//! In-memory keystore for managing decrypted BLS keys.
//!
//! ## Lifecycle
//!
//! ```text
//! [Locked]  ──unlock(encrypted_master_key, password)──▸  [Unlocked]
//!    ▲                                                        │
//!    └───────────────── lock() ◄──────────────────────────────┘
//! ```
//!
//! When **locked** (the default state), no secret key material is in memory.
//! When **unlocked**, the decrypted master key and all derived account keys
//! are held in `RwLock`-protected `HashMap`s. Calling `lock()` zeros all
//! key material by dropping the `SecretKey` values.
//!
//! ## Design Decision
//!
//! We use `std::sync::RwLock` (not `parking_lot::RwLock`) to minimize
//! dependencies. The l2_driver_state_channel uses `parking_lot`, but for
//! this crate's simpler access patterns, `std` suffices.
//!
//! Derived keys are indexed by derivation index (`u32`) with a reverse
//! lookup map (`puzzle_hash → index`) for identifying which derivation
//! owns a given coin.
//!
//! ## Reference
//!
//! Adapted from `l2_driver_state_channel/src/wallet/keystore.rs`.
//! See SPEC.md §6 "In-Memory Key Lifecycle".

pub mod encryption;
pub mod mnemonic;

use chia::bls::SecretKey;
use chia::protocol::Bytes32;
use chia::puzzles::DeriveSynthetic;
use std::collections::HashMap;
use std::sync::RwLock;

use crate::keys::derivation;
use crate::storage::format::WalletAccount;
use crate::types::{WalletError, WalletResult};

/// In-memory keystore holding decrypted BLS key material.
///
/// The keystore is **locked by default**. Call [`unlock`](Self::unlock)
/// with the encrypted master key blob and password to decrypt and derive
/// all account keys into memory.
///
/// ## Thread Safety
///
/// All fields are wrapped in `RwLock` for safe concurrent access.
/// Multiple readers can query keys simultaneously; writers (unlock/lock)
/// acquire exclusive access.
pub struct Keystore {
    /// Decrypted master secret key. `None` when locked.
    master_key: RwLock<Option<SecretKey>>,
    /// Account secret keys indexed by derivation index (e.g., 0, 1, 2...).
    /// Populated on unlock by calling `master_to_wallet_unhardened(master, idx)`.
    derived_keys: RwLock<HashMap<u32, SecretKey>>,
    /// Reverse lookup: puzzle hash → derivation index.
    /// Used to identify which account owns a given coin.
    puzzle_hash_to_index: RwLock<HashMap<Bytes32, u32>>,
    /// Whether the keystore is currently locked (no key material in memory).
    locked: RwLock<bool>,
}

impl Keystore {
    /// Create a new locked keystore with no keys.
    pub fn new() -> Self {
        Self {
            master_key: RwLock::new(None),
            derived_keys: RwLock::new(HashMap::new()),
            puzzle_hash_to_index: RwLock::new(HashMap::new()),
            locked: RwLock::new(true),
        }
    }

    /// Unlock the keystore by decrypting the master key and deriving all account keys.
    ///
    /// ## Steps
    /// 1. Decrypt `encrypted_master_key` using AES-256-GCM + Argon2id via [`encryption::decrypt_secret_key`].
    /// 2. Parse the 32-byte result into a `chia::bls::SecretKey`.
    /// 3. For each account in `accounts`, derive the account key via
    ///    `derivation::derive_account(master_sk, account.index, prefix)`.
    /// 4. Store all derived keys and puzzle hash mappings.
    ///
    /// ## Errors
    /// - [`WalletError::InvalidPassword`] if the password is wrong.
    /// - [`WalletError::InvalidSecretKey`] if decrypted bytes aren't a valid BLS scalar.
    pub fn unlock(
        &self,
        encrypted_master_key: &[u8],
        password: &str,
        accounts: &[WalletAccount],
        address_prefix: &str,
    ) -> WalletResult<()> {
        let sk_bytes = encryption::decrypt_secret_key(encrypted_master_key, password)?;
        let master_sk = SecretKey::from_bytes(&sk_bytes)
            .map_err(|e| WalletError::InvalidSecretKey(format!("Invalid master key: {}", e)))?;

        let mut derived = HashMap::new();
        let mut ph_to_idx = HashMap::new();

        for account in accounts {
            let (account_sk, _, _, puzzle_hash, _) =
                derivation::derive_account(&master_sk, account.index, address_prefix)?;
            derived.insert(account.index, account_sk);
            ph_to_idx.insert(puzzle_hash, account.index);
        }

        *self.master_key.write().unwrap() = Some(master_sk);
        *self.derived_keys.write().unwrap() = derived;
        *self.puzzle_hash_to_index.write().unwrap() = ph_to_idx;
        *self.locked.write().unwrap() = false;

        Ok(())
    }

    /// Lock the keystore, dropping all decrypted key material from memory.
    /// After this call, all signing operations will return `WalletLocked`.
    pub fn lock(&self) {
        *self.master_key.write().unwrap() = None;
        self.derived_keys.write().unwrap().clear();
        self.puzzle_hash_to_index.write().unwrap().clear();
        *self.locked.write().unwrap() = true;
    }

    /// Check if the keystore is unlocked.
    pub fn is_unlocked(&self) -> bool {
        !*self.locked.read().unwrap()
    }

    /// Get the master secret key. Errors if locked.
    pub fn master_key(&self) -> WalletResult<SecretKey> {
        self.master_key
            .read()
            .unwrap()
            .clone()
            .ok_or(WalletError::WalletLocked)
    }

    /// Get the account secret key for a derivation index.
    pub fn get_secret_key(&self, index: u32) -> WalletResult<SecretKey> {
        self.derived_keys
            .read()
            .unwrap()
            .get(&index)
            .cloned()
            .ok_or(WalletError::AccountNotFound(index))
    }

    /// Get the synthetic secret key for signing at a derivation index.
    ///
    /// The synthetic SK is derived from the account SK via `DeriveSynthetic::derive_synthetic()`.
    /// This is the key that must sign spends for the standard P2 puzzle.
    pub fn get_synthetic_sk(&self, index: u32) -> WalletResult<SecretKey> {
        let sk = self.get_secret_key(index)?;
        Ok(sk.derive_synthetic())
    }

    /// Get all derived secret keys (for cross-derivation signing).
    pub fn get_all_secret_keys(&self) -> WalletResult<Vec<(u32, SecretKey)>> {
        if !self.is_unlocked() {
            return Err(WalletError::WalletLocked);
        }
        Ok(self
            .derived_keys
            .read()
            .unwrap()
            .iter()
            .map(|(idx, sk)| (*idx, sk.clone()))
            .collect())
    }

    /// Add a new derivation to the keystore (when creating a new account while unlocked).
    pub fn add_derivation(
        &self,
        index: u32,
        address_prefix: &str,
    ) -> WalletResult<(SecretKey, Bytes32, String)> {
        let master_sk = self.master_key()?;
        let (account_sk, _, _, puzzle_hash, address) =
            derivation::derive_account(&master_sk, index, address_prefix)?;

        self.derived_keys
            .write()
            .unwrap()
            .insert(index, account_sk.clone());
        self.puzzle_hash_to_index
            .write()
            .unwrap()
            .insert(puzzle_hash, index);

        Ok((account_sk, puzzle_hash, address))
    }

    /// Reverse lookup: puzzle hash → derivation index.
    pub fn index_for_puzzle_hash(&self, puzzle_hash: &Bytes32) -> Option<u32> {
        self.puzzle_hash_to_index
            .read()
            .unwrap()
            .get(puzzle_hash)
            .copied()
    }
}

impl Default for Keystore {
    fn default() -> Self {
        Self::new()
    }
}
