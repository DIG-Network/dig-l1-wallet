//! HD key derivation utilities following the Chia standard path:
//! `m/12381/8444/2/{index}`.
//!
//! ## Derivation Chain
//!
//! ```text
//! Master SK ──[master_to_wallet_unhardened(sk, index)]──▸ Account SK
//!     │                                                        │
//!     │                                                   .public_key()
//!     │                                                        │
//!     │                                                   Account PK
//!     │                                                        │
//!     │                                               .derive_synthetic()
//!     │                                                        │
//!     │                                                  Synthetic PK
//!     │                                                        │
//!     │                                          StandardArgs::curry_tree_hash()
//!     │                                                        │
//!     │                                                  Puzzle Hash
//!     │                                                        │
//!     │                                              Address::encode()
//!     │                                                        │
//!     ▼                                                  xch1... / txch1...
//! ```
//!
//! ## Key Functions Used
//!
//! - `chia::bls::master_to_wallet_unhardened`: Implements the Chia HD path
//!   `m/12381/8444/2/{index}` (unhardened wallet keys).
//! - `chia::puzzles::DeriveSynthetic`: Trait providing `.derive_synthetic()` on
//!   both `PublicKey` and `SecretKey`. The synthetic key includes the default
//!   hidden puzzle hash, enabling the standard P2 puzzle.
//! - `chia_puzzle_types::standard::StandardArgs::curry_tree_hash`: Curries the
//!   P2_DELEGATED_PUZZLE_OR_HIDDEN_PUZZLE with the synthetic public key to
//!   produce the puzzle hash.
//! - `chia_wallet_sdk::utils::Address`: Bech32m encoding/decoding per CHIP-0002.
//!
//! ## Reference
//!
//! Adapted from:
//! - `DataLayer-Driver/src/lib.rs` lines 70-125 (key derivation helpers)
//! - `l2_driver_state_channel/src/services/wallet/keys.rs` (KeyDerivation struct)
//! - See SPEC.md §7 "HD Key Derivation Chain"

use chia::bls::{master_to_wallet_unhardened, PublicKey, SecretKey};
use chia::protocol::Bytes32;
use chia::puzzles::DeriveSynthetic;
use chia_puzzle_types::standard::StandardArgs;
use chia_wallet_sdk::utils::Address;

use crate::types::{WalletError, WalletResult};

/// Derive all key material for a given derivation index.
///
/// This is the canonical derivation function used throughout the wallet.
/// It produces everything needed to receive and spend coins at this index.
///
/// # Parameters
/// - `master_sk`: The wallet's master secret key (from mnemonic or import)
/// - `index`: Derivation index (0 = default, 1+ = additional accounts)
/// - `address_prefix`: `"xch"` for mainnet, `"txch"` for testnet11
///
/// # Returns
/// Tuple of `(account_sk, account_pk, synthetic_pk, puzzle_hash, bech32m_address)`.
///
/// # Example
/// ```rust
/// use chia::bls::SecretKey;
/// use dig_l1_wallet::keys::derivation;
///
/// let master_sk = SecretKey::from_seed(&[42u8; 32]);
/// let (sk, pk, syn_pk, ph, addr) = derivation::derive_account(&master_sk, 0, "xch").unwrap();
/// assert!(addr.starts_with("xch1"));
/// ```
pub fn derive_account(
    master_sk: &SecretKey,
    index: u32,
    address_prefix: &str,
) -> WalletResult<(SecretKey, PublicKey, PublicKey, Bytes32, String)> {
    // Step 1: HD derivation at m/12381/8444/2/{index}
    let account_sk = master_to_wallet_unhardened(master_sk, index);
    let account_pk = account_sk.public_key();

    // Step 2: Derive synthetic key (includes default hidden puzzle hash offset)
    // The synthetic key is what's actually used in the standard P2 puzzle.
    let synthetic_pk = account_pk.derive_synthetic();

    // Step 3: Compute puzzle hash by currying the standard puzzle with synthetic PK.
    // This matches the Chia reference wallet's address derivation.
    let puzzle_hash = Bytes32::from(StandardArgs::curry_tree_hash(synthetic_pk));

    // Step 4: Bech32m encode the puzzle hash into an address string.
    // Uses CHIP-0002 address format: https://github.com/Chia-Network/chips/blob/main/CHIPs/chip-0002.md
    let address = Address::new(puzzle_hash, address_prefix.to_string())
        .encode()
        .map_err(|e| WalletError::InvalidAddress(format!("Failed to encode address: {}", e)))?;

    Ok((account_sk, account_pk, synthetic_pk, puzzle_hash, address))
}

/// Derive the synthetic secret key for signing at a given derivation index.
///
/// The synthetic SK is needed for signing spend bundles because the
/// standard Chia puzzle (`P2_DELEGATED_PUZZLE_OR_HIDDEN_PUZZLE`) expects
/// signatures from the synthetic key, not the raw account key.
///
/// Equivalent to: `master_to_wallet_unhardened(sk, index).derive_synthetic()`
pub fn derive_synthetic_sk(master_sk: &SecretKey, index: u32) -> SecretKey {
    master_to_wallet_unhardened(master_sk, index).derive_synthetic()
}

/// Compute the standard puzzle hash from a (non-synthetic) public key.
///
/// Applies synthetic derivation then `StandardArgs::curry_tree_hash`.
/// Useful for computing the puzzle hash when you only have the public key
/// (e.g., from a stored `WalletAccount`).
///
/// Pattern from DataLayer-Driver `lib.rs::master_public_key_to_first_puzzle_hash`.
pub fn puzzle_hash_from_pk(pk: &PublicKey) -> Bytes32 {
    let synthetic_pk = pk.derive_synthetic();
    Bytes32::from(StandardArgs::curry_tree_hash(synthetic_pk))
}

/// Encode a puzzle hash as a bech32m address string.
///
/// Uses `chia_wallet_sdk::utils::Address` per CHIP-0002.
///
/// # Parameters
/// - `puzzle_hash`: 32-byte puzzle hash
/// - `prefix`: `"xch"` or `"txch"`
pub fn encode_address(puzzle_hash: &Bytes32, prefix: &str) -> WalletResult<String> {
    Address::new(*puzzle_hash, prefix.to_string())
        .encode()
        .map_err(|e| WalletError::InvalidAddress(format!("Failed to encode address: {}", e)))
}

/// Decode a bech32m address string to a puzzle hash.
///
/// Uses `chia_wallet_sdk::utils::Address::decode` per CHIP-0002.
/// Accepts both `xch1...` (mainnet) and `txch1...` (testnet11) prefixes.
///
/// Pattern from DataLayer-Driver `lib.rs::address_to_puzzle_hash`.
pub fn decode_address(address: &str) -> WalletResult<Bytes32> {
    let addr = Address::decode(address)
        .map_err(|e| WalletError::InvalidAddress(format!("Failed to decode address: {}", e)))?;
    Ok(addr.puzzle_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_account_produces_valid_output() {
        let sk = SecretKey::from_seed(&[42u8; 32]);
        let (account_sk, account_pk, synthetic_pk, puzzle_hash, address) =
            derive_account(&sk, 0, "xch").unwrap();

        // Account key should differ from master
        assert_ne!(account_sk.to_bytes(), sk.to_bytes());
        // Public key should match the secret key's public key
        assert_eq!(account_sk.public_key(), account_pk);
        // Synthetic key should differ from raw public key
        assert_ne!(account_pk, synthetic_pk);
        // Puzzle hash should be non-zero
        assert_ne!(puzzle_hash, Bytes32::default());
        // Address should have correct prefix
        assert!(address.starts_with("xch1"));
    }

    #[test]
    fn test_different_indexes_different_keys() {
        let sk = SecretKey::from_seed(&[42u8; 32]);
        let (sk0, _, _, ph0, _) = derive_account(&sk, 0, "xch").unwrap();
        let (sk1, _, _, ph1, _) = derive_account(&sk, 1, "xch").unwrap();

        assert_ne!(sk0.to_bytes(), sk1.to_bytes());
        assert_ne!(ph0, ph1);
    }

    #[test]
    fn test_address_roundtrip() {
        let sk = SecretKey::from_seed(&[42u8; 32]);
        let (_, _, _, puzzle_hash, address) = derive_account(&sk, 0, "xch").unwrap();

        let decoded = decode_address(&address).unwrap();
        assert_eq!(decoded, puzzle_hash);
    }

    #[test]
    fn test_puzzle_hash_from_pk_matches_derive_account() {
        let sk = SecretKey::from_seed(&[42u8; 32]);
        let account_sk = master_to_wallet_unhardened(&sk, 0);
        let pk = account_sk.public_key();

        let ph = puzzle_hash_from_pk(&pk);
        let (_, _, _, expected_ph, _) = derive_account(&sk, 0, "xch").unwrap();
        assert_eq!(ph, expected_ph);
    }

    #[test]
    fn test_synthetic_sk_matches_synthetic_pk() {
        let sk = SecretKey::from_seed(&[42u8; 32]);
        let syn_sk = derive_synthetic_sk(&sk, 0);
        let (_, _, synthetic_pk, _, _) = derive_account(&sk, 0, "xch").unwrap();

        assert_eq!(syn_sk.public_key(), synthetic_pk);
    }

    #[test]
    fn test_testnet_address_prefix() {
        let sk = SecretKey::from_seed(&[42u8; 32]);
        let (_, _, _, _, address) = derive_account(&sk, 0, "txch").unwrap();
        assert!(address.starts_with("txch1"));
    }
}
