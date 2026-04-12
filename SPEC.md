# dig-l1-wallet — Specification

## Overview

`dig-l1-wallet` is a Rust crate providing a self-custodial Chia L1 wallet with a well-defined public API. It supports key generation/import, encrypted on-disk storage, XCH and CAT balance queries, coin management (selection, splitting, combining), transaction construction and broadcast, and management of multiple named wallets.

It uses `chia-query` as its blockchain backend and follows the same crate organization and CI publishing pipeline. It **maximally leverages the chia crate ecosystem** — `chia`, `chia-wallet-sdk`, `chia-puzzle-types`, `chia-protocol`, `chia-bls`, `clvm-traits`, `clvm-utils`, and `clvmr` — for all wallet primitives rather than reimplementing any functionality these crates already provide.

All operations that touch the chain accept an optional **derivation index** parameter. When `None`, the operation spans **all known derivation indexes** for that wallet. When `Some(index)`, it targets a single derivation. The default (first) derivation is index `0` at `m/12381/8444/2/0`.

---

## 1. Crate Structure

```
dig-l1-wallet/
├── Cargo.toml
├── src/
│   ├── lib.rs                  # Public API surface — re-exports all public types
│   ├── wallet.rs               # L1Wallet — primary entry point struct
│   ├── keystore/
│   │   ├── mod.rs              # Keystore struct, lock/unlock lifecycle
│   │   ├── encryption.rs       # AES-256-GCM + Argon2id encrypt/decrypt
│   │   └── mnemonic.rs         # BIP39 mnemonic generation and import
│   ├── keys/
│   │   ├── mod.rs              # Key derivation utilities
│   │   └── derivation.rs       # HD path m/12381/8444/2/{index}, synthetic keys
│   ├── coins/
│   │   ├── mod.rs              # Coin listing, combine, split operations
│   │   ├── selection.rs        # CoinSelectionStrategy wrapping chia_wallet_sdk::utils::select_coins
│   │   └── tracker.rs          # Confirmed/pending coin tracking per address
│   ├── transaction/
│   │   ├── mod.rs              # XCH transaction builder (SpendContext + StandardLayer)
│   │   └── cat.rs              # CAT spend construction via CatArgs + StandardLayer inner
│   ├── storage/
│   │   ├── mod.rs              # Wallet file I/O, directory management
│   │   └── format.rs           # WalletFile / WalletAccount serialization format
│   └── types/
│       ├── mod.rs              # Re-exports
│       ├── error.rs            # WalletError enum (thiserror)
│       ├── config.rs           # L1WalletConfig
│       └── response.rs         # Balance, TxResult, AccountInfo, CoinSelection
├── tests/
│   ├── keystore.rs             # Encryption round-trip, key generation, import
│   ├── transaction.rs          # Spend bundle construction, signing
│   └── integration.rs          # Live chain tests (ignored by default)
└── .github/
    └── workflows/
        └── publish.yml         # CI: fmt, clippy, test, publish to crates.io
```

---

## 2. Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `chia-query` | latest | Blockchain backend — coin queries, `push_tx`, fee estimates |
| `chia` | 0.26 | Umbrella re-export: `chia::bls`, `chia::protocol`, `chia::puzzles`, `chia::clvm_traits`, `chia::clvm_utils`, `chia::traits`, `chia::consensus` |
| `chia-wallet-sdk` | 0.30 | `StandardLayer`, `SpendContext`, `Conditions`, `RequiredSignature`, `AggSigConstants`, `Address`, `utils::select_coins`, `MAINNET_CONSTANTS`, `TESTNET11_CONSTANTS` |
| `chia-puzzle-types` | 0.26 | `StandardArgs`, `StandardSolution`, `DeriveSynthetic`, `DEFAULT_HIDDEN_PUZZLE_HASH`, `EveProof`, `LineageProof`, `Proof`, `Memos` |
| `chia-protocol` | 0.26 | `Bytes32`, `Bytes`, `Coin`, `CoinSpend`, `SpendBundle`, `Program`, `CoinState`, `CoinStateFilters` |
| `chia-bls` | 0.26 | `SecretKey`, `PublicKey`, `Signature`, `sign`, `aggregate`, `master_to_wallet_unhardened`, `DerivableKey` |
| `chia-puzzles` | 0.20 | `CatArgs` (CAT puzzle construction), `SINGLETON_LAUNCHER_HASH` |
| `chia-traits` | 0.26 | `Streamable` trait for binary serialization |
| `clvm-traits` | 0.26 | `FromClvm`, `ToClvm` traits for CLVM type conversion |
| `clvm-utils` | 0.26 | `tree_hash`, `curry_tree_hash`, `CurriedProgram`, `TreeHash` |
| `clvmr` | 0.14 | `Allocator`, `NodePtr` for CLVM evaluation |
| `tokio` | 1 (full) | Async runtime |
| `serde` / `serde_json` | 1 | Wallet file serialization |
| `thiserror` | 2 | Error type derivation |
| `aes-gcm` | latest | AES-256-GCM authenticated encryption for key material |
| `argon2` | latest | Argon2id password-based key derivation |
| `bip39` | 2.0 | BIP39 mnemonic generation and validation |
| `rand` | 0.8 | Cryptographic random number generation |
| `hex` | 0.4 | Hex encoding/decoding |
| `log` | 0.4 | Logging |

---

## 3. SDK Type and Function Usage Map

The wallet does **not** reimplement anything the chia ecosystem already provides. This table maps every wallet concept to its SDK source:

| Concept | Type / Function | Source |
|---------|----------------|--------|
| Secret key | `SecretKey` | `chia::bls` |
| Public key | `PublicKey` | `chia::bls` |
| BLS signature | `Signature` | `chia::bls` |
| Sign a message | `sign(&sk, &msg)` | `chia::bls` |
| Aggregate signatures | `aggregate(&[sig])` | `chia::bls` |
| HD derivation | `master_to_wallet_unhardened(&sk, index)` | `chia::bls` |
| Derivable keys | `DerivableKey` trait | `chia::bls` |
| 32-byte hash | `Bytes32` | `chia::protocol` |
| Raw bytes | `Bytes` | `chia::protocol` |
| UTXO | `Coin` | `chia::protocol` |
| Coin + puzzle + solution | `CoinSpend` | `chia::protocol` |
| Transaction bundle | `SpendBundle` | `chia::protocol` |
| CLVM program | `Program` | `chia::protocol` |
| Synthetic key derivation | `pk.derive_synthetic()` | `chia_puzzle_types::DeriveSynthetic` |
| Standard puzzle hash | `StandardArgs::curry_tree_hash(synthetic_pk)` | `chia_puzzle_types::standard` |
| Standard puzzle args | `StandardArgs::new(synthetic_pk)` | `chia_puzzle_types::standard` |
| Standard puzzle solution | `StandardSolution` | `chia_puzzle_types::standard` |
| Default hidden puzzle hash | `DEFAULT_HIDDEN_PUZZLE_HASH` | `chia_puzzle_types::standard` |
| CAT puzzle args | `CatArgs` | `chia::puzzles::cat` / `chia_puzzles` |
| Lineage proof | `LineageProof`, `EveProof`, `Proof` | `chia_puzzle_types` |
| Memo hints | `Memos` | `chia_puzzle_types` |
| Standard puzzle spend | `StandardLayer::new(pk).spend(&mut ctx, coin, conditions)` | `chia_wallet_sdk::driver` |
| Spend accumulator | `SpendContext::new()` | `chia_wallet_sdk::driver` |
| Conditions builder | `Conditions::new().create_coin(...).reserve_fee(...)` | `chia_wallet_sdk::types` |
| Assert concurrent spend | `Conditions::assert_concurrent_spend(coin_id)` | `chia_wallet_sdk::types` |
| Signature extraction | `RequiredSignature::from_coin_spends(&mut alloc, &spends, &agg_sig)` | `chia_wallet_sdk::signer` |
| Signing constants | `AggSigConstants::new(constants.agg_sig_me_additional_data)` | `chia_wallet_sdk::signer` |
| Network constants | `MAINNET_CONSTANTS`, `TESTNET11_CONSTANTS` | `chia_wallet_sdk::types` |
| Address encode | `Address::new(puzzle_hash, prefix).encode()` | `chia_wallet_sdk::utils` |
| Address decode | `Address::decode(address_str)?.puzzle_hash` | `chia_wallet_sdk::utils` |
| Coin selection (knapsack) | `utils::select_coins(coins, target)` | `chia_wallet_sdk::utils` |
| Coin selection error | `CoinSelectionError` | `chia_wallet_sdk::utils` |
| CLVM allocator | `Allocator::new()` | `clvmr` |
| Tree hash | `tree_hash(&allocator, node)` | `clvm_utils` |
| Curry tree hash | `curry_tree_hash(...)` | `clvm_utils` |
| CLVM serialization | `FromClvm`, `ToClvm` | `clvm_traits` |
| Binary serialization | `Streamable` | `chia_traits` |
| `TreeHash` / `ToTreeHash` | Tree hash type + trait | `clvm_utils` |

---

## 4. Configuration

```rust
use chia_query::{ChiaQueryConfig, NetworkType};
use std::path::PathBuf;

pub struct L1WalletConfig {
    /// Chia network (Mainnet or Testnet11)
    pub network: NetworkType,

    /// Directory for wallet files (default: ~/.dig/wallets/)
    pub wallet_dir: PathBuf,

    /// chia-query configuration for blockchain access
    pub query_config: ChiaQueryConfig,

    /// Auto-lock timeout in seconds (0 = disabled)
    pub auto_lock_timeout_secs: u64,
}

impl Default for L1WalletConfig {
    fn default() -> Self {
        Self {
            network: NetworkType::Mainnet,
            wallet_dir: dirs::home_dir().unwrap().join(".dig").join("wallets"),
            query_config: ChiaQueryConfig::default(),
            auto_lock_timeout_secs: 0,
        }
    }
}
```

---

## 5. Wallet File Format

Each named wallet is stored as a single JSON file at `{wallet_dir}/{name}.wallet`.

```rust
pub struct WalletFile {
    /// Format version for migration support
    pub version: u32,                       // Currently 1

    /// Human-readable wallet name
    pub name: String,

    /// Network (serialized as string: "mainnet" | "testnet11")
    pub network: NetworkType,

    /// Master secret key, encrypted with AES-256-GCM
    /// Layout: salt (16 bytes) || nonce (12 bytes) || ciphertext || auth_tag
    /// Stored as hex string in JSON.
    pub encrypted_master_key: String,

    /// Derived accounts (public metadata only — no secrets on disk unencrypted)
    pub accounts: Vec<WalletAccount>,

    /// Timestamps (Unix epoch seconds)
    pub created_at: u64,
    pub modified_at: u64,
}

pub struct WalletAccount {
    /// Human-readable account label
    pub name: String,

    /// Derivation index: m/12381/8444/2/{index}
    pub index: u32,

    /// Standard puzzle hash (from synthetic public key) — 0x-prefixed hex
    pub puzzle_hash: String,

    /// Bech32m address (xch1... or txch1...) — via chia_wallet_sdk::utils::Address
    pub address: String,

    /// BLS public key — 48 bytes, hex string
    pub public_key: String,

    /// Synthetic public key — 48 bytes, hex string
    pub synthetic_public_key: String,

    /// Last confirmed sync height for coin tracking
    pub last_sync_height: u32,
}
```

---

## 6. Encryption

All secret key material is encrypted at rest using AES-256-GCM with Argon2id key derivation, matching the pattern established in `l2_driver_state_channel`.

### Key Derivation

```
Password → Argon2id(password, salt) → 32-byte encryption key

Parameters:
  memory_cost:  65536 (64 MB)
  time_cost:    3
  parallelism:  4
  salt:         16 bytes (random, stored with ciphertext)
  output:       32 bytes
```

### Encryption

```
encrypt(secret_key_bytes, password):
  1. Generate random salt (16 bytes)
  2. Derive encryption key via Argon2id(password, salt)
  3. Generate random nonce (12 bytes)
  4. Encrypt with AES-256-GCM(key, nonce, secret_key_bytes)
  5. Return: salt || nonce || ciphertext_with_auth_tag
```

### Decryption

```
decrypt(encrypted_blob, password):
  1. Extract salt (bytes 0..16)
  2. Extract nonce (bytes 16..28)
  3. Extract ciphertext (bytes 28..)
  4. Derive key via Argon2id(password, salt)
  5. Decrypt with AES-256-GCM(key, nonce, ciphertext)
  6. Return plaintext secret key bytes
  7. On failure: return DecryptionError (wrong password)
```

### In-Memory Key Lifecycle

The `Keystore` uses chia crate types directly:

```rust
use chia::bls::SecretKey;
use chia::protocol::Bytes32;
use std::sync::RwLock;
use std::collections::HashMap;

struct Keystore {
    /// Master secret key (decrypted, in memory only while unlocked)
    master_key: RwLock<Option<SecretKey>>,
    /// Derived account keys indexed by derivation index
    derived_keys: RwLock<HashMap<u32, SecretKey>>,
    /// Puzzle hash → derivation index reverse lookup
    puzzle_hash_to_index: RwLock<HashMap<Bytes32, u32>>,
    /// Whether the keystore is locked
    locked: RwLock<bool>,
}
```

Keys are:
- **Populated** on `unlock(password)` — master key decrypted, all account keys derived via `master_to_wallet_unhardened` and placed in memory.
- **Cleared** on `lock()` — all `SecretKey` material is dropped.
- **Required** for signing — any signing operation checks that the keystore is unlocked and returns `WalletLocked` if not.

---

## 7. Key Generation and Import

All key operations use chia crate primitives directly.

### Generate New Wallet

```
generate_wallet(name, password):
  1. Generate 256-bit entropy
  2. bip39::Mnemonic::generate(24 words)
  3. Derive master SecretKey from mnemonic seed via chia::bls
  4. Encrypt master SecretKey bytes with password (AES-256-GCM + Argon2id)
  5. Derive first account: master_to_wallet_unhardened(&master_sk, 0) → account_sk
  6. account_sk.public_key() → account_pk
  7. account_pk.derive_synthetic() → synthetic_pk   (DeriveSynthetic trait)
  8. StandardArgs::curry_tree_hash(synthetic_pk) → puzzle_hash
  9. Address::new(puzzle_hash, prefix).encode() → address
  10. Write WalletFile to disk
  11. Return mnemonic (for user backup) + first address
```

### Import from Mnemonic

```
import_mnemonic(name, mnemonic_words, password):
  1. bip39::Mnemonic::from_phrase() — validate word list + checksum
  2. Derive master SecretKey from mnemonic seed
  3. Encrypt + derive first account (same as steps 4-10 above)
  4. Write WalletFile to disk
```

### Import from Secret Key

```
import_secret_key(name, secret_key_bytes, password):
  1. SecretKey::from_bytes(&sk_bytes) — validate valid BLS scalar
  2. Encrypt + derive first account (same as steps 4-10 above)
  3. Write WalletFile to disk
```

### HD Key Derivation Chain (reference implementation)

```rust
use chia::bls::{master_to_wallet_unhardened, SecretKey, PublicKey};
use chia_puzzle_types::{standard::StandardArgs, DeriveSynthetic};
use chia_wallet_sdk::utils::Address;
use chia::protocol::Bytes32;

/// Derive all key material for a derivation index.
/// This is the canonical derivation used everywhere in the wallet.
fn derive_account(
    master_sk: &SecretKey,
    index: u32,
    address_prefix: &str,   // "xch" or "txch"
) -> (SecretKey, PublicKey, PublicKey, Bytes32, String) {
    let account_sk = master_to_wallet_unhardened(master_sk, index);
    let account_pk = account_sk.public_key();
    let synthetic_pk = account_pk.derive_synthetic();
    let puzzle_hash = Bytes32::from(StandardArgs::curry_tree_hash(synthetic_pk));
    let address = Address::new(puzzle_hash, address_prefix.to_string())
        .encode()
        .expect("valid bech32m");
    (account_sk, account_pk, synthetic_pk, puzzle_hash, address)
}

/// Same as derive_account but derives the synthetic secret key for signing.
/// Uses DeriveSynthetic on the secret key directly.
fn derive_synthetic_sk(master_sk: &SecretKey, index: u32) -> SecretKey {
    master_to_wallet_unhardened(master_sk, index).derive_synthetic()
}

/// Puzzle hash from public key (standalone, no master key needed).
/// Matches DataLayer-Driver pattern: master_public_key_to_first_puzzle_hash
fn puzzle_hash_from_pk(pk: &PublicKey) -> Bytes32 {
    let synthetic_pk = pk.derive_synthetic();
    Bytes32::from(StandardArgs::curry_tree_hash(synthetic_pk))
}

/// Address decoding using SDK utility.
fn decode_address(address: &str) -> Result<Bytes32, WalletError> {
    Ok(Address::decode(address)
        .map_err(|e| WalletError::InvalidAddress(e.to_string()))?
        .puzzle_hash)
}
```

---

## 8. Public API

### Derivation Index Convention

All methods that query the chain or build transactions accept `account_index: Option<u32>`:

- **`Some(0)`** — targets the first (default) synthetic key at `m/12381/8444/2/0`
- **`Some(n)`** — targets a specific derivation index
- **`None`** — operates across **all known derivation indexes** for that wallet (all accounts in `WalletFile.accounts`)

For balance queries, `None` aggregates balances across all derivations. For coin selection, `None` pools coins from all derivations. For sends, `None` is **not allowed** (must specify which key signs).

### `L1Wallet` — Primary Entry Point

```rust
impl L1Wallet {
    // ── Construction ──────────────────────────────────────────────

    /// Create a new L1Wallet instance with the given configuration.
    /// Initializes chia-query for blockchain access.
    pub async fn new(config: L1WalletConfig) -> Result<Self, WalletError>;

    // ── Wallet Management ─────────────────────────────────────────

    /// Create a new wallet with a generated BIP39 mnemonic.
    /// Returns the 24-word mnemonic for user backup.
    /// Automatically creates account at derivation index 0.
    pub async fn create_wallet(
        &self,
        name: &str,
        password: &str,
    ) -> Result<MnemonicBackup, WalletError>;

    /// Import a wallet from a BIP39 mnemonic phrase.
    /// Automatically creates account at derivation index 0.
    pub async fn import_from_mnemonic(
        &self,
        name: &str,
        mnemonic: &str,
        password: &str,
    ) -> Result<(), WalletError>;

    /// Import a wallet from a raw secret key (32 bytes).
    /// Automatically creates account at derivation index 0.
    pub async fn import_from_secret_key(
        &self,
        name: &str,
        secret_key: &[u8; 32],
        password: &str,
    ) -> Result<(), WalletError>;

    /// List all wallet names found in the wallet directory.
    pub fn list_wallets(&self) -> Result<Vec<String>, WalletError>;

    /// Delete a wallet file from disk. Irreversible.
    pub fn delete_wallet(&self, name: &str) -> Result<(), WalletError>;

    /// Rename a wallet.
    pub fn rename_wallet(&self, old_name: &str, new_name: &str) -> Result<(), WalletError>;

    // ── Lock / Unlock ─────────────────────────────────────────────

    /// Unlock a wallet by decrypting its master key with the given password.
    /// Derives and caches all account SecretKeys in memory.
    pub fn unlock(&self, name: &str, password: &str) -> Result<(), WalletError>;

    /// Lock a wallet, clearing all decrypted key material from memory.
    pub fn lock(&self, name: &str);

    /// Check if a wallet is currently unlocked.
    pub fn is_unlocked(&self, name: &str) -> Result<bool, WalletError>;

    // ── Account Management ────────────────────────────────────────

    /// Add a new derived account to the wallet.
    /// Derives the next available index: m/12381/8444/2/{next_index}.
    /// Wallet must be unlocked.
    pub fn create_account(
        &self,
        wallet_name: &str,
        account_name: &str,
    ) -> Result<AccountInfo, WalletError>;

    /// List all accounts in a wallet.
    pub fn list_accounts(
        &self,
        wallet_name: &str,
    ) -> Result<Vec<AccountInfo>, WalletError>;

    // ── Balance Queries ───────────────────────────────────────────

    /// Get XCH balance.
    /// - account_index = Some(n): balance for derivation index n
    /// - account_index = None: aggregated balance across ALL derivations
    pub async fn get_xch_balance(
        &self,
        wallet_name: &str,
        account_index: Option<u32>,
    ) -> Result<Balance, WalletError>;

    /// Get CAT balance by asset ID (TAIL hash, 0x-prefixed hex).
    /// - account_index = Some(n): balance for derivation index n
    /// - account_index = None: aggregated balance across ALL derivations
    pub async fn get_cat_balance(
        &self,
        wallet_name: &str,
        account_index: Option<u32>,
        asset_id: &str,
    ) -> Result<Balance, WalletError>;

    // ── Transactions ──────────────────────────────────────────────

    /// Send XCH from a specific derivation index to a destination address.
    /// Wallet must be unlocked. Uses SpendContext + StandardLayer internally.
    /// account_index is required (not optional) — must specify signing key.
    pub async fn send_xch(
        &self,
        wallet_name: &str,
        account_index: u32,
        to_address: &str,
        amount_mojos: u64,
        fee_mojos: u64,
    ) -> Result<TxResult, WalletError>;

    /// Send a CAT from a specific derivation index.
    /// asset_id is a 0x-prefixed hex TAIL hash.
    /// Wallet must be unlocked.
    pub async fn send_cat(
        &self,
        wallet_name: &str,
        account_index: u32,
        asset_id: &str,
        to_address: &str,
        amount: u64,
        fee_mojos: u64,
    ) -> Result<TxResult, WalletError>;

    /// Broadcast a pre-built chia::protocol::SpendBundle to the network.
    pub async fn broadcast_spend_bundle(
        &self,
        spend_bundle: &SpendBundle,
    ) -> Result<TxResult, WalletError>;

    /// Wait for a coin to be confirmed on chain.
    /// coin_id is a 0x-prefixed hex string.
    pub async fn wait_for_confirmation(
        &self,
        coin_id: &str,
        timeout: Duration,
    ) -> Result<CoinRecord, WalletError>;

    // ── Fee Estimation ────────────────────────────────────────────

    /// Get a fee estimate for a transaction.
    pub async fn estimate_fee(
        &self,
        spend_count: u64,
    ) -> Result<FeeEstimate, WalletError>;

    // ── Coin Management ─────────────────────────────────────────

    /// List all unspent XCH coins.
    /// - account_index = Some(n): coins for derivation n only
    /// - account_index = None: coins across ALL derivations
    /// Returns chia-query CoinRecords sorted by amount descending.
    pub async fn get_unspent_coins(
        &self,
        wallet_name: &str,
        account_index: Option<u32>,
    ) -> Result<Vec<CoinRecord>, WalletError>;

    /// List all unspent CAT coins by asset ID.
    /// - account_index = Some(n): coins for derivation n only
    /// - account_index = None: coins across ALL derivations
    pub async fn get_unspent_cat_coins(
        &self,
        wallet_name: &str,
        account_index: Option<u32>,
        asset_id: &str,
    ) -> Result<Vec<CoinRecord>, WalletError>;

    /// Select coins to meet a target amount.
    /// - account_index = Some(n): select from derivation n only
    /// - account_index = None: select across ALL derivations (pooled)
    /// Uses chia_wallet_sdk::utils::select_coins internally for the
    /// knapsack algorithm when strategy is KnapsackSdk.
    /// Returns selected coins and total value. Does not broadcast.
    pub async fn select_coins(
        &self,
        wallet_name: &str,
        account_index: Option<u32>,
        target_amount: u64,
        strategy: CoinSelectionStrategy,
    ) -> Result<CoinSelection, WalletError>;

    /// Select CAT coins to meet a target amount.
    /// Supports cross-derivation selection when account_index is None.
    pub async fn select_cat_coins(
        &self,
        wallet_name: &str,
        account_index: Option<u32>,
        asset_id: &str,
        target_amount: u64,
        strategy: CoinSelectionStrategy,
    ) -> Result<CoinSelection, WalletError>;

    /// Combine multiple small XCH coins into a single coin.
    /// If `coin_ids` is None, combines all coins for the account_index.
    /// If `coin_ids` is Some, combines only the specified coins.
    /// account_index is required — must specify which key signs and receives.
    /// Wallet must be unlocked.
    pub async fn combine_coins(
        &self,
        wallet_name: &str,
        account_index: u32,
        coin_ids: Option<&[String]>,
        fee_mojos: u64,
    ) -> Result<TxResult, WalletError>;

    /// Combine multiple small CAT coins into a single CAT coin.
    pub async fn combine_cat_coins(
        &self,
        wallet_name: &str,
        account_index: u32,
        asset_id: &str,
        coin_ids: Option<&[String]>,
        fee_mojos: u64,
    ) -> Result<TxResult, WalletError>;

    /// Split a single XCH coin into multiple coins of equal (or near-equal) value.
    /// account_index is required — must specify which key signs.
    /// Wallet must be unlocked.
    pub async fn split_coins(
        &self,
        wallet_name: &str,
        account_index: u32,
        coin_id: &str,
        target_count: u32,
        fee_mojos: u64,
    ) -> Result<TxResult, WalletError>;

    /// Split a single CAT coin into multiple CAT coins.
    pub async fn split_cat_coins(
        &self,
        wallet_name: &str,
        account_index: u32,
        asset_id: &str,
        coin_id: &str,
        target_count: u32,
        fee_mojos: u64,
    ) -> Result<TxResult, WalletError>;
}
```

### Response Types

```rust
use chia_query::CoinRecord;

/// Returned when creating a new wallet — contains the mnemonic for backup.
pub struct MnemonicBackup {
    pub mnemonic: String,       // 24-word BIP39 phrase
    pub wallet_name: String,
    pub first_address: String,  // xch1... or txch1... (derivation 0)
}

/// Account metadata (no secret material).
pub struct AccountInfo {
    pub name: String,
    pub index: u32,
    pub puzzle_hash: String,    // 0x-prefixed hex
    pub address: String,        // xch1... or txch1... via Address::encode()
}

/// Asset balance in mojos.
/// When queried with account_index=None, these are aggregated across all derivations.
pub struct Balance {
    pub confirmed: u64,         // Confirmed unspent
    pub pending: u64,           // Unconfirmed incoming
    pub spendable: u64,         // Confirmed minus pending outgoing
    pub coin_count: u32,        // Number of unspent coins
}

/// Transaction broadcast result.
pub struct TxResult {
    pub tx_id: String,          // SpendBundle hash (0x-prefixed hex)
    pub status: String,         // "SUCCESS" | "PENDING" | "FAILED"
    pub success: bool,
}

/// Coin selection strategy.
pub enum CoinSelectionStrategy {
    /// Use chia_wallet_sdk::utils::select_coins (knapsack algorithm).
    /// This is the default and recommended strategy.
    Knapsack,
    /// Select largest coins first — minimizes number of inputs.
    LargestFirst,
    /// Select smallest coins first — consolidates dust.
    SmallestFirst,
}

/// Result of a coin selection operation.
pub struct CoinSelection {
    pub coins: Vec<CoinRecord>,  // Selected coins (chia-query type)
    pub total: u64,              // Sum of selected coin amounts
    pub change: u64,             // total - target_amount
    pub coin_count: u32,         // Number of coins selected
}
```

---

## 9. Error Handling

```rust
use chia_query::ChiaQueryError;
use chia_wallet_sdk::{signer::SignerError, utils::CoinSelectionError};

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("Wallet not found: {0}")]
    WalletNotFound(String),

    #[error("Wallet already exists: {0}")]
    WalletAlreadyExists(String),

    #[error("Account not found: index {0}")]
    AccountNotFound(u32),

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Wallet is locked — call unlock() first")]
    WalletLocked,

    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Invalid coin: {0}")]
    InvalidCoin(String),

    #[error("Insufficient funds: available {available}, required {required}")]
    InsufficientFunds { available: u64, required: u64 },

    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Key derivation error: {0}")]
    KeyDerivation(String),

    #[error("Spend construction error: {0}")]
    SpendConstruction(String),

    #[error("Signing error: {0}")]
    Signing(#[from] SignerError),

    #[error("Coin selection error: {0}")]
    CoinSelection(#[from] CoinSelectionError),

    #[error("Driver error: {0}")]
    Driver(String),

    #[error("Blockchain query error: {0}")]
    Query(#[from] ChiaQueryError),

    #[error("Storage I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
```

---

## 10. Transaction Construction

All transaction building uses `chia-wallet-sdk`'s `SpendContext`, `StandardLayer`, `Conditions`, and `RequiredSignature`. The signing pattern follows DataLayer-Driver: map each secret key to both its original and synthetic public key, then match against `RequiredSignature` results.

### Sending XCH (reference implementation)

```rust
use chia::bls::{sign, aggregate, SecretKey, PublicKey, Signature};
use chia::protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
use chia_puzzle_types::DeriveSynthetic;
use chia_wallet_sdk::driver::{SpendContext, StandardLayer};
use chia_wallet_sdk::types::Conditions;
use chia_wallet_sdk::signer::{AggSigConstants, RequiredSignature};
use chia_wallet_sdk::types::MAINNET_CONSTANTS;
use clvmr::Allocator;

fn build_xch_send(
    synthetic_pk: PublicKey,
    coins: Vec<Coin>,
    dest_puzzle_hash: Bytes32,
    amount: u64,
    fee: u64,
    change_puzzle_hash: Bytes32,
) -> Result<Vec<CoinSpend>, WalletError> {
    let mut ctx = SpendContext::new();
    let p2 = StandardLayer::new(synthetic_pk);
    let total: u64 = coins.iter().map(|c| c.amount).sum();
    let change = total - amount - fee;

    // First coin: all output conditions
    let mut conditions = Conditions::new()
        .create_coin(dest_puzzle_hash, amount, vec![dest_puzzle_hash.into()]);

    if change > 0 {
        conditions = conditions.create_coin(change_puzzle_hash, change, vec![]);
    }
    if fee > 0 {
        conditions = conditions.reserve_fee(fee);
    }

    p2.spend(&mut ctx, coins[0], conditions)?;

    // Remaining coins: assert concurrent spend with first coin
    // (DataLayer-Driver pattern — prevents double-spend without empty conditions)
    for coin in &coins[1..] {
        p2.spend(
            &mut ctx,
            *coin,
            Conditions::new().assert_concurrent_spend(coins[0].coin_id()),
        )?;
    }

    Ok(ctx.take())
}

/// Sign coin spends using the DataLayer-Driver pattern:
/// map each SK to both original PK and synthetic PK, then match.
fn sign_coin_spends(
    coin_spends: &[CoinSpend],
    secret_keys: &[SecretKey],
    agg_sig_data: Bytes32,
) -> Result<Signature, WalletError> {
    use std::collections::HashMap;

    // Build PK → SK lookup for both original and synthetic keys
    let key_pairs: HashMap<PublicKey, SecretKey> = secret_keys
        .iter()
        .flat_map(|sk| {
            let pk = sk.public_key();
            let syn_sk = sk.derive_synthetic();
            let syn_pk = pk.derive_synthetic();
            vec![(pk, sk.clone()), (syn_pk, syn_sk)]
        })
        .collect();

    let mut allocator = Allocator::new();
    let agg_sig = AggSigConstants::new(agg_sig_data);
    let required = RequiredSignature::from_coin_spends(
        &mut allocator, coin_spends, &agg_sig,
    )?;

    let signatures: Vec<Signature> = required
        .iter()
        .map(|req| {
            let pk = req.public_key();
            let sk = key_pairs.get(&pk)
                .ok_or_else(|| WalletError::Signing(
                    SignerError::MissingKey(pk)
                ))?;
            Ok(sign(sk, req.message()))
        })
        .collect::<Result<Vec<_>, WalletError>>()?;

    Ok(aggregate(&signatures))
}
```

### Sending CATs

```
send_cat(wallet, account_index, asset_id, to_address, amount, fee):
  1. Verify wallet is unlocked
  2. Derive account key at m/12381/8444/2/{account_index}
  3. Address::decode(to_address) → dest_puzzle_hash
  4. Fetch unspent CAT coins for account + asset_id via chia-query
  5. Select CAT coins to cover amount (via select_coins)
  6. If fee > 0: also select XCH coins to cover the fee
  7. Create SpendContext
  8. For CAT spends: use CatArgs (from chia::puzzles::cat) with:
     - Inner puzzle = StandardLayer for the account
     - Inner conditions: CREATE_COIN for destination, change
     - Ring linkage: prev_coin/next_coin for CAT amount conservation
     - Lineage proofs via LineageProof/EveProof from chia_puzzle_types
  9. For XCH fee coin(s): StandardLayer.spend() with RESERVE_FEE
 10. RequiredSignature::from_coin_spends() → sign_coin_spends()
 11. Broadcast SpendBundle via chia-query push_tx()
 12. Return TxResult
```

### Coin Selection

The `select_coins` / `select_cat_coins` methods support cross-derivation pooling when `account_index=None`:

```
select_coins(wallet, account_index, target_amount, strategy):
  1. If account_index = Some(n):
       Fetch coins for puzzle_hash at derivation n
     If account_index = None:
       For each account in wallet.accounts:
         Fetch coins for that account's puzzle_hash
       Pool all coins together
  2. Apply strategy:
     - Knapsack: chia_wallet_sdk::utils::select_coins(coins, target)
     - LargestFirst: sort desc, accumulate until >= target
     - SmallestFirst: sort asc, accumulate until >= target
  3. Return CoinSelection { coins, total, change, coin_count }
```

**Knapsack** delegates to `chia_wallet_sdk::utils::select_coins` which implements the same algorithm used by DataLayer-Driver. This is the default and recommended strategy.

### Combining Coins

```
combine_coins(wallet, account_index, coin_ids, fee):
  1. Verify wallet is unlocked
  2. Derive synthetic_pk for m/12381/8444/2/{account_index}
  3. If coin_ids is None: fetch all unspent coins for account
     If coin_ids is Some: fetch specified coins, verify ownership
  4. Validate at least 2 coins to combine
  5. Create SpendContext, StandardLayer::new(synthetic_pk)
  6. First coin:
       p2.spend(ctx, coin, Conditions::new()
           .create_coin(own_puzzle_hash, total_output)
           .reserve_fee(fee))
  7. Remaining coins:
       p2.spend(ctx, coin, Conditions::new()
           .assert_concurrent_spend(first_coin.coin_id()))
  8. sign_coin_spends() → broadcast
  9. Return TxResult
```

For CATs: same logic but spends go through CAT outer puzzle with ring linkage. Fee is paid from a separate XCH coin if fee > 0.

### Splitting Coins

```
split_coins(wallet, account_index, coin_id, target_count, fee):
  1. Verify wallet is unlocked
  2. Derive synthetic_pk for m/12381/8444/2/{account_index}
  3. Fetch the coin by ID, verify ownership
  4. split_amount = (coin.amount - fee) / target_count
     Remainder goes to the first output
  5. Create SpendContext, StandardLayer::new(synthetic_pk)
  6. Build conditions:
     Conditions::new()
       .create_coin(own_puzzle_hash, split_amount + remainder)
       .create_coin(own_puzzle_hash, split_amount)  // × (target_count - 1)
       .reserve_fee(fee)
  7. p2.spend(ctx, coin, conditions)
  8. sign_coin_spends() → broadcast
  9. Return TxResult
```

For CATs: same inner puzzle conditions. Fee paid from separate XCH coin.

---

## 11. Balance Queries

### XCH Balance

```
get_xch_balance(wallet, account_index):
  If account_index = Some(n):
    1. Derive puzzle_hash for m/12381/8444/2/{n}
    2. Convert to 0x hex, query chia-query:
       get_coin_records_by_puzzle_hash(puzzle_hash_hex, include_spent=false)
    3. Sum, return Balance

  If account_index = None:
    1. For each account in wallet.accounts:
         Derive puzzle_hash, query coin records
    2. Aggregate: sum all confirmed, pending, spendable, coin_count
    3. Return combined Balance
```

### CAT Balance

```
get_cat_balance(wallet, account_index, asset_id):
  Same pattern as XCH but:
  - Query by hint: get_coin_records_by_hint(puzzle_hash_hex)
    and filter for coins matching the CAT structure for this asset_id
  - Alternatively compute CAT outer puzzle hash via CatArgs and query directly
  - Aggregates across all derivations when account_index = None
```

---

## 12. Wallet Management

### Multiple Named Wallets

- Each wallet is an independent file: `{wallet_dir}/{name}.wallet`
- `list_wallets()` — glob `*.wallet` in the wallet directory, return names
- `delete_wallet(name)` — remove the file
- `rename_wallet(old, new)` — rename the file, update the `name` field inside

### Multiple Accounts per Wallet (Derivation Indexes)

- Each wallet has one master key (from mnemonic or imported secret key)
- Accounts are derived at incrementing indices: `m/12381/8444/2/0`, `m/12381/8444/2/1`, ...
- `create_account()` appends a new `WalletAccount` entry with the next index
- All accounts share the same master key and wallet password
- **Index 0 is always created automatically** when a wallet is created/imported
- All balance, coin listing, and coin selection operations support `None` to span all derivations
- Send, combine, and split operations require a specific index (signing key must be unambiguous)

---

## 13. Blockchain Integration via chia-query

All chain interaction goes through `chia-query`. No direct peer or RPC connections are made by the wallet crate itself. The wallet converts between chia crate types (`Bytes32`, `Coin`, `SpendBundle`) and chia-query's hex-string types at the boundary.

| Wallet Operation | chia-query Method |
|------------------|-------------------|
| Get XCH coins (single derivation) | `get_coin_records_by_puzzle_hash` |
| Get XCH coins (all derivations) | `get_coin_records_by_puzzle_hash` × N (one per account) |
| Get CAT coins | `get_coin_records_by_puzzle_hash` + `get_coin_records_by_hint` |
| Broadcast tx | `push_tx` |
| Wait for confirm | `wait_for_confirmation` |
| Fee estimate | `get_fee_estimate` |
| Network info | `get_network_info` |
| Get coin details | `get_coin_record_by_name` |
| Get puzzle/solution | `get_puzzle_and_solution` |

### Type Conversion Layer

chia-query uses `String` (0x-prefixed hex) for all hashes. The wallet uses `Bytes32` internally. Conversion utilities:

```rust
use chia::protocol::Bytes32;

fn bytes32_to_hex(b: &Bytes32) -> String {
    format!("0x{}", hex::encode(b.as_ref()))
}

fn hex_to_bytes32(s: &str) -> Result<Bytes32, WalletError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| WalletError::InvalidAddress(e.to_string()))?;
    Bytes32::try_from(bytes.as_slice())
        .map_err(|_| WalletError::InvalidAddress("expected 32 bytes".into()))
}
```

---

## 14. CI / Publishing

Follows the same pipeline as `chia-query` (`.github/workflows/publish.yml`):

### Trigger
- On push to tags matching `v*`
- Manual workflow dispatch

### Jobs

**1. Test**
- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-features`
- `cargo doc --no-deps --all-features`

**2. Publish** (depends on test)
- `cargo build --release`
- `cargo package --allow-dirty`
- `cargo publish --allow-dirty --token ${{ secrets.CARGO_REGISTRY_TOKEN }}`

**3. GitHub Release** (depends on publish, tag trigger only)
- Extract version from tag
- Create GitHub release with changelog

### Required Secrets
- `CARGO_REGISTRY_TOKEN` — crates.io publish token
- `GH_ACCESS_TOKEN` — GitHub release creation

### Cargo.toml Metadata

```toml
[package]
name = "dig-l1-wallet"
version = "0.1.0"
edition = "2021"
license = "MIT"
repository = "https://github.com/DIG-Network/dig-l1-wallet"
description = "Self-custodial Chia L1 wallet crate with XCH and CAT support"
keywords = ["chia", "wallet", "blockchain", "cat", "l1"]
categories = ["cryptography::cryptocurrencies"]
```

---

## 15. Security Considerations

1. **Secret keys are never stored unencrypted on disk.** The master key is always AES-256-GCM encrypted with a user-provided password.
2. **Argon2id parameters are tuned for resistance** to brute-force (64 MB memory, 3 iterations, 4 lanes).
3. **Decrypted keys are held in memory only while the wallet is unlocked.** `lock()` drops all `SecretKey` material.
4. **Mnemonics are returned once at creation time** and not stored on disk. The user is responsible for backing up their mnemonic.
5. **Coin selection avoids dust** by default via SDK knapsack algorithm.
6. **Change always returns to the sender's own puzzle hash** — no new address derivation per transaction.
7. **No private key material appears in logs.** The `log` crate is used for operational tracing only.

---

## 16. Usage Example

```rust
use dig_l1_wallet::{L1Wallet, L1WalletConfig, CoinSelectionStrategy};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize with defaults (mainnet)
    let wallet = L1Wallet::new(L1WalletConfig::default()).await?;

    // Create a new wallet — returns mnemonic for backup
    let backup = wallet.create_wallet("my-wallet", "strong-password-here").await?;
    println!("Mnemonic (BACK THIS UP): {}", backup.mnemonic);
    println!("First address (index 0): {}", backup.first_address);

    // Unlock the wallet
    wallet.unlock("my-wallet", "strong-password-here")?;

    // Create additional derivation indexes
    let acct1 = wallet.create_account("my-wallet", "savings")?;
    println!("Index 1 address: {}", acct1.address);

    // ── Balance queries ──────────────────────────────────────

    // Balance for derivation index 0 (default)
    let bal = wallet.get_xch_balance("my-wallet", Some(0)).await?;
    println!("Index 0 XCH: {} mojos", bal.confirmed);

    // Balance for derivation index 1
    let bal1 = wallet.get_xch_balance("my-wallet", Some(1)).await?;
    println!("Index 1 XCH: {} mojos", bal1.confirmed);

    // Aggregated balance across ALL derivations
    let total = wallet.get_xch_balance("my-wallet", None).await?;
    println!("Total XCH across all derivations: {} mojos ({} coins)",
        total.confirmed, total.coin_count);

    // CAT balance (all derivations)
    let cat_bal = wallet.get_cat_balance(
        "my-wallet", None, "0xabcd...tail_hash"
    ).await?;
    println!("Total CAT balance: {}", cat_bal.confirmed);

    // ── Sending (requires specific derivation index) ─────────

    let tx = wallet.send_xch(
        "my-wallet",
        0,                          // sign with derivation index 0
        "xch1destination...",
        1_000_000_000_000,          // 1 XCH in mojos
        50_000_000,                 // fee
    ).await?;
    println!("TX: {} (success={})", tx.tx_id, tx.success);

    // Send a CAT from index 0
    let tx = wallet.send_cat(
        "my-wallet", 0,
        "0xabcd...tail_hash",
        "xch1destination...",
        1000, 50_000_000,
    ).await?;

    // ── Coin management ──────────────────────────────────────

    // List coins for index 0 only
    let coins = wallet.get_unspent_coins("my-wallet", Some(0)).await?;

    // List coins across ALL derivations
    let all_coins = wallet.get_unspent_coins("my-wallet", None).await?;
    println!("Total coins across all derivations: {}", all_coins.len());

    // Select coins across all derivations (pooled)
    let selection = wallet.select_coins(
        "my-wallet", None,          // pool from all derivations
        500_000_000_000,
        CoinSelectionStrategy::Knapsack,
    ).await?;
    println!("Selected {} coins, total={}, change={}",
        selection.coin_count, selection.total, selection.change);

    // Combine all coins for index 0 into one
    let tx = wallet.combine_coins("my-wallet", 0, None, 50_000_000).await?;

    // Split a coin from index 0 into 10 pieces
    let tx = wallet.split_coins("my-wallet", 0, "0xabcd...", 10, 50_000_000).await?;

    // Lock when done
    wallet.lock("my-wallet");

    Ok(())
}
```
