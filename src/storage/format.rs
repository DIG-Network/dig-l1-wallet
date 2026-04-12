//! Wallet file serialization format.
//!
//! Each named wallet is persisted as a single JSON file at
//! `{wallet_dir}/{name}.wallet`. The file contains the encrypted master
//! secret key and public metadata for each derived account.
//!
//! ## JSON Schema (version 1)
//!
//! ```json
//! {
//!   "version": 1,
//!   "name": "my-wallet",
//!   "network": "mainnet",
//!   "encrypted_master_key": "0x<hex of salt||nonce||ciphertext>",
//!   "accounts": [
//!     {
//!       "name": "Default",
//!       "index": 0,
//!       "puzzle_hash": "0x...",
//!       "address": "xch1...",
//!       "public_key": "<hex 48 bytes>",
//!       "synthetic_public_key": "<hex 48 bytes>",
//!       "last_sync_height": 0
//!     }
//!   ],
//!   "created_at": 1700000000,
//!   "modified_at": 1700000000
//! }
//! ```
//!
//! ## Design Decision
//!
//! The `encrypted_master_key` is stored as a hex string (not base64) for
//! consistency with chia-query's hex-string convention. The l2_driver_state_channel
//! uses base64; we chose hex per SPEC.md §5.
//!
//! ## Reference
//!
//! Adapted from `l2_driver_state_channel/src/services/wallet/storage.rs`.
//! See SPEC.md §5 "Wallet File Format".

use chia_query::NetworkType;
use serde::{Deserialize, Serialize};

/// On-disk wallet file format (version 1).
///
/// Contains only the encrypted master key and public account metadata.
/// No unencrypted secret material is ever written to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletFile {
    /// Format version — currently always `1`.
    /// Increment on breaking schema changes to support migration.
    pub version: u32,

    /// Human-readable wallet name (also determines the filename: `{name}.wallet`).
    pub name: String,

    /// Chia network this wallet operates on.
    /// Serialized as `"mainnet"` or `"testnet11"` via custom serde.
    #[serde(with = "network_serde")]
    pub network: NetworkType,

    /// Master secret key encrypted with AES-256-GCM + Argon2id.
    /// Hex-encoded wire format: `0x<salt(16B) || nonce(12B) || ciphertext+tag>`.
    /// See [`crate::keystore::encryption`] for the encryption scheme.
    pub encrypted_master_key: String,

    /// Derived accounts — public metadata only (no secret key material).
    /// Index 0 is always created automatically on wallet creation.
    pub accounts: Vec<WalletAccount>,

    /// Creation timestamp (Unix epoch seconds).
    pub created_at: u64,
    /// Last modification timestamp (Unix epoch seconds).
    pub modified_at: u64,
}

/// Public metadata for a single derived account.
///
/// Each account corresponds to derivation path `m/12381/8444/2/{index}`.
/// All fields are public (no secrets) — safe to store unencrypted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAccount {
    /// Human-readable account label
    pub name: String,

    /// Derivation index: m/12381/8444/2/{index}
    pub index: u32,

    /// Standard puzzle hash — 0x-prefixed hex
    pub puzzle_hash: String,

    /// Bech32m address (xch1... or txch1...)
    pub address: String,

    /// BLS public key — hex string
    pub public_key: String,

    /// Synthetic public key — hex string
    pub synthetic_public_key: String,

    /// Last confirmed sync height for coin tracking
    pub last_sync_height: u32,
}

/// Custom serde for NetworkType <-> "mainnet"/"testnet11".
mod network_serde {
    use chia_query::NetworkType;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(network: &NetworkType, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(network.network_id())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<NetworkType, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "mainnet" => Ok(NetworkType::Mainnet),
            "testnet11" => Ok(NetworkType::Testnet11),
            other => Err(serde::de::Error::custom(format!(
                "Unknown network: {}",
                other
            ))),
        }
    }
}
