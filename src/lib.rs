//! # dig-l1-wallet
//!
//! Self-custodial Chia L1 wallet crate with XCH and CAT (Chia Asset Token) support.
//!
//! ## Architecture
//!
//! This crate is organized as a layered library following the same structure as
//! [`chia-query`](https://crates.io/crates/chia-query). All blockchain interaction
//! is delegated to `chia-query` — this crate never opens peer connections directly.
//!
//! ```text
//! ┌─────────────────────────────────┐
//! │         L1Wallet (wallet.rs)    │  ← Public API orchestrator
//! ├─────────────────────────────────┤
//! │ transaction/  │ coins/          │  ← Spend building, coin queries
//! ├───────────────┼─────────────────┤
//! │ keystore/     │ storage/        │  ← Key mgmt, file I/O
//! ├───────────────┼─────────────────┤
//! │ keys/         │ types/          │  ← Derivation, error/config/response
//! └───────────────┴─────────────────┘
//! ```
//!
//! ## Key Design Decisions
//!
//! - **Maximizes chia crate ecosystem**: Uses `chia` (0.26), `chia-wallet-sdk` (0.30),
//!   `chia-puzzle-types`, `clvmr`, etc. for all wallet primitives. See SPEC.md §3.
//! - **Derivation index convention**: All chain-facing methods accept `Option<u32>`.
//!   `None` spans all derivations; `Some(0)` targets the default key. See SPEC.md §8.
//! - **Encryption at rest**: AES-256-GCM + Argon2id, adapted from
//!   `l2_driver_state_channel/src/services/wallet/encryption.rs`. See SPEC.md §6.
//! - **Spending pattern**: `SpendContext` + `StandardLayer` + `assert_concurrent_spend`,
//!   adapted from `DataLayer-Driver/src/wallet.rs`. See SPEC.md §10.
//! - **Signing pattern**: Maps each SK to (PK, SK) + (synthetic_PK, synthetic_SK), then
//!   uses `RequiredSignature::from_coin_spends`. See SPEC.md §10.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use dig_l1_wallet::{L1Wallet, L1WalletConfig, CoinSelectionStrategy};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize — connects to Chia network via chia-query
//!     let wallet = L1Wallet::new(L1WalletConfig::default()).await?;
//!
//!     // Create a new wallet (generates BIP39 mnemonic, encrypts master key)
//!     let backup = wallet.create_wallet("my-wallet", "password").await?;
//!     println!("Mnemonic: {}", backup.mnemonic);
//!
//!     // Unlock to enable signing and key operations
//!     wallet.unlock("my-wallet", "password")?;
//!
//!     // Query balance at derivation index 0 (the default)
//!     let balance = wallet.get_xch_balance("my-wallet", Some(0)).await?;
//!     println!("Balance: {} mojos", balance.confirmed);
//!
//!     // Or query across ALL derivation indexes
//!     let total = wallet.get_xch_balance("my-wallet", None).await?;
//!     println!("Total across all derivations: {} mojos", total.confirmed);
//!
//!     wallet.lock("my-wallet");
//!     Ok(())
//! }
//! ```

// ── Module declarations ───────────────────────────────────────────────
// Public modules expose the full internal API for advanced consumers.
// The `wallet` module is private — consumers interact via `L1Wallet`.

pub mod coins;
pub mod keys;
pub mod keystore;
pub mod storage;
pub mod transaction;
pub mod types;
mod wallet;

// ── Public API re-exports ─────────────────────────────────────────────
// Flat re-export of types so consumers can write `dig_l1_wallet::Balance`
// instead of `dig_l1_wallet::types::response::Balance`.

pub use types::*;
pub use wallet::L1Wallet;

// Re-export key chia-query types that appear in our public API signatures,
// so consumers don't need to add chia-query as a direct dependency.
pub use chia_query::{CoinRecord, FeeEstimate, NetworkType};
