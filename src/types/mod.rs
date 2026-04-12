//! Core types for the dig-l1-wallet crate.
//!
//! This module defines the error type ([`WalletError`]), configuration
//! ([`L1WalletConfig`]), and all public response types ([`Balance`],
//! [`TxResult`], [`CoinSelection`], etc.).
//!
//! All types are re-exported at the crate root via `pub use types::*`
//! in `lib.rs`, so consumers can import them directly.

pub mod config;
pub mod error;
pub mod response;

pub use config::*;
pub use error::*;
pub use response::*;
