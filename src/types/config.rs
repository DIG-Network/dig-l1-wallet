//! Wallet configuration types.
//!
//! [`L1WalletConfig`] is the main configuration struct passed to
//! [`L1Wallet::new()`](crate::L1Wallet::new). It composes the
//! `chia_query::ChiaQueryConfig` for blockchain access with wallet-specific
//! settings like the storage directory and network selection.
//!
//! ## Design Decision
//!
//! `ChiaQueryConfig` is consumed (moved) by `ChiaQuery::new()` and does not
//! implement `Clone`, so `L1WalletConfig` is also move-only. The wallet stores
//! the `NetworkType` separately after consuming the config.

use chia_query::{ChiaQueryConfig, NetworkType};
use std::path::PathBuf;

/// Configuration for creating an [`L1Wallet`](crate::L1Wallet).
///
/// # Usage
/// ```rust,no_run
/// use dig_l1_wallet::{L1WalletConfig, NetworkType};
///
/// let config = L1WalletConfig {
///     network: NetworkType::Testnet11,
///     ..Default::default()
/// };
/// ```
pub struct L1WalletConfig {
    /// Chia network — determines address prefix ("xch" vs "txch") and
    /// AGG_SIG_ME additional data for transaction signing.
    /// See: `chia_wallet_sdk::types::MAINNET_CONSTANTS` / `TESTNET11_CONSTANTS`
    pub network: NetworkType,

    /// Directory where `.wallet` files are stored.
    /// Default: `~/.dig/wallets/`
    pub wallet_dir: PathBuf,

    /// Configuration passed to `chia_query::ChiaQuery::new()`.
    /// Controls peer pool size, coinset fallback, TLS certs, etc.
    /// See: <https://crates.io/crates/chia-query>
    pub query_config: ChiaQueryConfig,

    /// Auto-lock timeout in seconds. When > 0, the wallet automatically
    /// locks after this many seconds of inactivity. 0 = disabled.
    /// (Reserved for future implementation.)
    pub auto_lock_timeout_secs: u64,
}

impl Default for L1WalletConfig {
    fn default() -> Self {
        Self {
            network: NetworkType::Mainnet,
            wallet_dir: dirs::home_dir()
                .expect("home directory must exist")
                .join(".dig")
                .join("wallets"),
            query_config: ChiaQueryConfig::default(),
            auto_lock_timeout_secs: 0,
        }
    }
}

/// Returns the bech32m address prefix for a network.
///
/// - Mainnet: `"xch"` (e.g., `xch1abc...`)
/// - Testnet11: `"txch"` (e.g., `txch1abc...`)
///
/// See: [CHIP-0002 Address format](https://github.com/Chia-Network/chips/blob/main/CHIPs/chip-0002.md)
pub fn address_prefix(network: NetworkType) -> &'static str {
    match network {
        NetworkType::Mainnet => "xch",
        NetworkType::Testnet11 => "txch",
    }
}
