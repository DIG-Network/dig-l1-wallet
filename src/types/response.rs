//! Public response types returned by [`L1Wallet`](crate::L1Wallet) methods.
//!
//! These types are designed to be serializable (via `serde`) so consumers
//! can easily convert them to JSON for CLI output or API responses.
//!
//! All types use chia-query's string-based representations (0x-prefixed hex)
//! for hashes and addresses, matching the chia-query API convention.
//! See: SPEC.md §8 "Response Types"

use serde::{Deserialize, Serialize};

/// Returned by [`L1Wallet::create_wallet`](crate::L1Wallet::create_wallet).
///
/// Contains the BIP39 mnemonic phrase that the user **must** back up.
/// The mnemonic is not stored on disk — it is only returned once at
/// creation time. See SPEC.md §7 "Generate New Wallet".
///
/// # Usage
/// ```rust,no_run
/// # async fn example(wallet: &dig_l1_wallet::L1Wallet) -> Result<(), Box<dyn std::error::Error>> {
/// let backup = wallet.create_wallet("my-wallet", "password").await?;
/// println!("BACK UP THIS MNEMONIC: {}", backup.mnemonic);
/// println!("First receive address: {}", backup.first_address);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MnemonicBackup {
    /// 24-word BIP39 mnemonic phrase (English).
    /// Generated from 256 bits of entropy via `bip39::Mnemonic::from_entropy_in`.
    pub mnemonic: String,
    /// Name of the created wallet.
    pub wallet_name: String,
    /// Bech32m address at derivation index 0 (xch1... or txch1...).
    /// Encoded via `chia_wallet_sdk::utils::Address::encode()`.
    pub first_address: String,
}

/// Account metadata (no secret material).
///
/// Returned by [`L1Wallet::create_account`](crate::L1Wallet::create_account)
/// and [`L1Wallet::list_accounts`](crate::L1Wallet::list_accounts).
///
/// Each account corresponds to a derivation index at path
/// `m/12381/8444/2/{index}` following the Chia HD key standard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    /// Human-readable account label.
    pub name: String,
    /// Derivation index: `m/12381/8444/2/{index}`.
    pub index: u32,
    /// Standard puzzle hash — 0x-prefixed hex.
    /// Computed as `StandardArgs::curry_tree_hash(synthetic_pk)`.
    pub puzzle_hash: String,
    /// Bech32m address (xch1... or txch1...).
    pub address: String,
}

/// Asset balance in mojos (1 XCH = 1_000_000_000_000 mojos).
///
/// When queried with `account_index = None`, values are aggregated
/// across all derivation indexes in the wallet.
///
/// # Semantics
/// - `confirmed`: Sum of all unspent coins confirmed on chain.
/// - `pending`: Unconfirmed incoming coins (reserved for future use; currently 0).
/// - `spendable`: Coins available to spend (confirmed minus pending outgoing).
/// - `coin_count`: Number of individual UTXO coins.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Balance {
    /// Sum of confirmed unspent coin amounts.
    pub confirmed: u64,
    /// Unconfirmed incoming amount (currently always 0; reserved for future pending tracking).
    pub pending: u64,
    /// Amount available to spend: `confirmed - pending_outgoing`.
    pub spendable: u64,
    /// Number of unspent UTXO coins contributing to the balance.
    pub coin_count: u32,
}

/// Result of broadcasting a spend bundle to the network.
///
/// Wraps the response from `chia_query::ChiaQuery::push_tx()`.
/// The `status` field reflects the full node's transaction status
/// ("SUCCESS", "PENDING", or "FAILED").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxResult {
    /// Transaction identifier (aggregated signature hex as stand-in ID).
    pub tx_id: String,
    /// Full node status: "SUCCESS", "PENDING", or "FAILED".
    pub status: String,
    /// Whether the transaction was accepted by the full node.
    pub success: bool,
}

/// Coin selection strategy for choosing which UTXOs to spend.
///
/// See SPEC.md §10 "Coin Selection" for algorithm details.
///
/// # Strategies
///
/// - **Knapsack**: Delegates to `chia_wallet_sdk::utils::select_coins` which
///   implements a knapsack algorithm. This is the same algorithm used by
///   DataLayer-Driver (`wallet.rs` line 127). Recommended default.
/// - **LargestFirst**: Greedy sort descending. Minimizes input count.
/// - **SmallestFirst**: Greedy sort ascending. Consolidates dust coins.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoinSelectionStrategy {
    /// Knapsack algorithm from `chia_wallet_sdk::utils::select_coins`.
    /// Adapted from DataLayer-Driver `wallet.rs::select_coins`.
    #[default]
    Knapsack,
    /// Greedy: select largest coins first until target is met.
    LargestFirst,
    /// Greedy: select smallest coins first until target is met.
    SmallestFirst,
}

/// Result of a coin selection operation (does not broadcast anything).
///
/// Returned by [`L1Wallet::select_coins`](crate::L1Wallet::select_coins)
/// and [`L1Wallet::select_cat_coins`](crate::L1Wallet::select_cat_coins).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinSelection {
    /// The selected coins (chia-query `CoinRecord` type with hex string fields).
    pub coins: Vec<chia_query::CoinRecord>,
    /// Total amount of all selected coins in mojos.
    pub total: u64,
    /// Excess amount: `total - target_amount`. This becomes the change output.
    pub change: u64,
    /// Number of coins selected.
    pub coin_count: u32,
}

/// Default maximum number of coins a single spend may consume.
///
/// The coin-management selection path
/// ([`select_for_spend`](crate::coins::selection::select_for_spend)) walks coins
/// high-value-first and considers at most this many inputs. A wallet whose largest
/// `DEFAULT_COIN_CAP` coins do not reach the target must first consolidate — see
/// [`SelectionOutcome::NeedsConsolidation`].
///
/// This mirrors the browser/JS spend layer's cap (chip35-dl-coin-wasm `selectCoins`)
/// so both spend layers agree on the boundary between "spendable" and "needs
/// consolidation". See SPEC.md §10 "Coin Selection".
pub const DEFAULT_COIN_CAP: usize = 50;

/// Outcome of a capped, high-value-first coin selection
/// ([`select_for_spend`](crate::coins::selection::select_for_spend)).
///
/// A discriminated result — the caller matches on the variant rather than catching
/// an error, so the three cases are always distinguishable:
///
/// - [`SelectionOutcome::Selected`] — coins reaching the target were found within the
///   coin-count cap; spend them directly.
/// - [`SelectionOutcome::NeedsConsolidation`] — the wallet holds enough total value,
///   but reaching the target needs more than `cap` coins. Consolidate (merge coins
///   into fewer, higher-value coins — see
///   [`L1Wallet::consolidate_coins`](crate::L1Wallet::consolidate_coins)) and retry.
/// - [`SelectionOutcome::InsufficientFunds`] — the total value of the asset is below
///   the target. DISTINCT from `NeedsConsolidation`: no amount of consolidation can
///   create value, so "not enough money" is never reported as "too fragmented".
///
/// This mirrors the browser/JS spend layer's `selectCoins` result
/// (chip35-dl-coin-wasm v0.14.0) field-for-field so both spend layers express the
/// same contract:
///
/// | JS result                                              | Rust variant |
/// |--------------------------------------------------------|--------------|
/// | `{ coins, total, change, coinCount, asset }`           | `Selected` |
/// | `{ availableCoinCount, availableTotal, required, cap }`| `NeedsConsolidation` |
/// | `{ availableCoinCount, availableTotal, required, cap }`| `InsufficientFunds` |
///
/// (In JS the three are tagged by an `ok` / `needsConsolidation` discriminant; in
/// Rust the enum variant is the discriminant.) See SPEC.md §10 "Coin Selection".
///
/// Note: this is a distinct type from [`WalletError::InsufficientFunds`], which the
/// older strategy-based [`select_with_strategy`](crate::coins::selection::select_with_strategy)
/// and the spend builders still return unchanged (back-compat).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SelectionOutcome {
    /// Coins reaching the target were selected within the cap.
    Selected {
        /// The selected coins, high-value-first (chia-query `CoinRecord` type).
        coins: Vec<chia_query::CoinRecord>,
        /// Total amount of all selected coins in mojos.
        total: u64,
        /// Excess amount: `total - target`. This becomes the change output.
        change: u64,
        /// Number of coins selected.
        coin_count: u32,
        /// Asset label: `"XCH"` for XCH, or the 0x-prefixed CAT tail (asset id) hex.
        asset: String,
    },
    /// Enough total value exists, but the target cannot be reached within `cap`
    /// coins. The caller should consolidate coins of the asset and retry.
    NeedsConsolidation {
        /// Total number of unspent coins of the asset the wallet holds.
        available_coin_count: u32,
        /// Sum of all unspent coins of the asset in mojos (always `>= required`).
        available_total: u64,
        /// The target amount that could not be reached within the cap, in mojos.
        required: u64,
        /// The coin-count cap in force for this selection.
        cap: usize,
    },
    /// The asset's total value is below the target — genuinely insufficient funds.
    InsufficientFunds {
        /// Total number of unspent coins of the asset the wallet holds.
        available_coin_count: u32,
        /// Sum of all unspent coins of the asset in mojos (always `< required`).
        available_total: u64,
        /// The target amount, in mojos.
        required: u64,
        /// The coin-count cap in force for this selection.
        cap: usize,
    },
}
