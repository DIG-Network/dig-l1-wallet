//! Coin selection strategies for choosing which UTXOs to spend.
//!
//! Three strategies are available:
//!
//! - **Knapsack**: Delegates to `chia_wallet_sdk::utils::select_coins` which
//!   implements a knapsack/branch-and-bound algorithm. This is the same algorithm
//!   used by DataLayer-Driver (`wallet.rs::select_coins`, line 127). **Recommended default.**
//! - **LargestFirst**: Greedy sort descending by amount. Minimizes the number of
//!   inputs (fewer CoinSpends in the bundle), but may create large change outputs.
//! - **SmallestFirst**: Greedy sort ascending by amount. Consolidates dust coins,
//!   but may require many inputs.
//!
//! ## Reference
//!
//! - Knapsack: `chia_wallet_sdk::utils::select_coins`
//! - DataLayer-Driver: `wallet.rs` line 127 (`utils::select_coins`)
//! - See SPEC.md §10 "Coin Selection"

use chia::protocol::Coin;
use chia_query::CoinRecord;
use chia_wallet_sdk::utils;

use crate::coins::tracker::coin_record_to_protocol_coin;
use crate::types::{CoinSelection, CoinSelectionStrategy, WalletError, WalletResult};

/// Select coins using the specified strategy.
pub fn select_with_strategy(
    records: &[CoinRecord],
    target: u64,
    strategy: CoinSelectionStrategy,
) -> WalletResult<CoinSelection> {
    if records.is_empty() {
        return Err(WalletError::InsufficientFunds {
            available: 0,
            required: target,
        });
    }

    let total_available: u64 = records.iter().map(|r| r.coin.amount).sum();
    if total_available < target {
        return Err(WalletError::InsufficientFunds {
            available: total_available,
            required: target,
        });
    }

    let selected = match strategy {
        CoinSelectionStrategy::Knapsack => select_knapsack(records, target)?,
        CoinSelectionStrategy::LargestFirst => select_largest_first(records, target),
        CoinSelectionStrategy::SmallestFirst => select_smallest_first(records, target),
    };

    let total: u64 = selected.iter().map(|r| r.coin.amount).sum();
    let change = total - target;
    let coin_count = selected.len() as u32;

    Ok(CoinSelection {
        coins: selected,
        total,
        change,
        coin_count,
    })
}

/// Knapsack coin selection via chia_wallet_sdk::utils::select_coins.
fn select_knapsack(records: &[CoinRecord], target: u64) -> WalletResult<Vec<CoinRecord>> {
    // Convert to protocol Coins for the SDK function
    let coins: Vec<Coin> = records
        .iter()
        .map(coin_record_to_protocol_coin)
        .collect::<WalletResult<Vec<_>>>()?;

    let selected_coins = utils::select_coins(coins.into_iter().collect(), target)?;

    // Map back to CoinRecords by matching coin_id
    let selected_ids: std::collections::HashSet<_> =
        selected_coins.iter().map(|c| c.coin_id()).collect();

    let selected_records: Vec<CoinRecord> = records
        .iter()
        .filter(|r| {
            if let Ok(coin) = coin_record_to_protocol_coin(r) {
                selected_ids.contains(&coin.coin_id())
            } else {
                false
            }
        })
        .cloned()
        .collect();

    Ok(selected_records)
}

/// Select largest coins first until target is met.
fn select_largest_first(records: &[CoinRecord], target: u64) -> Vec<CoinRecord> {
    let mut sorted: Vec<CoinRecord> = records.to_vec();
    sorted.sort_by(|a, b| b.coin.amount.cmp(&a.coin.amount));

    let mut selected = Vec::new();
    let mut total = 0u64;
    for record in sorted {
        if total >= target {
            break;
        }
        total += record.coin.amount;
        selected.push(record);
    }
    selected
}

/// Select smallest coins first until target is met.
fn select_smallest_first(records: &[CoinRecord], target: u64) -> Vec<CoinRecord> {
    let mut sorted: Vec<CoinRecord> = records.to_vec();
    sorted.sort_by(|a, b| a.coin.amount.cmp(&b.coin.amount));

    let mut selected = Vec::new();
    let mut total = 0u64;
    for record in sorted {
        if total >= target {
            break;
        }
        total += record.coin.amount;
        selected.push(record);
    }
    selected
}
