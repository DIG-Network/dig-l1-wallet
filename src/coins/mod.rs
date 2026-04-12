//! Coin operations — listing, selection, and cross-derivation aggregation.
//!
//! This module provides the bridge between wallet accounts and on-chain coins.
//! The key feature is **cross-derivation aggregation**: when `account_index = None`,
//! coin queries iterate over ALL accounts in the wallet and pool the results.
//!
//! ## Submodules
//!
//! - [`tracker`]: Type conversion (hex ↔ Bytes32) and chia-query wrappers
//! - [`selection`]: Coin selection strategies (Knapsack, LargestFirst, SmallestFirst)
//!
//! ## Reference
//!
//! See SPEC.md §8 "Derivation Index Convention" and §11 "Balance Queries".

pub mod selection;
pub mod tracker;

use chia_query::{ChiaQuery, CoinRecord};

use crate::storage::format::WalletAccount;
use crate::types::WalletResult;

/// Get all unspent XCH coins, optionally filtering by derivation index.
///
/// - `account_index = Some(n)`: coins for that derivation only
/// - `account_index = None`: coins from ALL derivations, pooled
pub async fn get_all_unspent_xch(
    client: &ChiaQuery,
    accounts: &[WalletAccount],
    account_index: Option<u32>,
) -> WalletResult<Vec<CoinRecord>> {
    let target_accounts: Vec<&WalletAccount> = match account_index {
        Some(idx) => accounts.iter().filter(|a| a.index == idx).collect(),
        None => accounts.iter().collect(),
    };

    let mut all_coins = Vec::new();
    for account in target_accounts {
        let coins = tracker::get_unspent_xch_coins(client, &account.puzzle_hash).await?;
        all_coins.extend(coins);
    }

    // Sort by amount descending
    all_coins.sort_by(|a, b| b.coin.amount.cmp(&a.coin.amount));
    Ok(all_coins)
}

/// Get all unspent CAT coins by asset ID, optionally filtering by derivation index.
pub async fn get_all_unspent_cat(
    client: &ChiaQuery,
    accounts: &[WalletAccount],
    account_index: Option<u32>,
    _asset_id: &str,
) -> WalletResult<Vec<CoinRecord>> {
    let target_accounts: Vec<&WalletAccount> = match account_index {
        Some(idx) => accounts.iter().filter(|a| a.index == idx).collect(),
        None => accounts.iter().collect(),
    };

    let mut all_coins = Vec::new();
    for account in target_accounts {
        let coins = tracker::get_unspent_cat_coins_by_hint(client, &account.puzzle_hash).await?;
        // TODO: Filter by asset_id match when CAT puzzle hash verification is implemented.
        // For now, return all hinted coins — the caller should verify asset_id.
        all_coins.extend(coins);
    }

    all_coins.sort_by(|a, b| b.coin.amount.cmp(&a.coin.amount));
    Ok(all_coins)
}
