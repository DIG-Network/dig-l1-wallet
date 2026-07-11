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

use chia::protocol::{Bytes32, Coin};
use chia_query::CoinRecord;
use chia_wallet_sdk::utils;

use crate::coins::tracker::coin_record_to_protocol_coin;
use crate::types::{
    CoinSelection, CoinSelectionStrategy, SelectionOutcome, WalletError, WalletResult,
};

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
    sorted.sort_by_key(|r| std::cmp::Reverse(r.coin.amount));

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
    sorted.sort_by_key(|r| r.coin.amount);

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

/// Select coins for a spend, high-value-first, bounded by a coin-count cap.
///
/// This is the canonical selection path for the coin-management flow (the same
/// contract the browser/JS spend layer expresses via `selectCoins`). Coins are
/// ordered by amount DESCENDING (tie-broken by coin id for determinism) and the
/// largest are taken greedily until `target` is met. At most `cap` coins are
/// eligible for a single spend (pass [`DEFAULT_COIN_CAP`](crate::DEFAULT_COIN_CAP)
/// for the default of 50).
///
/// Returns a discriminated [`SelectionOutcome`] (never a thrown error for a funding
/// shortfall — the caller matches the variant):
/// - [`SelectionOutcome::Selected`] when the target is reachable within `cap` coins.
/// - [`SelectionOutcome::NeedsConsolidation`] when enough total value exists but the
///   largest `cap` coins do not sum to the target — the caller should consolidate
///   (see [`select_for_consolidation`]) and retry.
/// - [`SelectionOutcome::InsufficientFunds`] when the total value is below the target.
///   DISTINCT from `NeedsConsolidation`: consolidation cannot create value, so "not
///   enough money" is never reported as "needs consolidation".
///
/// `asset` labels the [`SelectionOutcome::Selected`] result (`"XCH"` or a 0x-prefixed
/// CAT tail hex); it does not affect which coins are chosen. Selection is pure — no
/// network, no signing. The only `Err` is a malformed coin record (bad hex).
///
/// The result shape mirrors chip35-dl-coin-wasm v0.14.0's `selectCoins`
/// field-for-field — see [`SelectionOutcome`].
pub fn select_for_spend(
    records: &[CoinRecord],
    target: u64,
    asset: &str,
    cap: usize,
) -> WalletResult<SelectionOutcome> {
    let available_total: u64 = records.iter().map(|r| r.coin.amount).sum();
    let available_coin_count = records.len() as u32;

    // Genuine insufficient funds: no amount of consolidation can reach the target.
    if available_total < target {
        return Ok(SelectionOutcome::InsufficientFunds {
            available_coin_count,
            available_total,
            required: target,
            cap,
        });
    }

    // High-value-first, deterministic ordering.
    let sorted = sort_descending(records)?;

    // Only the largest `cap` coins are eligible for a single spend.
    let eligible = &sorted[..sorted.len().min(cap)];
    let eligible_total: u64 = eligible.iter().map(|r| r.coin.amount).sum();

    // Enough total value exists, but not within the cap → consolidation needed.
    if eligible_total < target {
        return Ok(SelectionOutcome::NeedsConsolidation {
            available_coin_count,
            available_total,
            required: target,
            cap,
        });
    }

    // Greedy-accumulate the largest coins until the target is met.
    let mut selected = Vec::new();
    let mut total = 0u64;
    for record in eligible {
        if total >= target {
            break;
        }
        total += record.coin.amount;
        selected.push(record.clone());
    }

    let coin_count = selected.len() as u32;
    Ok(SelectionOutcome::Selected {
        coins: selected,
        total,
        change: total - target,
        coin_count,
        asset: asset.to_string(),
    })
}

/// Select up to `cap` coins to consolidate (merge) into a single coin.
///
/// Picks the highest-value coins first (deterministic, coin-id tie-break): merging
/// the largest coins concentrates the most value into one output, so a subsequent
/// capped [`select_for_spend`] is most likely to succeed with the fewest rounds.
/// Requires at least 2 coins — a single coin cannot be consolidated.
///
/// Returns the coins to feed into the combine builder
/// ([`build_combine_tx`](crate::transaction::build_combine_tx) for XCH,
/// [`build_cat_combine`](crate::transaction::cat::build_cat_combine) for a CAT).
/// Selection is pure — no network, no signing.
pub fn select_for_consolidation(
    records: &[CoinRecord],
    cap: usize,
) -> WalletResult<Vec<CoinRecord>> {
    let sorted = sort_descending(records)?;
    let take = sorted.len().min(cap);
    if take < 2 {
        return Err(WalletError::SpendConstruction(
            "Need at least 2 coins to consolidate".into(),
        ));
    }
    Ok(sorted[..take].to_vec())
}

/// Sort coin records by amount DESCENDING, tie-broken by coin id ASCENDING.
///
/// The coin-id tie-break makes selection deterministic regardless of the order the
/// chain query returned coins in — equal-amount coins always sort the same way.
fn sort_descending(records: &[CoinRecord]) -> WalletResult<Vec<CoinRecord>> {
    let mut keyed: Vec<(Bytes32, CoinRecord)> = records
        .iter()
        .map(|r| Ok((coin_record_to_protocol_coin(r)?.coin_id(), r.clone())))
        .collect::<WalletResult<Vec<_>>>()?;
    keyed.sort_by(|a, b| {
        b.1.coin
            .amount
            .cmp(&a.1.coin.amount)
            .then_with(|| a.0.cmp(&b.0))
    });
    Ok(keyed.into_iter().map(|(_, record)| record).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DEFAULT_COIN_CAP;

    /// Build a deterministic unspent XCH `CoinRecord` fixture.
    ///
    /// `seed` gives distinct (valid-hex) parent/puzzle bytes so each coin has a
    /// distinct coin id — letting tests exercise the coin-id tie-break.
    fn record(amount: u64, seed: u8) -> CoinRecord {
        CoinRecord {
            coin: chia_query::Coin {
                parent_coin_info: format!("0x{}", hex::encode([seed; 32])),
                puzzle_hash: format!("0x{}", hex::encode([seed.wrapping_add(100); 32])),
                amount,
            },
            confirmed_block_index: 1,
            spent_block_index: 0,
            spent: false,
            coinbase: false,
            timestamp: 0,
        }
    }

    fn amounts(coins: &[CoinRecord]) -> Vec<u64> {
        coins.iter().map(|c| c.coin.amount).collect()
    }

    #[test]
    fn default_cap_is_50() {
        assert_eq!(DEFAULT_COIN_CAP, 50);
    }

    #[test]
    fn select_for_spend_orders_high_value_first() {
        let coins = [record(100, 1), record(300, 2), record(200, 3)];
        let outcome = select_for_spend(&coins, 400, "XCH", DEFAULT_COIN_CAP).unwrap();
        match outcome {
            SelectionOutcome::Selected {
                coins,
                total,
                change,
                coin_count,
                asset,
            } => {
                // Largest first: 300 then 200 reaches 400; the 100 coin is untouched.
                assert_eq!(amounts(&coins), vec![300, 200]);
                assert_eq!(total, 500);
                assert_eq!(change, 100);
                assert_eq!(coin_count, 2);
                assert_eq!(asset, "XCH");
            }
            other => panic!("expected Selected, got {other:?}"),
        }
    }

    #[test]
    fn select_for_spend_within_cap_never_needs_consolidation() {
        let coins: Vec<CoinRecord> = (0..10).map(|i| record(10, i as u8)).collect();
        let outcome = select_for_spend(&coins, 95, "XCH", DEFAULT_COIN_CAP).unwrap();
        match outcome {
            SelectionOutcome::Selected {
                total,
                change,
                coin_count,
                ..
            } => {
                assert_eq!(coin_count, 10);
                assert_eq!(total, 100);
                assert_eq!(change, 5);
            }
            other => panic!("expected Selected, got {other:?}"),
        }
    }

    #[test]
    fn select_for_spend_cap_exactly_enough_is_selected() {
        // 50 coins of 1; cap 50; target 50 → all 50 coins reach it exactly.
        let coins: Vec<CoinRecord> = (0..50).map(|i| record(1, i as u8)).collect();
        let outcome = select_for_spend(&coins, 50, "XCH", 50).unwrap();
        match outcome {
            SelectionOutcome::Selected {
                total,
                change,
                coin_count,
                ..
            } => {
                assert_eq!(coin_count, 50);
                assert_eq!(total, 50);
                assert_eq!(change, 0);
            }
            other => panic!("expected Selected at the cap boundary, got {other:?}"),
        }
    }

    #[test]
    fn select_for_spend_one_over_cap_needs_consolidation() {
        // 51 coins of 1; cap 50; target 51 → total is enough (51) but the largest
        // 50 sum to only 50 < 51, so the spend cannot be built within the cap.
        let coins: Vec<CoinRecord> = (0..51).map(|i| record(1, i as u8)).collect();
        let outcome = select_for_spend(&coins, 51, "XCH", 50).unwrap();
        match outcome {
            SelectionOutcome::NeedsConsolidation {
                available_coin_count,
                available_total,
                required,
                cap,
            } => {
                assert_eq!(available_coin_count, 51);
                assert_eq!(available_total, 51);
                assert_eq!(required, 51);
                assert_eq!(cap, 50);
            }
            other => panic!("expected NeedsConsolidation one over the cap, got {other:?}"),
        }
    }

    #[test]
    fn select_for_spend_insufficient_is_distinct_from_needs_consolidation() {
        // 51 coins of 1 (total 51); target 100 → no consolidation can reach it.
        let coins: Vec<CoinRecord> = (0..51).map(|i| record(1, i as u8)).collect();
        let outcome = select_for_spend(&coins, 100, "XCH", 50).unwrap();
        match outcome {
            SelectionOutcome::InsufficientFunds {
                available_coin_count,
                available_total,
                required,
                cap,
            } => {
                assert_eq!(available_coin_count, 51);
                assert_eq!(available_total, 51);
                assert_eq!(required, 100);
                assert_eq!(cap, 50);
            }
            other => panic!("expected InsufficientFunds, got {other:?}"),
        }
    }

    #[test]
    fn select_for_spend_empty_is_insufficient() {
        let outcome = select_for_spend(&[], 10, "XCH", 50).unwrap();
        assert!(matches!(
            outcome,
            SelectionOutcome::InsufficientFunds {
                available_coin_count: 0,
                available_total: 0,
                required: 10,
                cap: 50,
            }
        ));
    }

    #[test]
    fn select_for_spend_labels_selected_cat_asset() {
        let tail = "0xabc0000000000000000000000000000000000000000000000000000000000000";
        let coins = [record(100, 1), record(50, 2)];
        let outcome = select_for_spend(&coins, 120, tail, 50).unwrap();
        match outcome {
            SelectionOutcome::Selected { asset, .. } => assert_eq!(asset, tail),
            other => panic!("expected Selected, got {other:?}"),
        }
    }

    #[test]
    fn select_for_spend_is_deterministic_across_input_order() {
        // All equal amounts → the coin-id tie-break decides the selection.
        let base: Vec<CoinRecord> = (0..8).map(|i| record(10, i as u8)).collect();
        let mut shuffled = base.clone();
        shuffled.reverse();

        let a = select_for_spend(&base, 35, "XCH", DEFAULT_COIN_CAP).unwrap();
        let b = select_for_spend(&shuffled, 35, "XCH", DEFAULT_COIN_CAP).unwrap();

        let (
            SelectionOutcome::Selected { coins: ca, .. },
            SelectionOutcome::Selected { coins: cb, .. },
        ) = (&a, &b)
        else {
            panic!("expected Selected outcomes");
        };
        // 4 coins of 10 reach 35; the SAME 4 coin ids regardless of input order.
        let ids_a: Vec<&String> = ca.iter().map(|c| &c.coin.parent_coin_info).collect();
        let ids_b: Vec<&String> = cb.iter().map(|c| &c.coin.parent_coin_info).collect();
        assert_eq!(ids_a, ids_b);
        assert_eq!(ca.len(), 4);
    }

    #[test]
    fn select_for_consolidation_picks_largest_capped() {
        let coins = [
            record(5, 1),
            record(1, 2),
            record(4, 3),
            record(2, 4),
            record(3, 5),
        ];
        let picked = select_for_consolidation(&coins, 3).unwrap();
        // Top 3 by value, descending.
        assert_eq!(amounts(&picked), vec![5, 4, 3]);
    }

    #[test]
    fn select_for_consolidation_returns_all_when_under_cap() {
        let coins = [record(2, 1), record(9, 2), record(4, 3)];
        let picked = select_for_consolidation(&coins, 50).unwrap();
        assert_eq!(amounts(&picked), vec![9, 4, 2]);
    }

    #[test]
    fn select_for_consolidation_requires_two_coins() {
        assert!(matches!(
            select_for_consolidation(&[record(10, 1)], 50),
            Err(WalletError::SpendConstruction(_))
        ));
        assert!(matches!(
            select_for_consolidation(&[], 50),
            Err(WalletError::SpendConstruction(_))
        ));
    }

    #[test]
    fn select_for_consolidation_is_deterministic() {
        let base: Vec<CoinRecord> = (0..6).map(|i| record(7, i as u8)).collect();
        let mut shuffled = base.clone();
        shuffled.reverse();
        let a = select_for_consolidation(&base, 4).unwrap();
        let b = select_for_consolidation(&shuffled, 4).unwrap();
        let ids_a: Vec<&String> = a.iter().map(|c| &c.coin.parent_coin_info).collect();
        let ids_b: Vec<&String> = b.iter().map(|c| &c.coin.parent_coin_info).collect();
        assert_eq!(ids_a, ids_b);
        assert_eq!(a.len(), 4);
    }

    #[test]
    fn strategy_largest_first_picks_biggest() {
        let coins = [record(100, 1), record(300, 2), record(200, 3)];
        let sel = select_with_strategy(&coins, 400, CoinSelectionStrategy::LargestFirst).unwrap();
        assert_eq!(amounts(&sel.coins), vec![300, 200]);
        assert_eq!(sel.total, 500);
        assert_eq!(sel.change, 100);
    }

    #[test]
    fn strategy_smallest_first_picks_dust() {
        let coins = [record(100, 1), record(300, 2), record(200, 3)];
        let sel = select_with_strategy(&coins, 250, CoinSelectionStrategy::SmallestFirst).unwrap();
        // Ascending: 100 then 200 reaches 250.
        assert_eq!(amounts(&sel.coins), vec![100, 200]);
        assert_eq!(sel.total, 300);
        assert_eq!(sel.change, 50);
    }

    #[test]
    fn strategy_knapsack_finds_a_covering_set() {
        let coins = [record(100, 1), record(300, 2), record(200, 3)];
        let sel = select_with_strategy(&coins, 250, CoinSelectionStrategy::Knapsack).unwrap();
        assert!(sel.total >= 250);
        assert_eq!(sel.change, sel.total - 250);
        assert!(!sel.coins.is_empty());
    }

    #[test]
    fn strategy_empty_records_is_insufficient() {
        let err = select_with_strategy(&[], 10, CoinSelectionStrategy::Knapsack).unwrap_err();
        assert!(matches!(
            err,
            WalletError::InsufficientFunds {
                available: 0,
                required: 10
            }
        ));
    }

    #[test]
    fn strategy_below_target_is_insufficient() {
        let coins = [record(10, 1), record(20, 2)];
        let err =
            select_with_strategy(&coins, 100, CoinSelectionStrategy::LargestFirst).unwrap_err();
        assert!(matches!(
            err,
            WalletError::InsufficientFunds {
                available: 30,
                required: 100
            }
        ));
    }

    #[test]
    fn sort_descending_tie_breaks_by_coin_id() {
        let coins = [record(10, 9), record(10, 1), record(10, 5)];
        let sorted = sort_descending(&coins).unwrap();
        // Equal amounts → ascending coin id. Recompute the ids to assert the order.
        let ids: Vec<Bytes32> = sorted
            .iter()
            .map(|r| coin_record_to_protocol_coin(r).unwrap().coin_id())
            .collect();
        let mut expected = ids.clone();
        expected.sort();
        assert_eq!(ids, expected);
    }
}
