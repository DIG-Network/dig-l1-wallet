//! CAT (Chia Asset Token) transaction building.
//!
//! ## CAT Ring Accounting
//!
//! CATs use a "ring" structure where each coin spend must declare how much value
//! flows in/out (the "delta"), and the sum of all deltas across the ring must be zero
//! (conservation of value). The SDK's [`Cat::spend_all`] handles this automatically
//! when given a list of [`CatSpend`] objects.
//!
//! ## Lineage Proofs
//!
//! Each CAT coin requires a "lineage proof" — evidence that its parent was also
//! a valid CAT of the same asset ID. This proof contains:
//! - Parent's parent coin info
//! - Parent's inner puzzle hash
//! - Parent's amount
//!
//! We resolve lineage proofs by fetching the parent's puzzle and solution from
//! the chain via `chia-query`, then using `Cat::parse_children` to extract the
//! proof. This pattern is adapted from DataLayer-Driver `dig_coin.rs` lines 25-87.
//!
//! ## Fee Handling
//!
//! CAT spends cannot include RESERVE_FEE directly (only the inner puzzle can,
//! and that fee would be in CAT tokens, not XCH). Instead, fees are paid from
//! **separate XCH coins** that are linked to the CAT spend via
//! `assert_concurrent_spend`.
//!
//! ## Reference
//!
//! - DataLayer-Driver: `dig_coin.rs` lines 25-87 (CAT parsing)
//! - `chia_wallet_sdk::driver::Cat::spend_all` (ring accounting)
//! - `chia::puzzles::cat::CatArgs` (CAT puzzle hash computation)
//! - See SPEC.md §10 "Sending CATs"

use chia::bls::PublicKey;
use chia::protocol::{Bytes32, Coin, CoinSpend, Program};
use chia::puzzles::{cat::CatArgs, Memos};
use chia_query::ChiaQuery;
use chia_wallet_sdk::driver::{
    Cat, CatSpend, Puzzle, SpendContext, SpendWithConditions, StandardLayer,
};
use chia_wallet_sdk::types::Conditions;
use clvm_utils::{ToTreeHash, TreeHash};

use crate::coins::tracker::coin_record_to_protocol_coin;
use crate::types::{WalletError, WalletResult};

/// Compute the CAT outer puzzle hash for a given inner puzzle hash and asset ID.
pub fn cat_puzzle_hash(inner_puzzle_hash: Bytes32, asset_id: Bytes32) -> Bytes32 {
    Bytes32::from(CatArgs::curry_tree_hash(asset_id, TreeHash::from(inner_puzzle_hash)).to_bytes())
}

/// Resolve a CAT coin from on-chain data by fetching its parent's puzzle and solution.
///
/// Adapted from DataLayer-Driver dig_coin.rs `from_coin` pattern.
pub async fn resolve_cat_coin(
    client: &ChiaQuery,
    coin: &chia::protocol::Coin,
    parent_coin_info_hex: &str,
    confirmed_height: u32,
    asset_id: Bytes32,
) -> WalletResult<Cat> {
    let mut ctx = SpendContext::new();

    // Fetch parent coin record
    let parent_record = client
        .get_coin_record_by_name(parent_coin_info_hex)
        .await
        .map_err(|e| WalletError::InvalidCoin(format!("Failed to fetch parent coin: {}", e)))?;

    let parent_coin = coin_record_to_protocol_coin(&parent_record)?;

    // Fetch parent puzzle and solution
    let parent_spend = client
        .get_puzzle_and_solution(parent_coin_info_hex, Some(confirmed_height))
        .await
        .map_err(|e| {
            WalletError::InvalidCoin(format!("Failed to fetch parent puzzle/solution: {}", e))
        })?;

    // Parse hex puzzle and solution into CLVM
    let puzzle_hex = parent_spend
        .puzzle_reveal
        .strip_prefix("0x")
        .unwrap_or(&parent_spend.puzzle_reveal);
    let solution_hex = parent_spend
        .solution
        .strip_prefix("0x")
        .unwrap_or(&parent_spend.solution);

    let puzzle_bytes =
        hex::decode(puzzle_hex).map_err(|e| WalletError::InvalidCoin(e.to_string()))?;
    let solution_bytes =
        hex::decode(solution_hex).map_err(|e| WalletError::InvalidCoin(e.to_string()))?;

    let puzzle_program = Program::from(puzzle_bytes);
    let solution_program = Program::from(solution_bytes);

    let parent_puzzle_ptr = ctx
        .alloc(&puzzle_program)
        .map_err(|e| WalletError::SpendConstruction(format!("Failed to alloc puzzle: {:?}", e)))?;

    let parent_puzzle = Puzzle::parse(&ctx, parent_puzzle_ptr);

    let parent_solution = ctx.alloc(&solution_program).map_err(|e| {
        WalletError::SpendConstruction(format!("Failed to alloc solution: {:?}", e))
    })?;

    // Parse CAT children from the parent spend
    let parsed_children =
        Cat::parse_children(&mut ctx, parent_coin, parent_puzzle, parent_solution)
            .map_err(|e| WalletError::SpendConstruction(format!("Failed to parse CAT: {:?}", e)))?
            .ok_or_else(|| WalletError::InvalidCoin("Parent is not a CAT spend".into()))?;

    // Find the specific child coin we're looking for
    let proved_cat = parsed_children
        .into_iter()
        .find(|child| {
            child.coin.coin_id() == coin.coin_id()
                && child.lineage_proof.is_some()
                && child.info.asset_id == asset_id
        })
        .ok_or_else(|| {
            WalletError::InvalidCoin("Could not find matching CAT child with lineage proof".into())
        })?;

    Ok(proved_cat)
}

/// Build coin spends for a CAT send transaction.
///
/// Uses Cat::spend_all with CatSpend for proper ring accounting.
/// If fee > 0, XCH fee coins are spent separately with RESERVE_FEE.
pub fn build_cat_send(
    synthetic_pk: PublicKey,
    cat_coins: &[Cat],
    dest_puzzle_hash: Bytes32,
    amount: u64,
    fee: u64,
    change_puzzle_hash: Bytes32,
    xch_fee_coins: &[Coin],
) -> WalletResult<Vec<CoinSpend>> {
    if cat_coins.is_empty() {
        return Err(WalletError::SpendConstruction(
            "No CAT coins provided".into(),
        ));
    }

    let total_cat: u64 = cat_coins.iter().map(|c| c.coin.amount).sum();
    if total_cat < amount {
        return Err(WalletError::InsufficientFunds {
            available: total_cat,
            required: amount,
        });
    }

    let mut ctx = SpendContext::new();
    let p2 = StandardLayer::new(synthetic_pk);
    let cat_change = total_cat - amount;

    // Build CatSpends
    let mut cat_spends = Vec::new();
    for (i, cat) in cat_coins.iter().enumerate() {
        let inner_conditions = if i == 0 {
            let dest_hint = ctx
                .hint(dest_puzzle_hash)
                .map_err(|e| WalletError::SpendConstruction(format!("{:?}", e)))?;

            let mut conds = Conditions::new().create_coin(dest_puzzle_hash, amount, dest_hint);
            if cat_change > 0 {
                conds = conds.create_coin(change_puzzle_hash, cat_change, Memos::None);
            }
            conds
        } else {
            Conditions::new()
        };

        let inner_spend = p2.spend_with_conditions(&mut ctx, inner_conditions)?;
        cat_spends.push(CatSpend::new(*cat, inner_spend));
    }

    Cat::spend_all(&mut ctx, &cat_spends)?;

    // Handle XCH fee coins if needed
    if fee > 0 && !xch_fee_coins.is_empty() {
        spend_xch_fee(
            &mut ctx,
            &p2,
            xch_fee_coins,
            fee,
            cat_coins[0].coin.coin_id(),
        )?;
    }

    Ok(ctx.take())
}

/// Build coin spends to combine multiple CAT coins into one.
pub fn build_cat_combine(
    synthetic_pk: PublicKey,
    cat_coins: &[Cat],
    own_puzzle_hash: Bytes32,
    fee: u64,
    xch_fee_coins: &[Coin],
) -> WalletResult<Vec<CoinSpend>> {
    if cat_coins.len() < 2 {
        return Err(WalletError::SpendConstruction(
            "Need at least 2 CAT coins to combine".into(),
        ));
    }

    let total: u64 = cat_coins.iter().map(|c| c.coin.amount).sum();

    let mut ctx = SpendContext::new();
    let p2 = StandardLayer::new(synthetic_pk);

    let mut cat_spends = Vec::new();
    for (i, cat) in cat_coins.iter().enumerate() {
        let conditions = if i == 0 {
            Conditions::new().create_coin(own_puzzle_hash, total, Memos::None)
        } else {
            Conditions::new()
        };

        let inner_spend = p2.spend_with_conditions(&mut ctx, conditions)?;
        cat_spends.push(CatSpend::new(*cat, inner_spend));
    }

    Cat::spend_all(&mut ctx, &cat_spends)?;

    // Handle XCH fee
    if fee > 0 && !xch_fee_coins.is_empty() {
        spend_xch_fee(
            &mut ctx,
            &p2,
            xch_fee_coins,
            fee,
            cat_coins[0].coin.coin_id(),
        )?;
    }

    Ok(ctx.take())
}

/// Build coin spends to split one CAT coin into multiple pieces.
pub fn build_cat_split(
    synthetic_pk: PublicKey,
    cat_coin: &Cat,
    target_count: u32,
    own_puzzle_hash: Bytes32,
    fee: u64,
    xch_fee_coins: &[Coin],
) -> WalletResult<Vec<CoinSpend>> {
    if target_count < 2 {
        return Err(WalletError::SpendConstruction(
            "target_count must be at least 2".into(),
        ));
    }

    let total = cat_coin.coin.amount;
    let split_amount = total / target_count as u64;
    let remainder = total % target_count as u64;

    if split_amount == 0 {
        return Err(WalletError::SpendConstruction(
            "CAT coin too small to split".into(),
        ));
    }

    let mut ctx = SpendContext::new();
    let p2 = StandardLayer::new(synthetic_pk);

    let mut conditions =
        Conditions::new().create_coin(own_puzzle_hash, split_amount + remainder, Memos::None);

    for _ in 1..target_count {
        conditions = conditions.create_coin(own_puzzle_hash, split_amount, Memos::None);
    }

    let inner_spend = p2.spend_with_conditions(&mut ctx, conditions)?;
    Cat::spend_all(&mut ctx, &[CatSpend::new(*cat_coin, inner_spend)])?;

    // Handle XCH fee
    if fee > 0 && !xch_fee_coins.is_empty() {
        spend_xch_fee(&mut ctx, &p2, xch_fee_coins, fee, cat_coin.coin.coin_id())?;
    }

    Ok(ctx.take())
}

/// Helper: spend XCH coins for fee payment, linked to a CAT spend via assert_concurrent_spend.
fn spend_xch_fee(
    ctx: &mut SpendContext,
    p2: &StandardLayer,
    xch_fee_coins: &[Coin],
    fee: u64,
    link_coin_id: Bytes32,
) -> WalletResult<()> {
    let xch_total: u64 = xch_fee_coins.iter().map(|c| c.amount).sum();
    let xch_change = xch_total - fee;

    let mut conditions = Conditions::new()
        .reserve_fee(fee)
        .assert_concurrent_spend(link_coin_id);

    if xch_change > 0 {
        let change_ph = Bytes32::from(p2.tree_hash());
        conditions = conditions.create_coin(change_ph, xch_change, Memos::None);
    }

    p2.spend(ctx, xch_fee_coins[0], conditions)?;

    let first_xch_id = xch_fee_coins[0].coin_id();
    for coin in &xch_fee_coins[1..] {
        p2.spend(
            ctx,
            *coin,
            Conditions::new().assert_concurrent_spend(first_xch_id),
        )?;
    }

    Ok(())
}
