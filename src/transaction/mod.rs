//! XCH transaction building, signing, and spend bundle construction.
//!
//! ## Architecture
//!
//! All transaction construction uses `chia-wallet-sdk` primitives:
//! - [`SpendContext`]: Accumulates `CoinSpend`s during construction
//! - [`StandardLayer`]: Wraps the standard P2 puzzle (P2_DELEGATED_PUZZLE_OR_HIDDEN_PUZZLE)
//! - [`Conditions`]: Builder for output conditions (CREATE_COIN, RESERVE_FEE, etc.)
//! - [`RequiredSignature::from_coin_spends`]: Extracts BLS signature requirements
//!
//! ## Multi-Coin Spending Pattern
//!
//! When spending multiple coins in one transaction (e.g., coin selection chose 3 coins):
//! 1. **First coin** carries all output conditions (CREATE_COIN, RESERVE_FEE, change)
//! 2. **Remaining coins** use `assert_concurrent_spend(first_coin_id)` — this
//!    cryptographically binds them to the first coin's spend, preventing replay.
//!
//! This pattern is adapted from DataLayer-Driver `wallet.rs::spend_coins_together`
//! (lines 131-165).
//!
//! ## Signing Pattern
//!
//! The signing function maps each secret key to BOTH its original public key
//! AND its synthetic public key (via `DeriveSynthetic`). This is because the
//! standard puzzle may require signatures from either variant depending on the
//! AGG_SIG condition. Pattern from DataLayer-Driver `wallet.rs::sign_coin_spends`
//! (lines 985-1026).
//!
//! ## Reference
//!
//! - DataLayer-Driver: `wallet.rs` lines 131-194 (spend), 985-1026 (sign)
//! - See SPEC.md §10 "Transaction Construction"

pub mod cat;

use std::collections::HashMap;

use chia::bls::{sign, PublicKey, SecretKey, Signature};
use chia::protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
use chia::puzzles::{DeriveSynthetic, Memos};
use chia_query::NetworkType;
use chia_wallet_sdk::driver::{SpendContext, StandardLayer};
use chia_wallet_sdk::signer::{AggSigConstants, RequiredSignature};
use chia_wallet_sdk::types::{Conditions, MAINNET_CONSTANTS, TESTNET11_CONSTANTS};
use clvmr::Allocator;

use crate::types::{WalletError, WalletResult};

/// Build coin spends for an XCH send transaction.
///
/// First coin carries all output conditions; remaining coins assert concurrent spend.
pub fn build_xch_send(
    synthetic_pk: PublicKey,
    coins: &[Coin],
    dest_puzzle_hash: Bytes32,
    amount: u64,
    fee: u64,
    change_puzzle_hash: Bytes32,
) -> WalletResult<Vec<CoinSpend>> {
    if coins.is_empty() {
        return Err(WalletError::SpendConstruction("No coins provided".into()));
    }

    let total: u64 = coins.iter().map(|c| c.amount).sum();
    if total < amount + fee {
        return Err(WalletError::InsufficientFunds {
            available: total,
            required: amount + fee,
        });
    }

    let mut ctx = SpendContext::new();
    let p2 = StandardLayer::new(synthetic_pk);
    let change = total - amount - fee;

    // First coin: all output conditions
    let hint = ctx
        .hint(dest_puzzle_hash)
        .map_err(|e| WalletError::SpendConstruction(format!("{:?}", e)))?;

    let mut conditions = Conditions::new().create_coin(dest_puzzle_hash, amount, hint);

    if change > 0 {
        conditions = conditions.create_coin(change_puzzle_hash, change, Memos::None);
    }
    if fee > 0 {
        conditions = conditions.reserve_fee(fee);
    }

    p2.spend(&mut ctx, coins[0], conditions)?;

    // Remaining coins: assert concurrent spend with first coin
    let first_coin_id = coins[0].coin_id();
    for coin in &coins[1..] {
        p2.spend(
            &mut ctx,
            *coin,
            Conditions::new().assert_concurrent_spend(first_coin_id),
        )?;
    }

    Ok(ctx.take())
}

/// Build coin spends to combine multiple coins into one.
pub fn build_combine_tx(
    synthetic_pk: PublicKey,
    coins: &[Coin],
    own_puzzle_hash: Bytes32,
    fee: u64,
) -> WalletResult<Vec<CoinSpend>> {
    if coins.len() < 2 {
        return Err(WalletError::SpendConstruction(
            "Need at least 2 coins to combine".into(),
        ));
    }

    let total: u64 = coins.iter().map(|c| c.amount).sum();
    if total <= fee {
        return Err(WalletError::InsufficientFunds {
            available: total,
            required: fee + 1,
        });
    }

    let output_amount = total - fee;

    let mut ctx = SpendContext::new();
    let p2 = StandardLayer::new(synthetic_pk);

    // First coin: create combined output
    let mut conditions = Conditions::new().create_coin(own_puzzle_hash, output_amount, Memos::None);
    if fee > 0 {
        conditions = conditions.reserve_fee(fee);
    }
    p2.spend(&mut ctx, coins[0], conditions)?;

    // Remaining coins: assert concurrent spend
    let first_coin_id = coins[0].coin_id();
    for coin in &coins[1..] {
        p2.spend(
            &mut ctx,
            *coin,
            Conditions::new().assert_concurrent_spend(first_coin_id),
        )?;
    }

    Ok(ctx.take())
}

/// Build coin spends to split one coin into multiple equal pieces.
pub fn build_split_tx(
    synthetic_pk: PublicKey,
    coin: Coin,
    target_count: u32,
    own_puzzle_hash: Bytes32,
    fee: u64,
) -> WalletResult<Vec<CoinSpend>> {
    if target_count < 2 {
        return Err(WalletError::SpendConstruction(
            "target_count must be at least 2".into(),
        ));
    }
    if coin.amount <= fee {
        return Err(WalletError::InsufficientFunds {
            available: coin.amount,
            required: fee + target_count as u64,
        });
    }

    let spendable = coin.amount - fee;
    let split_amount = spendable / target_count as u64;
    let remainder = spendable % target_count as u64;

    if split_amount == 0 {
        return Err(WalletError::SpendConstruction(
            "Coin too small to split into that many pieces".into(),
        ));
    }

    let mut ctx = SpendContext::new();
    let p2 = StandardLayer::new(synthetic_pk);

    // Build conditions: first output gets remainder, rest are equal
    let mut conditions =
        Conditions::new().create_coin(own_puzzle_hash, split_amount + remainder, Memos::None);

    for _ in 1..target_count {
        conditions = conditions.create_coin(own_puzzle_hash, split_amount, Memos::None);
    }

    if fee > 0 {
        conditions = conditions.reserve_fee(fee);
    }

    p2.spend(&mut ctx, coin, conditions)?;

    Ok(ctx.take())
}

/// Sign coin spends using the DataLayer-Driver pattern.
///
/// Maps each secret key to both its original PK and synthetic PK,
/// then matches against RequiredSignature results.
pub fn sign_coin_spends(
    coin_spends: &[CoinSpend],
    secret_keys: &[SecretKey],
    agg_sig_data: Bytes32,
) -> WalletResult<Signature> {
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
    let required = RequiredSignature::from_coin_spends(&mut allocator, coin_spends, &agg_sig)?;

    let mut sig = Signature::default();

    for req in required {
        let RequiredSignature::Bls(bls_req) = req else {
            continue;
        };

        if let Some(sk) = key_pairs.get(&bls_req.public_key) {
            sig += &sign(sk, bls_req.message());
        }
    }

    Ok(sig)
}

/// Assemble a SpendBundle from coin spends and a signature.
pub fn assemble_spend_bundle(coin_spends: Vec<CoinSpend>, signature: Signature) -> SpendBundle {
    SpendBundle::new(coin_spends, signature)
}

/// Get the AGG_SIG_ME additional data for a network.
pub fn get_agg_sig_data(network: NetworkType) -> Bytes32 {
    match network {
        NetworkType::Mainnet => MAINNET_CONSTANTS.agg_sig_me_additional_data,
        NetworkType::Testnet11 => TESTNET11_CONSTANTS.agg_sig_me_additional_data,
    }
}
