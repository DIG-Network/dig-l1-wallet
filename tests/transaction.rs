//! Tests for XCH transaction building and signing.

use chia::bls::SecretKey;
use chia::protocol::{Bytes32, Coin};
use chia::puzzles::{DeriveSynthetic, LineageProof};
use chia_puzzle_types::standard::StandardArgs;
use chia_query::CoinRecord;
use chia_wallet_sdk::driver::{Cat, CatInfo};
use chia_wallet_sdk::types::MAINNET_CONSTANTS;

use dig_l1_wallet::coins::selection;
use dig_l1_wallet::coins::tracker::coin_record_to_protocol_coin;
use dig_l1_wallet::transaction;
use dig_l1_wallet::transaction::cat as cat_tx;

fn test_key_and_coin() -> (SecretKey, Coin, Bytes32) {
    let master_sk = SecretKey::from_seed(&[42u8; 32]);
    let account_sk = chia::bls::master_to_wallet_unhardened(&master_sk, 0);
    let synthetic_pk = account_sk.public_key().derive_synthetic();
    let puzzle_hash = Bytes32::from(StandardArgs::curry_tree_hash(synthetic_pk));

    let coin = Coin {
        parent_coin_info: Bytes32::from([1u8; 32]),
        puzzle_hash,
        amount: 1_000_000_000_000,
    };

    (account_sk, coin, puzzle_hash)
}

#[test]
fn test_build_xch_send() {
    let (account_sk, coin, own_ph) = test_key_and_coin();
    let synthetic_pk = account_sk.public_key().derive_synthetic();
    let dest_ph = Bytes32::from([99u8; 32]);

    let spends = transaction::build_xch_send(
        synthetic_pk,
        &[coin],
        dest_ph,
        500_000_000_000,
        50_000_000,
        own_ph,
    )
    .unwrap();

    assert_eq!(spends.len(), 1);
    assert_eq!(spends[0].coin, coin);
}

#[test]
fn test_build_xch_send_insufficient_funds() {
    let (account_sk, coin, own_ph) = test_key_and_coin();
    let synthetic_pk = account_sk.public_key().derive_synthetic();
    let dest_ph = Bytes32::from([99u8; 32]);

    let result = transaction::build_xch_send(
        synthetic_pk,
        &[coin],
        dest_ph,
        2_000_000_000_000, // more than coin amount
        0,
        own_ph,
    );

    assert!(result.is_err());
}

#[test]
fn test_build_combine_tx() {
    let (account_sk, coin1, own_ph) = test_key_and_coin();
    let synthetic_pk = account_sk.public_key().derive_synthetic();

    let coin2 = Coin {
        parent_coin_info: Bytes32::from([2u8; 32]),
        puzzle_hash: own_ph,
        amount: 500_000_000_000,
    };

    let spends =
        transaction::build_combine_tx(synthetic_pk, &[coin1, coin2], own_ph, 50_000_000).unwrap();

    assert_eq!(spends.len(), 2);
}

#[test]
fn test_build_split_tx() {
    let (account_sk, coin, own_ph) = test_key_and_coin();
    let synthetic_pk = account_sk.public_key().derive_synthetic();

    let spends = transaction::build_split_tx(synthetic_pk, coin, 5, own_ph, 50_000_000).unwrap();

    assert_eq!(spends.len(), 1);
}

#[test]
fn test_sign_coin_spends() {
    let (account_sk, coin, own_ph) = test_key_and_coin();
    let synthetic_pk = account_sk.public_key().derive_synthetic();
    let dest_ph = Bytes32::from([99u8; 32]);

    let spends =
        transaction::build_xch_send(synthetic_pk, &[coin], dest_ph, 500_000_000_000, 0, own_ph)
            .unwrap();

    let agg_sig_data = MAINNET_CONSTANTS.agg_sig_me_additional_data;
    let signature = transaction::sign_coin_spends(&spends, &[account_sk], agg_sig_data).unwrap();

    // Signature should not be the default (all zeros)
    assert_ne!(
        signature.to_bytes(),
        chia::bls::Signature::default().to_bytes()
    );
}

#[test]
fn test_assemble_spend_bundle() {
    let (account_sk, coin, own_ph) = test_key_and_coin();
    let synthetic_pk = account_sk.public_key().derive_synthetic();
    let dest_ph = Bytes32::from([99u8; 32]);

    let spends =
        transaction::build_xch_send(synthetic_pk, &[coin], dest_ph, 500_000_000_000, 0, own_ph)
            .unwrap();

    let agg_sig_data = MAINNET_CONSTANTS.agg_sig_me_additional_data;
    let signature = transaction::sign_coin_spends(&spends, &[account_sk], agg_sig_data).unwrap();

    let bundle = transaction::assemble_spend_bundle(spends, signature);
    assert_eq!(bundle.coin_spends.len(), 1);
}

// ---------------------------------------------------------------------------
// Cap-aware consolidation: selection helper feeds the existing combine builders
// (XCH + CAT), merging up to `cap` highest-value coins into one owner coin.
// ---------------------------------------------------------------------------

/// Build an unspent XCH `CoinRecord` whose puzzle hash is the owner's.
fn xch_record(amount: u64, seed: u8, own_ph: Bytes32) -> CoinRecord {
    CoinRecord {
        coin: chia_query::Coin {
            parent_coin_info: format!("0x{}", hex::encode([seed; 32])),
            puzzle_hash: format!("0x{}", hex::encode(own_ph.as_ref())),
            amount,
        },
        confirmed_block_index: 1,
        spent_block_index: 0,
        spent: false,
        coinbase: false,
        timestamp: 0,
    }
}

#[test]
fn consolidation_selects_and_builds_xch_combine_n_to_1() {
    let (account_sk, _coin, own_ph) = test_key_and_coin();
    let synthetic_pk = account_sk.public_key().derive_synthetic();

    // 4 coins; cap 3 → the 3 highest-value coins merge into 1.
    let records = [
        xch_record(5_000, 1, own_ph),
        xch_record(1_000, 2, own_ph),
        xch_record(4_000, 3, own_ph),
        xch_record(2_000, 4, own_ph),
    ];
    let picked = selection::select_for_consolidation(&records, 3).unwrap();
    assert_eq!(picked.len(), 3);
    assert_eq!(picked[0].coin.amount, 5_000); // largest leads

    let coins: Vec<Coin> = picked
        .iter()
        .map(|r| coin_record_to_protocol_coin(r).unwrap())
        .collect();

    let fee = 500;
    let spends = transaction::build_combine_tx(synthetic_pk, &coins, own_ph, fee).unwrap();
    // N inputs → 1 output: one CoinSpend per input, lead coin spent first.
    assert_eq!(spends.len(), 3);
    assert_eq!(spends[0].coin.amount, 5_000);

    // Change/fee arithmetic: the merged output is total - fee. A fee that would
    // leave nothing to output must be rejected (guards the change computation).
    let total: u64 = coins.iter().map(|c| c.amount).sum(); // 11_000
    assert!(transaction::build_combine_tx(synthetic_pk, &coins, own_ph, total).is_err());
    assert!(transaction::build_combine_tx(synthetic_pk, &coins, own_ph, total - 1).is_ok());
}

/// Fabricate a CAT of `asset_id` owned by `synthetic_pk`'s standard puzzle.
fn make_cat(synthetic_pk: chia::bls::PublicKey, asset_id: Bytes32, amount: u64, seed: u8) -> Cat {
    let p2_puzzle_hash = Bytes32::from(StandardArgs::curry_tree_hash(synthetic_pk));
    let outer_puzzle_hash = cat_tx::cat_puzzle_hash(p2_puzzle_hash, asset_id);
    let coin = Coin {
        parent_coin_info: Bytes32::from([seed; 32]),
        puzzle_hash: outer_puzzle_hash,
        amount,
    };
    let lineage_proof = LineageProof {
        parent_parent_coin_info: Bytes32::from([seed ^ 0xFF; 32]),
        parent_inner_puzzle_hash: p2_puzzle_hash,
        parent_amount: amount,
    };
    Cat::new(
        coin,
        Some(lineage_proof),
        CatInfo::new(asset_id, None, p2_puzzle_hash),
    )
}

#[test]
fn consolidation_builds_cat_combine_n_to_1() {
    let (account_sk, _coin, own_ph) = test_key_and_coin();
    let synthetic_pk = account_sk.public_key().derive_synthetic();
    let asset_id = Bytes32::from([7u8; 32]);

    // 3 CAT coins → 1 output (ring nets to zero; fee=0 so no separate XCH coin).
    let cats = [
        make_cat(synthetic_pk, asset_id, 3_000, 1),
        make_cat(synthetic_pk, asset_id, 2_000, 2),
        make_cat(synthetic_pk, asset_id, 1_000, 3),
    ];
    let spends = cat_tx::build_cat_combine(synthetic_pk, &cats, own_ph, 0, &[]).unwrap();
    assert_eq!(spends.len(), 3);

    // Requires ≥2 coins.
    assert!(cat_tx::build_cat_combine(synthetic_pk, &cats[..1], own_ph, 0, &[]).is_err());
}
