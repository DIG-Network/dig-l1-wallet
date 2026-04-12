//! Tests for XCH transaction building and signing.

use chia::bls::SecretKey;
use chia::protocol::{Bytes32, Coin};
use chia::puzzles::DeriveSynthetic;
use chia_puzzle_types::standard::StandardArgs;
use chia_wallet_sdk::types::MAINNET_CONSTANTS;

use dig_l1_wallet::transaction;

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

    let spends = transaction::build_combine_tx(
        synthetic_pk,
        &[coin1, coin2],
        own_ph,
        50_000_000,
    )
    .unwrap();

    assert_eq!(spends.len(), 2);
}

#[test]
fn test_build_split_tx() {
    let (account_sk, coin, own_ph) = test_key_and_coin();
    let synthetic_pk = account_sk.public_key().derive_synthetic();

    let spends = transaction::build_split_tx(
        synthetic_pk,
        coin,
        5,
        own_ph,
        50_000_000,
    )
    .unwrap();

    assert_eq!(spends.len(), 1);
}

#[test]
fn test_sign_coin_spends() {
    let (account_sk, coin, own_ph) = test_key_and_coin();
    let synthetic_pk = account_sk.public_key().derive_synthetic();
    let dest_ph = Bytes32::from([99u8; 32]);

    let spends = transaction::build_xch_send(
        synthetic_pk,
        &[coin],
        dest_ph,
        500_000_000_000,
        0,
        own_ph,
    )
    .unwrap();

    let agg_sig_data = MAINNET_CONSTANTS.agg_sig_me_additional_data;
    let signature = transaction::sign_coin_spends(&spends, &[account_sk], agg_sig_data).unwrap();

    // Signature should not be the default (all zeros)
    assert_ne!(signature.to_bytes(), chia::bls::Signature::default().to_bytes());
}

#[test]
fn test_assemble_spend_bundle() {
    let (account_sk, coin, own_ph) = test_key_and_coin();
    let synthetic_pk = account_sk.public_key().derive_synthetic();
    let dest_ph = Bytes32::from([99u8; 32]);

    let spends = transaction::build_xch_send(
        synthetic_pk,
        &[coin],
        dest_ph,
        500_000_000_000,
        0,
        own_ph,
    )
    .unwrap();

    let agg_sig_data = MAINNET_CONSTANTS.agg_sig_me_additional_data;
    let signature = transaction::sign_coin_spends(&spends, &[account_sk], agg_sig_data).unwrap();

    let bundle = transaction::assemble_spend_bundle(spends, signature);
    assert_eq!(bundle.coin_spends.len(), 1);
}
