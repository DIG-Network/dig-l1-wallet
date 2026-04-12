//! Tests for encryption, mnemonic generation, and key derivation.

use dig_l1_wallet::keystore::encryption;
use dig_l1_wallet::keystore::mnemonic;
use dig_l1_wallet::keys::derivation;

#[test]
fn test_encrypt_decrypt_secret_key_roundtrip() {
    let secret_key = [42u8; 32];
    let password = "strong_password_123!";

    let encrypted = encryption::encrypt_secret_key(&secret_key, password).unwrap();
    let decrypted = encryption::decrypt_secret_key(&encrypted, password).unwrap();

    assert_eq!(decrypted, secret_key);
}

#[test]
fn test_wrong_password_fails() {
    let secret_key = [42u8; 32];
    let encrypted = encryption::encrypt_secret_key(&secret_key, "correct").unwrap();
    let result = encryption::decrypt_secret_key(&encrypted, "wrong");
    assert!(result.is_err());
}

#[test]
fn test_generate_24_word_mnemonic() {
    let mnemonic = mnemonic::generate_mnemonic().unwrap();
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    assert_eq!(words.len(), 24);
}

#[test]
fn test_mnemonic_validation() {
    let mnemonic = mnemonic::generate_mnemonic().unwrap();
    mnemonic::validate_mnemonic(&mnemonic).unwrap();

    assert!(mnemonic::validate_mnemonic("not valid at all").is_err());
}

#[test]
fn test_mnemonic_deterministic_key_derivation() {
    let mnemonic = mnemonic::generate_mnemonic().unwrap();
    let sk1 = mnemonic::derive_master_key_from_mnemonic(&mnemonic).unwrap();
    let sk2 = mnemonic::derive_master_key_from_mnemonic(&mnemonic).unwrap();
    assert_eq!(sk1.to_bytes(), sk2.to_bytes());
}

#[test]
fn test_derive_different_indexes_produce_different_keys() {
    let master_sk = chia::bls::SecretKey::from_seed(&[42u8; 32]);
    let (sk0, _, _, ph0, _) = derivation::derive_account(&master_sk, 0, "xch").unwrap();
    let (sk1, _, _, ph1, _) = derivation::derive_account(&master_sk, 1, "xch").unwrap();

    assert_ne!(sk0.to_bytes(), sk1.to_bytes());
    assert_ne!(ph0, ph1);
}

#[test]
fn test_address_roundtrip() {
    let master_sk = chia::bls::SecretKey::from_seed(&[42u8; 32]);
    let (_, _, _, puzzle_hash, address) = derivation::derive_account(&master_sk, 0, "xch").unwrap();

    assert!(address.starts_with("xch1"));

    let decoded = derivation::decode_address(&address).unwrap();
    assert_eq!(decoded, puzzle_hash);
}

#[test]
fn test_testnet_address_prefix() {
    let master_sk = chia::bls::SecretKey::from_seed(&[42u8; 32]);
    let (_, _, _, _, address) = derivation::derive_account(&master_sk, 0, "txch").unwrap();
    assert!(address.starts_with("txch1"));
}

#[test]
fn test_synthetic_sk_matches_synthetic_pk() {
    let master_sk = chia::bls::SecretKey::from_seed(&[42u8; 32]);
    let syn_sk = derivation::derive_synthetic_sk(&master_sk, 0);
    let (_, _, synthetic_pk, _, _) = derivation::derive_account(&master_sk, 0, "xch").unwrap();

    assert_eq!(syn_sk.public_key(), synthetic_pk);
}
