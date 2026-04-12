//! Integration tests requiring live chain access.
//! Run with: cargo test --test integration -- --ignored

use dig_l1_wallet::{L1Wallet, L1WalletConfig};

#[tokio::test]
#[ignore]
async fn test_create_and_query_wallet() {
    let config = L1WalletConfig {
        wallet_dir: std::env::temp_dir().join("dig-l1-wallet-test"),
        ..Default::default()
    };

    let wallet = L1Wallet::new(config).await.unwrap();

    // Create wallet
    let backup = wallet
        .create_wallet("test-wallet", "test-password")
        .await
        .unwrap();
    assert!(backup.first_address.starts_with("xch1"));
    assert_eq!(backup.mnemonic.split_whitespace().count(), 24);

    // Unlock
    wallet.unlock("test-wallet", "test-password").unwrap();
    assert!(wallet.is_unlocked("test-wallet").unwrap());

    // Query balance (will be 0 for a new wallet)
    let balance = wallet
        .get_xch_balance("test-wallet", Some(0))
        .await
        .unwrap();
    assert_eq!(balance.confirmed, 0);

    // Lock
    wallet.lock("test-wallet");
    assert!(!wallet.is_unlocked("test-wallet").unwrap());

    // Cleanup
    wallet.delete_wallet("test-wallet").unwrap();
}
