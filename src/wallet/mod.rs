//! [`L1Wallet`] — primary entry point for the dig-l1-wallet crate.
//!
//! ## Role
//!
//! `L1Wallet` is the **orchestrator** that composes all subsystems:
//! - [`Keystore`](crate::keystore::Keystore) for in-memory key management
//! - [`WalletStorage`](crate::storage::WalletStorage) for `.wallet` file I/O
//! - [`ChiaQuery`](chia_query::ChiaQuery) for all blockchain interaction
//! - [`transaction`](crate::transaction) module for spend bundle construction
//! - [`coins`](crate::coins) module for coin queries and selection
//!
//! ## Derivation Index Convention
//!
//! Methods that query the chain accept `account_index: Option<u32>`:
//! - `Some(0)`: The default (first) synthetic key at `m/12381/8444/2/0`
//! - `Some(n)`: A specific derivation index
//! - `None`: Operate across ALL known derivation indexes
//!
//! Methods that **sign transactions** require `account_index: u32` (not optional)
//! because the signing key must be unambiguous.
//!
//! ## Thread Safety
//!
//! Per-wallet keystores are held in a `RwLock<HashMap<String, Keystore>>`.
//! Multiple wallets can be unlocked concurrently. Within a single wallet,
//! the `Keystore` uses its own `RwLock`s for key access.
//!
//! ## Reference
//!
//! See SPEC.md §8 "Public API" for the full method signatures and behavior.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Duration;

use chia::bls::SecretKey;
use chia::protocol::Bytes32;
use chia::puzzles::DeriveSynthetic;
use chia_puzzle_types::standard::StandardArgs;
use chia_query::{ChiaQuery, CoinRecord, FeeEstimate};

use crate::coins;
use crate::coins::selection;
use crate::coins::tracker::{
    bytes32_to_hex, coin_record_to_protocol_coin, hex_to_bytes32, protocol_spend_bundle_to_query,
};
use crate::keys::derivation;
use crate::keystore::Keystore;
use crate::storage::format::{WalletAccount, WalletFile};
use crate::storage::{self, WalletStorage};
use crate::transaction;
use crate::transaction::cat as cat_tx;
use crate::types::*;

/// Self-custodial Chia L1 wallet.
pub struct L1Wallet {
    network: chia_query::NetworkType,
    client: ChiaQuery,
    keystores: RwLock<HashMap<String, Keystore>>,
    storage: WalletStorage,
}

impl L1Wallet {
    // ── Construction ──────────────────────────────────────────────

    /// Create a new L1Wallet instance.
    /// Initializes chia-query for blockchain access.
    pub async fn new(config: L1WalletConfig) -> WalletResult<Self> {
        let storage = WalletStorage::new(config.wallet_dir.clone());
        storage.ensure_dir()?;

        let client = ChiaQuery::new(config.query_config)
            .await
            .map_err(WalletError::Query)?;

        Ok(Self {
            network: config.network,
            client,
            keystores: RwLock::new(HashMap::new()),
            storage,
        })
    }

    // ── Wallet Management ─────────────────────────────────────────

    /// Create a new wallet with a generated BIP39 mnemonic.
    /// Automatically creates account at derivation index 0.
    pub async fn create_wallet(&self, name: &str, password: &str) -> WalletResult<MnemonicBackup> {
        if self.storage.wallet_exists(name) {
            return Err(WalletError::WalletAlreadyExists(name.to_string()));
        }

        let mnemonic = crate::keystore::mnemonic::generate_mnemonic()?;
        let master_sk = crate::keystore::mnemonic::derive_master_key_from_mnemonic(&mnemonic)?;

        let wallet_file = self.build_wallet_file(name, &master_sk, password)?;
        self.storage.save_wallet(&wallet_file)?;

        let first_address = wallet_file.accounts[0].address.clone();

        Ok(MnemonicBackup {
            mnemonic,
            wallet_name: name.to_string(),
            first_address,
        })
    }

    /// Import a wallet from a BIP39 mnemonic phrase.
    pub async fn import_from_mnemonic(
        &self,
        name: &str,
        mnemonic: &str,
        password: &str,
    ) -> WalletResult<()> {
        if self.storage.wallet_exists(name) {
            return Err(WalletError::WalletAlreadyExists(name.to_string()));
        }

        crate::keystore::mnemonic::validate_mnemonic(mnemonic)?;
        let master_sk = crate::keystore::mnemonic::derive_master_key_from_mnemonic(mnemonic)?;

        let wallet_file = self.build_wallet_file(name, &master_sk, password)?;
        self.storage.save_wallet(&wallet_file)?;

        Ok(())
    }

    /// Import a wallet from a raw secret key (32 bytes).
    pub async fn import_from_secret_key(
        &self,
        name: &str,
        secret_key: &[u8; 32],
        password: &str,
    ) -> WalletResult<()> {
        if self.storage.wallet_exists(name) {
            return Err(WalletError::WalletAlreadyExists(name.to_string()));
        }

        let master_sk = SecretKey::from_bytes(secret_key)
            .map_err(|e| WalletError::InvalidSecretKey(format!("{}", e)))?;

        let wallet_file = self.build_wallet_file(name, &master_sk, password)?;
        self.storage.save_wallet(&wallet_file)?;

        Ok(())
    }

    /// List all wallet names found in the wallet directory.
    pub fn list_wallets(&self) -> WalletResult<Vec<String>> {
        self.storage.list_wallets()
    }

    /// Delete a wallet file from disk.
    pub fn delete_wallet(&self, name: &str) -> WalletResult<()> {
        self.keystores.write().unwrap().remove(name);
        self.storage.delete_wallet(name)
    }

    /// Rename a wallet.
    pub fn rename_wallet(&self, old_name: &str, new_name: &str) -> WalletResult<()> {
        // Move keystore entry if it exists
        let ks = self.keystores.write().unwrap().remove(old_name);
        if let Some(ks) = ks {
            self.keystores
                .write()
                .unwrap()
                .insert(new_name.to_string(), ks);
        }
        self.storage.rename_wallet(old_name, new_name)
    }

    // ── Lock / Unlock ─────────────────────────────────────────────

    /// Unlock a wallet by decrypting its master key with the given password.
    pub fn unlock(&self, name: &str, password: &str) -> WalletResult<()> {
        let wallet_file = self.storage.load_wallet(name)?;
        let encrypted_bytes = hex::decode(
            wallet_file
                .encrypted_master_key
                .strip_prefix("0x")
                .unwrap_or(&wallet_file.encrypted_master_key),
        )
        .map_err(|e| WalletError::Decryption(format!("Invalid hex in wallet file: {}", e)))?;

        let prefix = address_prefix(self.network);
        let keystore = Keystore::new();
        keystore.unlock(&encrypted_bytes, password, &wallet_file.accounts, prefix)?;

        self.keystores
            .write()
            .unwrap()
            .insert(name.to_string(), keystore);
        Ok(())
    }

    /// Lock a wallet, clearing all decrypted key material from memory.
    pub fn lock(&self, name: &str) {
        if let Some(ks) = self.keystores.write().unwrap().get(name) {
            ks.lock();
        }
        self.keystores.write().unwrap().remove(name);
    }

    /// Check if a wallet is currently unlocked.
    pub fn is_unlocked(&self, name: &str) -> WalletResult<bool> {
        Ok(self
            .keystores
            .read()
            .unwrap()
            .get(name)
            .map(|ks| ks.is_unlocked())
            .unwrap_or(false))
    }

    // ── Account Management ────────────────────────────────────────

    /// Add a new derived account to the wallet.
    pub fn create_account(
        &self,
        wallet_name: &str,
        account_name: &str,
    ) -> WalletResult<AccountInfo> {
        self.assert_unlocked(wallet_name)?;
        let mut wallet_file = self.storage.load_wallet(wallet_name)?;

        let next_index = wallet_file
            .accounts
            .iter()
            .map(|a| a.index)
            .max()
            .map(|m| m + 1)
            .unwrap_or(1); // index 0 always exists already

        let prefix = address_prefix(self.network);
        let (_, puzzle_hash, address) =
            self.keystore_add_derivation(wallet_name, next_index, prefix)?;
        let master_sk = self.get_master_sk(wallet_name)?;
        let account_sk: SecretKey = chia::bls::master_to_wallet_unhardened(&master_sk, next_index);
        let account_pk = account_sk.public_key();
        let synthetic_pk = account_pk.derive_synthetic();

        let account = WalletAccount {
            name: account_name.to_string(),
            index: next_index,
            puzzle_hash: bytes32_to_hex(&puzzle_hash),
            address: address.clone(),
            public_key: hex::encode(account_pk.to_bytes()),
            synthetic_public_key: hex::encode(synthetic_pk.to_bytes()),
            last_sync_height: 0,
        };

        wallet_file.accounts.push(account);
        wallet_file.modified_at = storage::now_secs();
        self.storage.save_wallet(&wallet_file)?;

        Ok(AccountInfo {
            name: account_name.to_string(),
            index: next_index,
            puzzle_hash: bytes32_to_hex(&puzzle_hash),
            address,
        })
    }

    /// List all accounts in a wallet.
    pub fn list_accounts(&self, wallet_name: &str) -> WalletResult<Vec<AccountInfo>> {
        let wallet_file = self.storage.load_wallet(wallet_name)?;
        Ok(wallet_file
            .accounts
            .iter()
            .map(|a| AccountInfo {
                name: a.name.clone(),
                index: a.index,
                puzzle_hash: a.puzzle_hash.clone(),
                address: a.address.clone(),
            })
            .collect())
    }

    // ── Balance Queries ───────────────────────────────────────────

    /// Get XCH balance.
    /// - account_index = Some(n): balance for derivation n
    /// - account_index = None: aggregated across ALL derivations
    pub async fn get_xch_balance(
        &self,
        wallet_name: &str,
        account_index: Option<u32>,
    ) -> WalletResult<Balance> {
        let wallet_file = self.storage.load_wallet(wallet_name)?;
        let coin_records =
            coins::get_all_unspent_xch(&self.client, &wallet_file.accounts, account_index).await?;

        let confirmed: u64 = coin_records.iter().map(|r| r.coin.amount).sum();
        let coin_count = coin_records.len() as u32;

        Ok(Balance {
            confirmed,
            pending: 0,
            spendable: confirmed,
            coin_count,
        })
    }

    /// Get CAT balance by asset ID (0x-prefixed hex TAIL hash).
    pub async fn get_cat_balance(
        &self,
        wallet_name: &str,
        account_index: Option<u32>,
        asset_id: &str,
    ) -> WalletResult<Balance> {
        let wallet_file = self.storage.load_wallet(wallet_name)?;
        let coin_records = coins::get_all_unspent_cat(
            &self.client,
            &wallet_file.accounts,
            account_index,
            asset_id,
        )
        .await?;

        let confirmed: u64 = coin_records.iter().map(|r| r.coin.amount).sum();
        let coin_count = coin_records.len() as u32;

        Ok(Balance {
            confirmed,
            pending: 0,
            spendable: confirmed,
            coin_count,
        })
    }

    // ── Transactions ──────────────────────────────────────────────

    /// Send XCH from a specific derivation index to a destination address.
    pub async fn send_xch(
        &self,
        wallet_name: &str,
        account_index: u32,
        to_address: &str,
        amount_mojos: u64,
        fee_mojos: u64,
    ) -> WalletResult<TxResult> {
        self.assert_unlocked(wallet_name)?;
        let wallet_file = self.storage.load_wallet(wallet_name)?;

        let account_sk = self.get_account_sk(wallet_name, account_index)?;
        let synthetic_pk = account_sk.public_key().derive_synthetic();
        let own_puzzle_hash = Bytes32::from(StandardArgs::curry_tree_hash(synthetic_pk));

        let dest_puzzle_hash = derivation::decode_address(to_address)?;

        // Fetch and select coins
        let coin_records =
            coins::get_all_unspent_xch(&self.client, &wallet_file.accounts, Some(account_index))
                .await?;

        let sel = selection::select_with_strategy(
            &coin_records,
            amount_mojos + fee_mojos,
            CoinSelectionStrategy::Knapsack,
        )?;

        let protocol_coins: Vec<chia::protocol::Coin> = sel
            .coins
            .iter()
            .map(coin_record_to_protocol_coin)
            .collect::<WalletResult<Vec<_>>>()?;

        // Build, sign, broadcast
        let coin_spends = transaction::build_xch_send(
            synthetic_pk,
            &protocol_coins,
            dest_puzzle_hash,
            amount_mojos,
            fee_mojos,
            own_puzzle_hash,
        )?;

        let agg_sig_data = transaction::get_agg_sig_data(self.network);
        let signature = transaction::sign_coin_spends(&coin_spends, &[account_sk], agg_sig_data)?;
        let bundle = transaction::assemble_spend_bundle(coin_spends, signature);

        self.broadcast_protocol_bundle(&bundle).await
    }

    /// Send a CAT from a specific derivation index.
    pub async fn send_cat(
        &self,
        wallet_name: &str,
        account_index: u32,
        asset_id: &str,
        to_address: &str,
        amount: u64,
        fee_mojos: u64,
    ) -> WalletResult<TxResult> {
        self.assert_unlocked(wallet_name)?;
        let wallet_file = self.storage.load_wallet(wallet_name)?;

        let account_sk = self.get_account_sk(wallet_name, account_index)?;
        let synthetic_pk = account_sk.public_key().derive_synthetic();
        let own_puzzle_hash = Bytes32::from(StandardArgs::curry_tree_hash(synthetic_pk));
        let asset_id_bytes = hex_to_bytes32(asset_id)?;

        let dest_puzzle_hash = derivation::decode_address(to_address)?;

        // Fetch CAT coins
        let cat_records = coins::get_all_unspent_cat(
            &self.client,
            &wallet_file.accounts,
            Some(account_index),
            asset_id,
        )
        .await?;

        let cat_sel =
            selection::select_with_strategy(&cat_records, amount, CoinSelectionStrategy::Knapsack)?;

        // Resolve CAT coins with lineage proofs
        let mut resolved_cats = Vec::new();
        for record in &cat_sel.coins {
            let protocol_coin = coin_record_to_protocol_coin(record)?;
            let cat = cat_tx::resolve_cat_coin(
                &self.client,
                &protocol_coin,
                &record.coin.parent_coin_info,
                record.confirmed_block_index,
                asset_id_bytes,
            )
            .await?;
            resolved_cats.push(cat);
        }

        // Fetch XCH coins for fee if needed
        let mut xch_fee_coins = Vec::new();
        if fee_mojos > 0 {
            let xch_records = coins::get_all_unspent_xch(
                &self.client,
                &wallet_file.accounts,
                Some(account_index),
            )
            .await?;
            let xch_sel = selection::select_with_strategy(
                &xch_records,
                fee_mojos,
                CoinSelectionStrategy::Knapsack,
            )?;
            xch_fee_coins = xch_sel
                .coins
                .iter()
                .map(coin_record_to_protocol_coin)
                .collect::<WalletResult<Vec<_>>>()?;
        }

        let coin_spends = cat_tx::build_cat_send(
            synthetic_pk,
            &resolved_cats,
            dest_puzzle_hash,
            amount,
            fee_mojos,
            own_puzzle_hash,
            &xch_fee_coins,
        )?;

        let agg_sig_data = transaction::get_agg_sig_data(self.network);
        let signature = transaction::sign_coin_spends(&coin_spends, &[account_sk], agg_sig_data)?;
        let bundle = transaction::assemble_spend_bundle(coin_spends, signature);

        self.broadcast_protocol_bundle(&bundle).await
    }

    /// Broadcast a pre-built SpendBundle to the network.
    pub async fn broadcast_spend_bundle(
        &self,
        spend_bundle: &chia::protocol::SpendBundle,
    ) -> WalletResult<TxResult> {
        self.broadcast_protocol_bundle(spend_bundle).await
    }

    /// Wait for a coin to be confirmed on chain.
    pub async fn wait_for_confirmation(
        &self,
        coin_id: &str,
        timeout: Duration,
    ) -> WalletResult<CoinRecord> {
        let record = self
            .client
            .wait_for_confirmation(coin_id, Duration::from_secs(5), timeout)
            .await?;
        Ok(record)
    }

    // ── Fee Estimation ────────────────────────────────────────────

    /// Get a fee estimate for a transaction.
    pub async fn estimate_fee(&self, spend_count: u64) -> WalletResult<FeeEstimate> {
        let estimate = self
            .client
            .get_fee_estimate(None, Some(&[60, 120, 300]), Some(spend_count))
            .await?;
        Ok(estimate)
    }

    // ── Coin Management ─────────────────────────────────────────

    /// List all unspent XCH coins.
    pub async fn get_unspent_coins(
        &self,
        wallet_name: &str,
        account_index: Option<u32>,
    ) -> WalletResult<Vec<CoinRecord>> {
        let wallet_file = self.storage.load_wallet(wallet_name)?;
        coins::get_all_unspent_xch(&self.client, &wallet_file.accounts, account_index).await
    }

    /// List all unspent CAT coins by asset ID.
    pub async fn get_unspent_cat_coins(
        &self,
        wallet_name: &str,
        account_index: Option<u32>,
        asset_id: &str,
    ) -> WalletResult<Vec<CoinRecord>> {
        let wallet_file = self.storage.load_wallet(wallet_name)?;
        coins::get_all_unspent_cat(&self.client, &wallet_file.accounts, account_index, asset_id)
            .await
    }

    /// Select coins to meet a target amount.
    pub async fn select_coins(
        &self,
        wallet_name: &str,
        account_index: Option<u32>,
        target_amount: u64,
        strategy: CoinSelectionStrategy,
    ) -> WalletResult<CoinSelection> {
        let records = self.get_unspent_coins(wallet_name, account_index).await?;
        selection::select_with_strategy(&records, target_amount, strategy)
    }

    /// Select CAT coins to meet a target amount.
    pub async fn select_cat_coins(
        &self,
        wallet_name: &str,
        account_index: Option<u32>,
        asset_id: &str,
        target_amount: u64,
        strategy: CoinSelectionStrategy,
    ) -> WalletResult<CoinSelection> {
        let records = self
            .get_unspent_cat_coins(wallet_name, account_index, asset_id)
            .await?;
        selection::select_with_strategy(&records, target_amount, strategy)
    }

    /// Combine multiple XCH coins into a single coin.
    pub async fn combine_coins(
        &self,
        wallet_name: &str,
        account_index: u32,
        coin_ids: Option<&[String]>,
        fee_mojos: u64,
    ) -> WalletResult<TxResult> {
        self.assert_unlocked(wallet_name)?;
        let wallet_file = self.storage.load_wallet(wallet_name)?;

        let account_sk = self.get_account_sk(wallet_name, account_index)?;
        let synthetic_pk = account_sk.public_key().derive_synthetic();
        let own_puzzle_hash = Bytes32::from(StandardArgs::curry_tree_hash(synthetic_pk));

        let all_records =
            coins::get_all_unspent_xch(&self.client, &wallet_file.accounts, Some(account_index))
                .await?;

        let records = match coin_ids {
            Some(ids) => filter_by_coin_ids(&all_records, ids)?,
            None => all_records,
        };

        let protocol_coins: Vec<chia::protocol::Coin> = records
            .iter()
            .map(coin_record_to_protocol_coin)
            .collect::<WalletResult<Vec<_>>>()?;

        let coin_spends = transaction::build_combine_tx(
            synthetic_pk,
            &protocol_coins,
            own_puzzle_hash,
            fee_mojos,
        )?;

        let agg_sig_data = transaction::get_agg_sig_data(self.network);
        let signature = transaction::sign_coin_spends(&coin_spends, &[account_sk], agg_sig_data)?;
        let bundle = transaction::assemble_spend_bundle(coin_spends, signature);

        self.broadcast_protocol_bundle(&bundle).await
    }

    /// Combine multiple CAT coins into a single CAT coin.
    pub async fn combine_cat_coins(
        &self,
        wallet_name: &str,
        account_index: u32,
        asset_id: &str,
        coin_ids: Option<&[String]>,
        fee_mojos: u64,
    ) -> WalletResult<TxResult> {
        self.assert_unlocked(wallet_name)?;
        let wallet_file = self.storage.load_wallet(wallet_name)?;

        let account_sk = self.get_account_sk(wallet_name, account_index)?;
        let synthetic_pk = account_sk.public_key().derive_synthetic();
        let own_puzzle_hash = Bytes32::from(StandardArgs::curry_tree_hash(synthetic_pk));
        let asset_id_bytes = hex_to_bytes32(asset_id)?;

        let all_records = coins::get_all_unspent_cat(
            &self.client,
            &wallet_file.accounts,
            Some(account_index),
            asset_id,
        )
        .await?;

        let records = match coin_ids {
            Some(ids) => filter_by_coin_ids(&all_records, ids)?,
            None => all_records,
        };

        let mut resolved_cats = Vec::new();
        for record in &records {
            let protocol_coin = coin_record_to_protocol_coin(record)?;
            let cat = cat_tx::resolve_cat_coin(
                &self.client,
                &protocol_coin,
                &record.coin.parent_coin_info,
                record.confirmed_block_index,
                asset_id_bytes,
            )
            .await?;
            resolved_cats.push(cat);
        }

        // XCH for fee
        let mut xch_fee_coins = Vec::new();
        if fee_mojos > 0 {
            let xch_records = coins::get_all_unspent_xch(
                &self.client,
                &wallet_file.accounts,
                Some(account_index),
            )
            .await?;
            let xch_sel = selection::select_with_strategy(
                &xch_records,
                fee_mojos,
                CoinSelectionStrategy::Knapsack,
            )?;
            xch_fee_coins = xch_sel
                .coins
                .iter()
                .map(coin_record_to_protocol_coin)
                .collect::<WalletResult<Vec<_>>>()?;
        }

        let coin_spends = cat_tx::build_cat_combine(
            synthetic_pk,
            &resolved_cats,
            own_puzzle_hash,
            fee_mojos,
            &xch_fee_coins,
        )?;

        let agg_sig_data = transaction::get_agg_sig_data(self.network);
        let signature = transaction::sign_coin_spends(&coin_spends, &[account_sk], agg_sig_data)?;
        let bundle = transaction::assemble_spend_bundle(coin_spends, signature);

        self.broadcast_protocol_bundle(&bundle).await
    }

    /// Split a single XCH coin into multiple equal pieces.
    pub async fn split_coins(
        &self,
        wallet_name: &str,
        account_index: u32,
        coin_id: &str,
        target_count: u32,
        fee_mojos: u64,
    ) -> WalletResult<TxResult> {
        self.assert_unlocked(wallet_name)?;

        let account_sk = self.get_account_sk(wallet_name, account_index)?;
        let synthetic_pk = account_sk.public_key().derive_synthetic();
        let own_puzzle_hash = Bytes32::from(StandardArgs::curry_tree_hash(synthetic_pk));

        let record = self.client.get_coin_record_by_name(coin_id).await?;
        let protocol_coin = coin_record_to_protocol_coin(&record)?;

        let coin_spends = transaction::build_split_tx(
            synthetic_pk,
            protocol_coin,
            target_count,
            own_puzzle_hash,
            fee_mojos,
        )?;

        let agg_sig_data = transaction::get_agg_sig_data(self.network);
        let signature = transaction::sign_coin_spends(&coin_spends, &[account_sk], agg_sig_data)?;
        let bundle = transaction::assemble_spend_bundle(coin_spends, signature);

        self.broadcast_protocol_bundle(&bundle).await
    }

    /// Split a single CAT coin into multiple pieces.
    pub async fn split_cat_coins(
        &self,
        wallet_name: &str,
        account_index: u32,
        asset_id: &str,
        coin_id: &str,
        target_count: u32,
        fee_mojos: u64,
    ) -> WalletResult<TxResult> {
        self.assert_unlocked(wallet_name)?;
        let wallet_file = self.storage.load_wallet(wallet_name)?;

        let account_sk = self.get_account_sk(wallet_name, account_index)?;
        let synthetic_pk = account_sk.public_key().derive_synthetic();
        let own_puzzle_hash = Bytes32::from(StandardArgs::curry_tree_hash(synthetic_pk));
        let asset_id_bytes = hex_to_bytes32(asset_id)?;

        let record = self.client.get_coin_record_by_name(coin_id).await?;
        let protocol_coin = coin_record_to_protocol_coin(&record)?;

        let resolved_cat = cat_tx::resolve_cat_coin(
            &self.client,
            &protocol_coin,
            &record.coin.parent_coin_info,
            record.confirmed_block_index,
            asset_id_bytes,
        )
        .await?;

        // XCH for fee
        let mut xch_fee_coins = Vec::new();
        if fee_mojos > 0 {
            let xch_records = coins::get_all_unspent_xch(
                &self.client,
                &wallet_file.accounts,
                Some(account_index),
            )
            .await?;
            let xch_sel = selection::select_with_strategy(
                &xch_records,
                fee_mojos,
                CoinSelectionStrategy::Knapsack,
            )?;
            xch_fee_coins = xch_sel
                .coins
                .iter()
                .map(coin_record_to_protocol_coin)
                .collect::<WalletResult<Vec<_>>>()?;
        }

        let coin_spends = cat_tx::build_cat_split(
            synthetic_pk,
            &resolved_cat,
            target_count,
            own_puzzle_hash,
            fee_mojos,
            &xch_fee_coins,
        )?;

        let agg_sig_data = transaction::get_agg_sig_data(self.network);
        let signature = transaction::sign_coin_spends(&coin_spends, &[account_sk], agg_sig_data)?;
        let bundle = transaction::assemble_spend_bundle(coin_spends, signature);

        self.broadcast_protocol_bundle(&bundle).await
    }

    // ── Internal Helpers ──────────────────────────────────────────

    /// Check that a wallet is unlocked. Returns an error if not.
    fn assert_unlocked(&self, name: &str) -> WalletResult<()> {
        let keystores = self.keystores.read().unwrap();
        if !keystores.contains_key(name) {
            return Err(WalletError::WalletLocked);
        }
        Ok(())
    }

    /// Get a cloned secret key for a wallet+index. The wallet must be unlocked.
    fn get_account_sk(&self, wallet_name: &str, index: u32) -> WalletResult<SecretKey> {
        let keystores = self.keystores.read().unwrap();
        let ks = keystores
            .get(wallet_name)
            .ok_or(WalletError::WalletLocked)?;
        ks.get_secret_key(index)
    }

    /// Get the master secret key for a wallet. The wallet must be unlocked.
    fn get_master_sk(&self, wallet_name: &str) -> WalletResult<SecretKey> {
        let keystores = self.keystores.read().unwrap();
        let ks = keystores
            .get(wallet_name)
            .ok_or(WalletError::WalletLocked)?;
        ks.master_key()
    }

    /// Add a derivation to an unlocked wallet's keystore.
    fn keystore_add_derivation(
        &self,
        wallet_name: &str,
        index: u32,
        prefix: &str,
    ) -> WalletResult<(SecretKey, Bytes32, String)> {
        let keystores = self.keystores.read().unwrap();
        let ks = keystores
            .get(wallet_name)
            .ok_or(WalletError::WalletLocked)?;
        ks.add_derivation(index, prefix)
    }

    /// Build a WalletFile from a master secret key.
    fn build_wallet_file(
        &self,
        name: &str,
        master_sk: &SecretKey,
        password: &str,
    ) -> WalletResult<WalletFile> {
        let sk_bytes = master_sk.to_bytes();
        let encrypted = crate::keystore::encryption::encrypt_secret_key(&sk_bytes, password)?;
        let encrypted_hex = format!("0x{}", hex::encode(&encrypted));

        let prefix = address_prefix(self.network);
        let (_, account_pk, synthetic_pk, puzzle_hash, address) =
            derivation::derive_account(master_sk, 0, prefix)?;

        let account = WalletAccount {
            name: "Default".to_string(),
            index: 0,
            puzzle_hash: bytes32_to_hex(&puzzle_hash),
            address,
            public_key: hex::encode(account_pk.to_bytes()),
            synthetic_public_key: hex::encode(synthetic_pk.to_bytes()),
            last_sync_height: 0,
        };

        let now = storage::now_secs();

        Ok(WalletFile {
            version: 1,
            name: name.to_string(),
            network: self.network,
            encrypted_master_key: encrypted_hex,
            accounts: vec![account],
            created_at: now,
            modified_at: now,
        })
    }

    /// Convert a protocol SpendBundle and broadcast via chia-query.
    async fn broadcast_protocol_bundle(
        &self,
        bundle: &chia::protocol::SpendBundle,
    ) -> WalletResult<TxResult> {
        let query_bundle = protocol_spend_bundle_to_query(bundle);
        let status = self.client.push_tx(&query_bundle).await?;

        // Use the aggregated signature as a stand-in tx identifier
        let tx_id = query_bundle.aggregated_signature.clone();

        Ok(TxResult {
            tx_id,
            status: status.status,
            success: status.success,
        })
    }
}

/// Filter coin records by a list of 0x-prefixed coin IDs.
fn filter_by_coin_ids(
    records: &[CoinRecord],
    coin_ids: &[String],
) -> WalletResult<Vec<CoinRecord>> {
    let mut result = Vec::new();
    for id in coin_ids {
        let id_bytes = hex_to_bytes32(id)?;
        let found = records.iter().find(|r| {
            coin_record_to_protocol_coin(r)
                .map(|c| c.coin_id() == id_bytes)
                .unwrap_or(false)
        });
        match found {
            Some(r) => result.push(r.clone()),
            None => {
                return Err(WalletError::InvalidCoin(format!("Coin not found: {}", id)));
            }
        }
    }
    Ok(result)
}
