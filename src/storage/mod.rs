//! Wallet file storage — read/write `.wallet` JSON files to disk.
//!
//! [`WalletStorage`] manages the wallet directory and provides CRUD
//! operations for wallet files. Each wallet is a single JSON file
//! named `{wallet_dir}/{name}.wallet`.
//!
//! ## Reference
//!
//! Adapted from `l2_driver_state_channel/src/services/wallet/storage.rs`.
//! See SPEC.md §12 "Wallet Management".

pub mod format;

use std::fs;
use std::path::PathBuf;

use crate::storage::format::WalletFile;
use crate::types::{WalletError, WalletResult};

/// Manages wallet files on disk.
pub struct WalletStorage {
    wallet_dir: PathBuf,
}

impl WalletStorage {
    /// Create a new WalletStorage for the given directory.
    pub fn new(wallet_dir: PathBuf) -> Self {
        Self { wallet_dir }
    }

    /// Ensure the wallet directory exists.
    pub fn ensure_dir(&self) -> WalletResult<()> {
        fs::create_dir_all(&self.wallet_dir)?;
        Ok(())
    }

    /// Get the file path for a named wallet.
    pub fn wallet_path(&self, name: &str) -> PathBuf {
        self.wallet_dir.join(format!("{}.wallet", name))
    }

    /// Check if a wallet file exists.
    pub fn wallet_exists(&self, name: &str) -> bool {
        self.wallet_path(name).exists()
    }

    /// Save a wallet file to disk.
    pub fn save_wallet(&self, wallet: &WalletFile) -> WalletResult<()> {
        self.ensure_dir()?;
        let path = self.wallet_path(&wallet.name);
        let data = serde_json::to_vec_pretty(wallet)?;
        fs::write(&path, data)?;
        Ok(())
    }

    /// Load a wallet file from disk.
    pub fn load_wallet(&self, name: &str) -> WalletResult<WalletFile> {
        let path = self.wallet_path(name);
        if !path.exists() {
            return Err(WalletError::WalletNotFound(name.to_string()));
        }
        let data = fs::read(&path)?;
        let wallet: WalletFile = serde_json::from_slice(&data)?;
        Ok(wallet)
    }

    /// Delete a wallet file from disk.
    pub fn delete_wallet(&self, name: &str) -> WalletResult<()> {
        let path = self.wallet_path(name);
        if !path.exists() {
            return Err(WalletError::WalletNotFound(name.to_string()));
        }
        fs::remove_file(&path)?;
        Ok(())
    }

    /// Rename a wallet (renames file and updates name field inside).
    pub fn rename_wallet(&self, old_name: &str, new_name: &str) -> WalletResult<()> {
        if self.wallet_exists(new_name) {
            return Err(WalletError::WalletAlreadyExists(new_name.to_string()));
        }

        let mut wallet = self.load_wallet(old_name)?;
        wallet.name = new_name.to_string();
        wallet.modified_at = now_secs();

        self.save_wallet(&wallet)?;
        // Remove old file (only after new file is written successfully)
        let old_path = self.wallet_path(old_name);
        fs::remove_file(&old_path)?;

        Ok(())
    }

    /// List all wallet names in the directory.
    pub fn list_wallets(&self) -> WalletResult<Vec<String>> {
        if !self.wallet_dir.exists() {
            return Ok(Vec::new());
        }

        let mut names = Vec::new();
        for entry in fs::read_dir(&self.wallet_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("wallet") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    names.push(stem.to_string());
                }
            }
        }
        names.sort();
        Ok(names)
    }
}

/// Get the current time as Unix epoch seconds.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
