//! Error types for the dig-l1-wallet crate.
//!
//! [`WalletError`] is the single error enum used throughout the crate.
//! It wraps errors from the chia ecosystem crates via `#[from]` where possible.
//!
//! ## Design Decision
//!
//! We use a flat enum rather than nested error types because:
//! 1. The wallet orchestrator (`L1Wallet`) calls across all subsystems in a single flow.
//! 2. Consumers only need to match on one error type.
//! 3. `thiserror` v2 provides ergonomic `#[from]` derivation.
//!
//! SDK error types that don't implement `Display` uniformly (like `DriverError`)
//! use a manual `From` impl that formats via `Debug`.

use chia_query::ChiaQueryError;
use chia_wallet_sdk::signer::SignerError;
use chia_wallet_sdk::utils::CoinSelectionError;

/// Convenience alias used throughout the crate.
pub type WalletResult<T> = Result<T, WalletError>;

/// All errors that can occur during wallet operations.
///
/// # Usage
/// ```rust,no_run
/// use dig_l1_wallet::{WalletError, WalletResult};
///
/// fn example() -> WalletResult<()> {
///     Err(WalletError::WalletLocked)
/// }
/// ```
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    /// The named wallet file was not found in the wallet directory.
    #[error("Wallet not found: {0}")]
    WalletNotFound(String),

    /// Attempted to create a wallet with a name that already exists.
    #[error("Wallet already exists: {0}")]
    WalletAlreadyExists(String),

    /// No account exists at the requested derivation index.
    /// Create one first via `L1Wallet::create_account`.
    #[error("Account not found: index {0}")]
    AccountNotFound(u32),

    /// The password provided to `unlock()` did not decrypt the master key.
    /// AES-256-GCM authentication tag verification failed.
    #[error("Invalid password")]
    InvalidPassword,

    /// Operation requires an unlocked wallet but the wallet is locked.
    /// Call `L1Wallet::unlock(name, password)` first.
    #[error("Wallet is locked — call unlock() first")]
    WalletLocked,

    /// The BIP39 mnemonic phrase is invalid (bad checksum, wrong word count, etc.).
    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    /// The raw secret key bytes are not a valid BLS12-381 scalar.
    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(String),

    /// The bech32m address could not be decoded, or the puzzle hash is malformed.
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    /// A coin ID or coin record is malformed or not found on chain.
    #[error("Invalid coin: {0}")]
    InvalidCoin(String),

    /// Not enough funds to cover the requested amount + fee.
    #[error("Insufficient funds: available {available}, required {required}")]
    InsufficientFunds { available: u64, required: u64 },

    /// The full node rejected the spend bundle broadcast.
    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    /// AES-256-GCM encryption of key material failed.
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// AES-256-GCM decryption of key material failed (not password-related).
    #[error("Decryption error: {0}")]
    Decryption(String),

    /// Argon2id key derivation from password failed.
    #[error("Key derivation error: {0}")]
    KeyDerivation(String),

    /// SpendContext or StandardLayer failed to construct a coin spend.
    /// Wraps errors from `chia_wallet_sdk::driver`.
    #[error("Spend construction error: {0}")]
    SpendConstruction(String),

    /// BLS signature extraction or aggregation failed.
    /// Wraps `chia_wallet_sdk::signer::SignerError`.
    #[error("Signing error: {0}")]
    Signing(#[from] SignerError),

    /// The knapsack coin selection algorithm (from `chia_wallet_sdk::utils`)
    /// could not find a valid coin set for the target amount.
    #[error("Coin selection error: {0}")]
    CoinSelection(#[from] CoinSelectionError),

    /// A `chia_wallet_sdk::driver::DriverError` occurred during puzzle
    /// construction (CAT layer, standard layer, etc.).
    #[error("Driver error: {0}")]
    Driver(String),

    /// An error from `chia-query` during blockchain interaction
    /// (peer failure, coinset API error, etc.).
    #[error("Blockchain query error: {0}")]
    Query(#[from] ChiaQueryError),

    /// Filesystem I/O error when reading/writing wallet files.
    #[error("Storage I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization/deserialization error for wallet files.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Manual `From` impl because `DriverError` uses `Debug` formatting
/// rather than implementing `Display` uniformly.
/// See: `chia_wallet_sdk::driver::DriverError`
impl From<chia_wallet_sdk::driver::DriverError> for WalletError {
    fn from(e: chia_wallet_sdk::driver::DriverError) -> Self {
        WalletError::Driver(format!("{:?}", e))
    }
}
