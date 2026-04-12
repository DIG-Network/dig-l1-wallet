//! BIP39 mnemonic generation, validation, and master key derivation.
//!
//! Implements the Chia standard for mnemonic-to-key derivation:
//! 1. Generate 256 bits of entropy → 24-word BIP39 mnemonic
//! 2. Mnemonic → seed (with empty passphrase, per Chia convention)
//! 3. Seed → BLS12-381 master secret key via `SecretKey::from_seed`
//!
//! ## Reference
//!
//! Adapted from `l2_driver_state_channel/src/services/wallet/keys.rs`
//! (`KeyDerivation::generate_mnemonic`, `derive_master_key_from_mnemonic`).
//! See SPEC.md §7 "Key Generation and Import".
//!
//! ## Chia Convention
//!
//! Chia uses an **empty passphrase** for mnemonic-to-seed derivation
//! (unlike Bitcoin which supports an optional passphrase). This is hardcoded
//! as `mnemonic.to_seed("")`.

use bip39::{Language, Mnemonic};
use chia::bls::SecretKey;
use rand::RngCore;

use crate::types::{WalletError, WalletResult};

/// Generate a 24-word BIP39 mnemonic from cryptographically secure random entropy.
///
/// Uses 256 bits (32 bytes) of entropy, producing a 24-word English mnemonic.
/// This is the same entropy size used by the official Chia wallet.
///
/// # Returns
/// A space-separated string of 24 BIP39 English words.
///
/// # Example
/// ```rust
/// use dig_l1_wallet::keystore::mnemonic;
///
/// let mnemonic = mnemonic::generate_mnemonic().unwrap();
/// assert_eq!(mnemonic.split_whitespace().count(), 24);
/// ```
pub fn generate_mnemonic() -> WalletResult<String> {
    let mut entropy = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut entropy);

    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
        .map_err(|e| WalletError::InvalidMnemonic(format!("Failed to generate mnemonic: {}", e)))?;

    Ok(mnemonic.to_string())
}

/// Validate a BIP39 mnemonic phrase (word list membership + checksum).
///
/// Accepts 12, 15, 18, 21, or 24 word mnemonics, but Chia standard is 24 words.
///
/// # Errors
/// Returns [`WalletError::InvalidMnemonic`] if any word is not in the BIP39
/// English word list, or if the checksum bits don't match.
pub fn validate_mnemonic(mnemonic: &str) -> WalletResult<()> {
    Mnemonic::parse_in_normalized(Language::English, mnemonic)
        .map_err(|e| WalletError::InvalidMnemonic(format!("Invalid mnemonic: {}", e)))?;
    Ok(())
}

/// Derive a BLS12-381 master secret key from a BIP39 mnemonic phrase.
///
/// ## Derivation Steps
/// 1. Parse and validate the mnemonic phrase
/// 2. Derive a 64-byte seed using PBKDF2-HMAC-SHA512 with empty passphrase
///    (`mnemonic.to_seed("")`) — this is the Chia convention
/// 3. Derive the BLS master secret key from the 64-byte seed via
///    `chia::bls::SecretKey::from_seed`
///
/// ## Determinism
/// The same mnemonic always produces the same master key — this is how
/// wallet recovery works: back up the 24 words, re-derive the master key.
///
/// ## Reference
/// - BIP39: <https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki>
/// - Chia key derivation: <https://docs.chia.net/key-architecture/>
pub fn derive_master_key_from_mnemonic(mnemonic: &str) -> WalletResult<SecretKey> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic)
        .map_err(|e| WalletError::InvalidMnemonic(format!("Invalid mnemonic: {}", e)))?;

    // Chia uses empty passphrase — this is NOT configurable
    let seed = mnemonic.to_seed("");
    Ok(SecretKey::from_seed(&seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mnemonic_generation_produces_24_words() {
        let mnemonic = generate_mnemonic().unwrap();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 24, "Chia standard is 24-word mnemonic");
    }

    #[test]
    fn test_generated_mnemonic_is_valid() {
        let mnemonic = generate_mnemonic().unwrap();
        validate_mnemonic(&mnemonic).unwrap();
    }

    #[test]
    fn test_invalid_mnemonic_rejected() {
        let result = validate_mnemonic("not a valid mnemonic phrase at all");
        assert!(result.is_err());
    }

    #[test]
    fn test_deterministic_key_derivation() {
        let mnemonic = generate_mnemonic().unwrap();
        let sk1 = derive_master_key_from_mnemonic(&mnemonic).unwrap();
        let sk2 = derive_master_key_from_mnemonic(&mnemonic).unwrap();
        assert_eq!(
            sk1.to_bytes(),
            sk2.to_bytes(),
            "Same mnemonic must produce same key"
        );
    }
}
