//! AES-256-GCM encryption with Argon2id key derivation for wallet secrets.
//!
//! ## Wire Format
//!
//! Encrypted data is laid out as:
//! ```text
//! salt (16 bytes) || nonce (12 bytes) || ciphertext + auth_tag
//! ```
//!
//! ## Security Parameters (matching l2_driver_state_channel)
//!
//! - **Algorithm**: Argon2id (hybrid — resistant to both side-channel and GPU attacks)
//! - **Memory**: 64 MB (`ARGON2_MEMORY_COST = 65536` KiB)
//! - **Iterations**: 3 (`ARGON2_TIME_COST`)
//! - **Parallelism**: 4 lanes (`ARGON2_PARALLELISM`)
//! - **Salt**: 16 bytes (128-bit), randomly generated per encryption
//! - **Nonce**: 12 bytes (96-bit), randomly generated per encryption
//! - **Cipher**: AES-256-GCM (authenticated encryption with associated data)
//!
//! ## Reference
//!
//! Adapted from `l2_driver_state_channel/src/services/wallet/encryption.rs`.
//! See SPEC.md §6 "Encryption" for the full specification.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;

use crate::types::{WalletError, WalletResult};

/// Salt size for Argon2 key derivation (16 bytes = 128 bits).
/// Stored as the first 16 bytes of the encrypted blob.
const SALT_SIZE: usize = 16;

/// Nonce size for AES-256-GCM (12 bytes = 96 bits).
/// Stored immediately after the salt in the encrypted blob.
const NONCE_SIZE: usize = 12;

/// Argon2 memory cost in KiB. 65536 KiB = 64 MB.
/// Tuned to resist brute-force on consumer hardware while remaining
/// usable on modest systems. Matches l2_driver_state_channel.
const ARGON2_MEMORY_COST: u32 = 65536;

/// Argon2 time cost (number of iterations). Higher = slower per attempt.
const ARGON2_TIME_COST: u32 = 3;

/// Argon2 parallelism (number of lanes). Matches l2_driver_state_channel.
const ARGON2_PARALLELISM: u32 = 4;

/// Minimum valid encrypted data length: salt + nonce + GCM auth tag (16 bytes).
const MIN_ENCRYPTED_LEN: usize = SALT_SIZE + NONCE_SIZE + 16;

/// Derive a 256-bit encryption key from a password using Argon2id.
///
/// Uses Argon2id (the recommended variant) which combines the
/// side-channel resistance of Argon2i with the GPU-resistance of Argon2d.
///
/// # Parameters
/// - `password`: User-provided password string
/// - `salt`: Random salt (must be stored alongside the ciphertext)
///
/// # Returns
/// A 32-byte derived key suitable for AES-256-GCM.
pub fn derive_key_from_password(password: &str, salt: &[u8]) -> WalletResult<[u8; 32]> {
    let params = Params::new(
        ARGON2_MEMORY_COST,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(32), // 256-bit output
    )
    .map_err(|e| WalletError::KeyDerivation(format!("Invalid Argon2 params: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|e| WalletError::KeyDerivation(format!("Key derivation failed: {}", e)))?;

    Ok(output)
}

/// Encrypt arbitrary plaintext using AES-256-GCM with Argon2id key derivation.
///
/// # Wire format
/// Returns `salt (16 bytes) || nonce (12 bytes) || ciphertext_with_tag`.
///
/// # Usage
/// ```rust
/// use dig_l1_wallet::keystore::encryption;
///
/// let encrypted = encryption::encrypt(b"secret data", "my_password").unwrap();
/// let decrypted = encryption::decrypt(&encrypted, "my_password").unwrap();
/// assert_eq!(decrypted, b"secret data");
/// ```
pub fn encrypt(plaintext: &[u8], password: &str) -> WalletResult<Vec<u8>> {
    // Step 1: Generate random salt for Argon2id key derivation
    let mut salt = [0u8; SALT_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);

    // Step 2: Derive 256-bit encryption key from password
    let derived_key = derive_key_from_password(password, &salt)?;

    // Step 3: Generate random nonce for AES-256-GCM
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Step 4: Encrypt with AES-256-GCM (includes authentication tag)
    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|e| WalletError::Encryption(format!("Failed to create cipher: {}", e)))?;

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| WalletError::Encryption(format!("Encryption failed: {}", e)))?;

    // Step 5: Concatenate: salt || nonce || ciphertext_with_tag
    let mut result = Vec::with_capacity(SALT_SIZE + NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt data encrypted by [`encrypt`].
///
/// # Expected format
/// Input must be `salt (16 bytes) || nonce (12 bytes) || ciphertext_with_tag`.
///
/// # Errors
/// - [`WalletError::InvalidPassword`] if the password is wrong
///   (GCM authentication tag verification fails).
/// - [`WalletError::Decryption`] if the data is too short or malformed.
pub fn decrypt(encrypted: &[u8], password: &str) -> WalletResult<Vec<u8>> {
    if encrypted.len() < MIN_ENCRYPTED_LEN {
        return Err(WalletError::Decryption("Encrypted data too short".into()));
    }

    // Parse the wire format: salt || nonce || ciphertext
    let salt = &encrypted[..SALT_SIZE];
    let nonce_bytes = &encrypted[SALT_SIZE..SALT_SIZE + NONCE_SIZE];
    let ciphertext = &encrypted[SALT_SIZE + NONCE_SIZE..];

    // Re-derive the encryption key from the password + stored salt
    let derived_key = derive_key_from_password(password, salt)?;

    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|e| WalletError::Decryption(format!("Failed to create cipher: {}", e)))?;

    #[allow(deprecated)]
    let nonce = Nonce::from_slice(nonce_bytes);

    // GCM decryption: fails with InvalidPassword if the auth tag doesn't match
    // (i.e., wrong password produces wrong derived key → wrong tag)
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| WalletError::InvalidPassword)?;

    Ok(plaintext)
}

/// Encrypt a 32-byte BLS secret key.
///
/// Convenience wrapper around [`encrypt`] for the common case of
/// encrypting a `chia::bls::SecretKey::to_bytes()` result.
pub fn encrypt_secret_key(secret_key: &[u8; 32], password: &str) -> WalletResult<Vec<u8>> {
    encrypt(secret_key, password)
}

/// Decrypt a 32-byte BLS secret key.
///
/// Validates that the decrypted data is exactly 32 bytes.
///
/// # Errors
/// - [`WalletError::InvalidPassword`] if the password is wrong.
/// - [`WalletError::Decryption`] if decrypted length ≠ 32.
pub fn decrypt_secret_key(encrypted: &[u8], password: &str) -> WalletResult<[u8; 32]> {
    let decrypted = decrypt(encrypted, password)?;

    if decrypted.len() != 32 {
        return Err(WalletError::Decryption(format!(
            "Decrypted key has wrong length: expected 32, got {}",
            decrypted.len()
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&decrypted);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"Hello, World!";
        let password = "test_password_123";

        let encrypted = encrypt(plaintext, password).unwrap();
        let decrypted = decrypt(&encrypted, password).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_secret_key_roundtrip() {
        let secret_key = [42u8; 32];
        let password = "strong_password";

        let encrypted = encrypt_secret_key(&secret_key, password).unwrap();
        let decrypted = decrypt_secret_key(&encrypted, password).unwrap();

        assert_eq!(decrypted, secret_key);
    }

    #[test]
    fn test_wrong_password_fails() {
        let plaintext = b"Secret data";
        let encrypted = encrypt(plaintext, "correct_password").unwrap();
        let result = decrypt(&encrypted, "wrong_password");
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_data_too_short() {
        let result = decrypt(&[0u8; 10], "password");
        assert!(matches!(result, Err(WalletError::Decryption(_))));
    }

    #[test]
    fn test_different_encryptions_produce_different_ciphertext() {
        // Random salt and nonce should produce different output each time
        let plaintext = b"same input";
        let password = "same_password";
        let enc1 = encrypt(plaintext, password).unwrap();
        let enc2 = encrypt(plaintext, password).unwrap();
        assert_ne!(enc1, enc2); // Different salt/nonce → different ciphertext
    }
}
