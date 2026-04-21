//! Encrypted storage for 32-byte BLS master seeds.
//!
//! This module is a thin adapter over the shared
//! [`dig-keystore`](https://crates.io/crates/dig-keystore) crate. It exposes
//! the same public surface that previous `dig-l1-wallet` versions used
//! (`encrypt_secret_key` / `decrypt_secret_key`), but every cryptographic
//! operation — Argon2id KDF, AES-256-GCM encryption, file-format encoding —
//! now lives in `dig-keystore`. The benefit:
//!
//! - Single audit surface for key-encryption primitives across the DIG
//!   workspace.
//! - Shared file format (`DIGLW1`) with future `apps/wallet` consumers.
//! - `dig-l1-wallet` no longer depends on `aes-gcm` or `argon2` directly.
//!
//! # Wire format (v2 of `dig-l1-wallet`)
//!
//! Since v0.2.0 the encrypted blob uses the `DIGLW1` keystore format from
//! `dig-keystore` — a 53-byte header + AES-256-GCM ciphertext (48 bytes for
//! a 32-byte seed) + 4-byte CRC32. Total 105 bytes. See
//! `dig-keystore/docs/resources/SPEC.md` for the byte-level specification.
//!
//! **Breaking change from v0.1.x**: encrypted blobs produced by older
//! versions (raw `salt || nonce || ciphertext`, no magic bytes or version
//! tag) cannot be decrypted by v0.2.0+. Operators on v0.1.x wallets must
//! re-encrypt their keys under the new format. For an alpha-stage crate,
//! this is acceptable; for a stable crate a migration path would be
//! provided.
//!
//! # Security parameters
//!
//! Inherited verbatim from `dig-keystore::KdfParams::DEFAULT`:
//!
//! | Parameter | Value |
//! |---|---|
//! | KDF | Argon2id (RFC 9106) |
//! | Memory | 64 MiB |
//! | Iterations | 3 |
//! | Lanes | 4 |
//! | Cipher | AES-256-GCM (RFC 5116) |
//! | Salt | 16 bytes random per encryption |
//! | Nonce | 12 bytes random per encryption |

use std::sync::Arc;

use dig_keystore::{
    backend::{BackendKey, KeychainBackend, MemoryBackend},
    scheme::L1WalletBls,
    KdfParams, Keystore, KeystoreError, Password,
};
use zeroize::Zeroizing;

use crate::types::{WalletError, WalletResult};

/// Fixed `BackendKey` used for the in-memory scratch backend that wraps a
/// single secret key. The specific value doesn't matter — it never touches
/// disk — but it's a constant so the encrypt/decrypt paths agree.
const SCRATCH_KEY: &str = "wallet";

/// Encrypt a 32-byte BLS secret key under `password`, producing a
/// `DIGLW1` keystore blob.
///
/// # Parameters
/// - `secret_key`: the 32-byte BLS master seed (typically derived from a BIP-39 mnemonic).
/// - `password`: user password. Any byte length accepted; short passwords
///   are the operator's problem.
///
/// # Returns
/// The full keystore file as a `Vec<u8>` — header + encrypted seed + CRC.
/// Approximately 105 bytes.
///
/// # Errors
/// - [`WalletError::Encryption`] if the underlying `dig-keystore` layer fails
///   (typically an I/O error from the in-memory scratch backend, which is
///   effectively unreachable — or an `InvalidKdfParams` if the defaults are
///   somehow rejected, which is also unreachable).
pub fn encrypt_secret_key(secret_key: &[u8; 32], password: &str) -> WalletResult<Vec<u8>> {
    let backend = Arc::new(MemoryBackend::new());
    let trait_backend: Arc<dyn KeychainBackend> = backend.clone();
    let path = BackendKey::new(SCRATCH_KEY);

    Keystore::<L1WalletBls>::create(
        trait_backend,
        path.clone(),
        Password::from(password),
        Some(Zeroizing::new(secret_key.to_vec())),
        KdfParams::default(),
    )
    .map_err(|e| WalletError::Encryption(format!("dig-keystore create: {}", e)))?;

    backend
        .read(&path)
        .map_err(|e| WalletError::Encryption(format!("dig-keystore read: {}", e)))
}

/// Decrypt a `DIGLW1` keystore blob to a 32-byte BLS secret key.
///
/// # Parameters
/// - `encrypted`: the full keystore blob previously produced by
///   [`encrypt_secret_key`] (or any `DIGLW1`-format file — e.g.,
///   `dig-keystore::Keystore<L1WalletBls>` with the same scheme).
/// - `password`: the password used at encrypt time.
///
/// # Returns
/// The 32-byte secret key.
///
/// # Errors
/// - [`WalletError::InvalidPassword`] if the password is wrong (maps from
///   `KeystoreError::DecryptFailed`, which covers wrong password, tampered
///   ciphertext, or tampered header).
/// - [`WalletError::Decryption`] for any other failure: truncated / garbage
///   input, unknown magic (not a DIG keystore), wrong scheme id, CRC
///   mismatch, unsupported format.
pub fn decrypt_secret_key(encrypted: &[u8], password: &str) -> WalletResult<[u8; 32]> {
    let backend = Arc::new(MemoryBackend::new());
    let trait_backend: Arc<dyn KeychainBackend> = backend.clone();
    let path = BackendKey::new(SCRATCH_KEY);

    // Stash the bytes into the scratch backend so Keystore::load can read them.
    backend
        .write(&path, encrypted)
        .map_err(|e| WalletError::Decryption(format!("dig-keystore write: {}", e)))?;

    let ks = Keystore::<L1WalletBls>::load(trait_backend, path).map_err(map_keystore_error)?;
    let signer = ks
        .unlock(Password::from(password))
        .map_err(map_keystore_error)?;

    // SignerHandle::expose_secret returns a borrow of the Zeroizing buffer
    // inside the handle. Copy into a fixed-size array before the handle drops.
    let bytes = signer.expose_secret();
    if bytes.len() != 32 {
        return Err(WalletError::Decryption(format!(
            "unexpected secret length: expected 32, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Map the richer `dig-keystore` error enum down to `WalletError` so the
/// wallet's existing error surface doesn't balloon.
///
/// - `DecryptFailed` → [`WalletError::InvalidPassword`] (most likely cause
///   from a user perspective; the other triggers — tampered ciphertext /
///   header — are file-level corruption and surface the same way).
/// - Everything else → [`WalletError::Decryption`] with the display string.
fn map_keystore_error(e: KeystoreError) -> WalletError {
    match e {
        KeystoreError::DecryptFailed => WalletError::InvalidPassword,
        KeystoreError::Truncated { .. } => {
            WalletError::Decryption("encrypted data too short".into())
        }
        other => WalletError::Decryption(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Proves:** `encrypt_secret_key` → `decrypt_secret_key` recovers the
    /// original 32-byte seed bit-exactly.
    ///
    /// **Why it matters:** This is the one load-bearing property of this
    /// module. If the round-trip ever produces a mangled seed, the wallet
    /// derives a completely different set of addresses than it encrypted.
    ///
    /// **Catches:** any regression in the dig-keystore adapter — wrong
    /// scheme id passed to `Keystore::create`, accidental hashing of the
    /// seed before encryption, length drift between the stored plaintext
    /// and the recovered bytes.
    #[test]
    fn test_secret_key_roundtrip() {
        let secret_key = [42u8; 32];
        let password = "strong_password";

        let encrypted = encrypt_secret_key(&secret_key, password).unwrap();
        let decrypted = decrypt_secret_key(&encrypted, password).unwrap();

        assert_eq!(decrypted, secret_key);
    }

    /// **Proves:** decryption with the wrong password returns
    /// [`WalletError::InvalidPassword`] — not a generic `Decryption` error
    /// and not garbage plaintext.
    ///
    /// **Why it matters:** Operators routinely mistype passwords. CLI
    /// tools route `InvalidPassword` into "wrong password, please retry"
    /// UX; any other error variant triggers operator alerts for possible
    /// corruption.
    ///
    /// **Catches:** a regression where the `map_keystore_error` match arm
    /// accidentally routes `DecryptFailed` into the catch-all `Decryption`
    /// variant.
    #[test]
    fn test_wrong_password_fails() {
        let secret_key = [42u8; 32];
        let encrypted = encrypt_secret_key(&secret_key, "correct_password").unwrap();
        let result = decrypt_secret_key(&encrypted, "wrong_password");
        assert!(
            matches!(result, Err(WalletError::InvalidPassword)),
            "expected InvalidPassword, got {:?}",
            result
        );
    }

    /// **Proves:** decryption of a buffer too short to be a valid keystore
    /// returns [`WalletError::Decryption`] without panicking.
    ///
    /// **Why it matters:** Corrupt / truncated input should fail gracefully.
    /// A panic here would crash any binary that calls `decrypt_secret_key`
    /// on operator-supplied data.
    ///
    /// **Catches:** unchecked slice indexing in the dig-keystore adapter
    /// (unreachable given dig-keystore's internal guards, but pinned here
    /// for defence-in-depth).
    #[test]
    fn test_encrypted_data_too_short() {
        let result = decrypt_secret_key(&[0u8; 10], "password");
        assert!(
            matches!(result, Err(WalletError::Decryption(_))),
            "expected Decryption error, got {:?}",
            result
        );
    }

    /// **Proves:** two encryptions of the same seed under the same password
    /// produce different ciphertexts, because the salt and nonce are freshly
    /// randomised per call.
    ///
    /// **Why it matters:** Deterministic ciphertext would let a passive
    /// observer detect "same wallet" across backups, or worse, allow
    /// dictionary-style analyses across files. Random salt + nonce per
    /// encryption is a load-bearing cryptographic requirement.
    ///
    /// **Catches:** an adapter bug where the backend key is incorrectly
    /// keyed on the secret bytes (leading to same salt) or the RNG is
    /// accidentally seeded deterministically.
    #[test]
    fn test_different_encryptions_produce_different_ciphertext() {
        let secret_key = [42u8; 32];
        let password = "same_password";
        let enc1 = encrypt_secret_key(&secret_key, password).unwrap();
        let enc2 = encrypt_secret_key(&secret_key, password).unwrap();
        assert_ne!(enc1, enc2);
    }

    /// **Proves:** the produced blob starts with the `DIGLW1` magic — i.e.,
    /// we really are producing the `dig-keystore` wire format, not the
    /// legacy raw format.
    ///
    /// **Why it matters:** External tools (`dig-keystore` CLI, future
    /// `apps/wallet`) identify keystore files by their magic prefix. If
    /// this adapter accidentally produced a non-magic blob, cross-tool
    /// interop would break silently.
    ///
    /// **Catches:** a regression to a local-only format; choosing the
    /// wrong `KeyScheme` (e.g., `BlsSigning`/`DIGVK1` instead of
    /// `L1WalletBls`/`DIGLW1`).
    #[test]
    fn test_blob_uses_diglw1_magic() {
        let secret_key = [42u8; 32];
        let encrypted = encrypt_secret_key(&secret_key, "pw").unwrap();
        assert!(encrypted.len() >= 6, "blob shorter than magic prefix");
        assert_eq!(&encrypted[..6], b"DIGLW1");
    }
}
