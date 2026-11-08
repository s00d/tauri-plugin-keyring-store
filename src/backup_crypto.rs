//! Encrypted backup envelope (Argon2id + ChaCha20-Poly1305), always available.
//! (The `crypto` Cargo feature only toggles SLIP10/BIP39/Ed25519 procedures, not this module.)

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::models::PasswordBackupEncryptedDto;

const BACKUP_CRYPTO_FORMAT: u32 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// Argon2id parameters (memory KiB, iterations, lanes, output length).
fn argon_params() -> Params {
    Params::new(19456, 3, 1, Some(KEY_LEN)).expect("valid argon params")
}

fn cipher(passphrase: &[u8], salt: &[u8]) -> Result<ChaCha20Poly1305> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params())
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|e| Error::Crypto(format!("argon2: {e}")))?;
    ChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| Error::Crypto("bad key".into()))
}

/// Encrypt UTF-8 plaintext bytes (typically JSON of [`crate::models::PasswordBackupPlainDto`]).
pub fn encrypt_plain_bytes(plain: &[u8], passphrase: &[u8]) -> Result<PasswordBackupEncryptedDto> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|e| Error::Crypto(format!("rng salt: {e}")))?;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|e| Error::Crypto(format!("rng nonce: {e}")))?;

    let ciphertext = cipher(passphrase, &salt)?
        .encrypt(&Nonce::from(nonce), plain)
        .map_err(|_| Error::Crypto("chacha encrypt failed".into()))?;

    let engine = base64::engine::general_purpose::STANDARD;
    Ok(PasswordBackupEncryptedDto {
        format_version: BACKUP_CRYPTO_FORMAT,
        salt: engine.encode(salt),
        nonce: engine.encode(nonce),
        ciphertext: engine.encode(ciphertext),
    })
}

/// Decrypt envelope back to plaintext bytes (wiped on drop).
pub fn decrypt_to_plain(
    dto: &PasswordBackupEncryptedDto,
    passphrase: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if dto.format_version != BACKUP_CRYPTO_FORMAT {
        return Err(Error::Crypto(format!(
            "unsupported backup crypto format {}",
            dto.format_version
        )));
    }

    let engine = base64::engine::general_purpose::STANDARD;
    let decode = |what: &str, v: &str| {
        engine
            .decode(v.trim())
            .map_err(|e| Error::Crypto(format!("{what} base64: {e}")))
    };
    let salt = decode("salt", &dto.salt)?;
    let nonce: [u8; NONCE_LEN] = decode("nonce", &dto.nonce)?
        .try_into()
        .map_err(|_| Error::Crypto("invalid salt or nonce length".into()))?;
    let ciphertext = decode("ciphertext", &dto.ciphertext)?;
    if salt.len() != SALT_LEN {
        return Err(Error::Crypto("invalid salt or nonce length".into()));
    }

    cipher(passphrase, &salt)?
        .decrypt(&Nonce::from(nonce), ciphertext.as_ref())
        .map(Zeroizing::new)
        .map_err(|_| {
            Error::Crypto("chacha decrypt failed (wrong passphrase or corrupt data)".into())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plain = br#"{"formatVersion":1,"entries":[]}"#;
        let enc = encrypt_plain_bytes(plain, b"test-passphrase").unwrap();
        let back = decrypt_to_plain(&enc, b"test-passphrase").unwrap();
        assert_eq!(back.as_slice(), plain);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let plain = b"secret data";
        let enc = encrypt_plain_bytes(plain, b"a").unwrap();
        assert!(decrypt_to_plain(&enc, b"b").is_err());
    }

    /// Envelopes written by 0.1.x (chacha20poly1305 0.10 / argon2 0.5) must still decrypt.
    #[test]
    fn decrypts_envelope_from_previous_release() {
        let dto = PasswordBackupEncryptedDto {
            format_version: 1,
            salt: OLD_SALT.into(),
            nonce: OLD_NONCE.into(),
            ciphertext: OLD_CT.into(),
        };
        assert_eq!(decrypt_to_plain(&dto, b"pw").unwrap().as_slice(), b"hello");
    }

    const OLD_SALT: &str = "BwcHBwcHBwcHBwcHBwcHBw==";
    const OLD_NONCE: &str = "CQkJCQkJCQkJCQkJ";
    const OLD_CT: &str = "RP5SwNCnQpSyn9fMv8GAU32Q3D9W";
}
