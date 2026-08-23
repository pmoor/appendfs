use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum CipherSuite {
    #[default]
    None = 0,
    ChaCha20Poly1305 = 1,
}

impl CipherSuite {
    pub fn is_encrypted(self) -> bool {
        self != CipherSuite::None
    }
}

impl fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CipherSuite::None => write!(f, "Plaintext (None)"),
            CipherSuite::ChaCha20Poly1305 => write!(f, "ChaCha20-Poly1305"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    AuthFailed,
    /// The supplied passphrase or key file does not match this volume.
    ///
    /// Kept distinct from [`CryptoError::AuthFailed`] so a wrong key is never reported as
    /// data corruption - the two are otherwise indistinguishable to a caller.
    WrongKey,
    /// Encrypted data was reached with no key supplied at all.
    ///
    /// Distinct from [`CryptoError::WrongKey`]: "you did not provide a key" and "the key
    /// you provided is wrong" call for different things from the user.
    KeyRequired,
    InvalidKeyLength,
    IoError(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::AuthFailed => write!(f, "Cryptographic authentication failed (corrupted or tampered data)"),
            CryptoError::WrongKey => write!(
                f,
                "Wrong passphrase or key file for this volume (the volume itself is intact)"
            ),
            CryptoError::KeyRequired => write!(
                f,
                "This volume is encrypted - a passphrase or key file is required to read it"
            ),
            CryptoError::InvalidKeyLength => write!(f, "Invalid cryptographic key length"),
            CryptoError::IoError(s) => write!(f, "Crypto I/O error: {}", s),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<CryptoError> for std::io::Error {
    fn from(err: CryptoError) -> Self {
        match err {
            CryptoError::AuthFailed => std::io::Error::new(std::io::ErrorKind::InvalidData, err),
            CryptoError::WrongKey | CryptoError::KeyRequired => {
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, err)
            }
            _ => std::io::Error::other(err),
        }
    }
}

/// Encrypts `plaintext` with associated authenticated data `aad`.
pub fn encrypt_payload(
    cipher: CipherSuite,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match cipher {
        CipherSuite::None => Ok(plaintext.to_vec()),
        CipherSuite::ChaCha20Poly1305 => {
            let key = Key::from_slice(key);
            let cipher = ChaCha20Poly1305::new(key);
            let nonce = Nonce::from_slice(nonce);
            let payload = Payload { msg: plaintext, aad };
            cipher.encrypt(nonce, payload).map_err(|_| CryptoError::AuthFailed)
        }
    }
}

/// Decrypts `ciphertext` with associated authenticated data `aad`.
pub fn decrypt_payload(
    cipher: CipherSuite,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match cipher {
        CipherSuite::None => Ok(ciphertext.to_vec()),
        CipherSuite::ChaCha20Poly1305 => {
            let key = Key::from_slice(key);
            let cipher = ChaCha20Poly1305::new(key);
            let nonce = Nonce::from_slice(nonce);
            let payload = Payload { msg: ciphertext, aad };
            cipher.decrypt(nonce, payload).map_err(|_| CryptoError::AuthFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20poly1305_round_trip() {
        let key = [0x42u8; 32];
        let nonce = [0x07u8; 12];
        let aad = b"record_header_bytes";
        let plaintext = b"Hello AppendFS Encrypted World!";

        let ciphertext = encrypt_payload(CipherSuite::ChaCha20Poly1305, &key, &nonce, aad, plaintext).unwrap();
        assert_ne!(&ciphertext, plaintext);
        assert_eq!(ciphertext.len(), plaintext.len() + 16);

        let decrypted = decrypt_payload(CipherSuite::ChaCha20Poly1305, &key, &nonce, aad, &ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let nonce = [0x07u8; 12];
        let aad = b"record_header_bytes";
        let plaintext = b"Sensitive filesystem metadata";

        let mut ciphertext = encrypt_payload(CipherSuite::ChaCha20Poly1305, &key, &nonce, aad, plaintext).unwrap();
        // Tamper with one byte
        ciphertext[0] ^= 0xFF;

        let err = decrypt_payload(CipherSuite::ChaCha20Poly1305, &key, &nonce, aad, &ciphertext).unwrap_err();
        assert_eq!(err, CryptoError::AuthFailed);
    }

    #[test]
    fn test_tampered_aad_fails() {
        let key = [0x42u8; 32];
        let nonce = [0x07u8; 12];
        let aad = b"record_header_bytes";
        let plaintext = b"Sensitive filesystem metadata";

        let ciphertext = encrypt_payload(CipherSuite::ChaCha20Poly1305, &key, &nonce, aad, plaintext).unwrap();
        let wrong_aad = b"different_header_bytes";

        let err = decrypt_payload(CipherSuite::ChaCha20Poly1305, &key, &nonce, wrong_aad, &ciphertext).unwrap_err();
        assert_eq!(err, CryptoError::AuthFailed);
    }

    #[test]
    fn test_none_cipher_is_identity() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"Plaintext bytes";

        let encrypted = encrypt_payload(CipherSuite::None, &key, &nonce, b"", plaintext).unwrap();
        assert_eq!(&encrypted, plaintext);

        let decrypted = decrypt_payload(CipherSuite::None, &key, &nonce, b"", &encrypted).unwrap();
        assert_eq!(&decrypted, plaintext);
    }
}
