use crate::crypto::cipher::{CipherSuite, CryptoError, decrypt_payload, encrypt_payload};
use crate::crypto::kdf::MasterKey;
use crate::crypto::nonce::{derive_record_nonce, generate_random_16, generate_random_iv};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zeroize::Zeroize;

/// Domain-separation contexts for the two subkeys derived from the master key.
///
/// The master key is never used to encrypt anything directly. Deriving separate subkeys
/// keeps the key-check value and the data path in disjoint key spaces, so the KCV's random
/// IV can never collide with a derived record nonce under the same key.
const DATA_KEY_CONTEXT: &str = "appendfs volume data key v1";
const KCV_KEY_CONTEXT: &str = "appendfs key check value v1";

fn derive_subkey(context: &str, master: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(context, master)
}

/// Computes the key check value: the bare Poly1305 tag over an empty message, with the
/// volume ID as associated data. Encrypting nothing means the KCV reveals no plaintext and
/// costs exactly one tag; binding `volume_id` stops a KCV from being transplanted between
/// volumes to make a wrong key look right.
fn compute_kcv(master: &[u8; 32], volume_id: &[u8; 16], iv: &[u8; 12]) -> Result<[u8; 16], CryptoError> {
    let kcv_key = derive_subkey(KCV_KEY_CONTEXT, master);
    let tag = encrypt_payload(CipherSuite::ChaCha20Poly1305, &kcv_key, iv, volume_id, &[])?;
    tag.try_into().map_err(|_| CryptoError::InvalidKeyLength)
}

/// Which credentials a volume's key is built from.
///
/// Recorded in the volume header so a mount knows what to ask for. Without it the CLI has to
/// infer the credential type from which flags the user happened to pass, and getting that
/// wrong is indistinguishable from getting the credential itself wrong - both just produce a
/// key that fails the check value.
///
/// This field is unauthenticated (it sits in the plaintext header), but tampering with it
/// only misdirects credential collection into deriving the wrong key, which the check value
/// then rejects. It is a denial of service, not a way in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum KeySource {
    /// Unencrypted volume; no credential at all.
    None = 0,
    /// Argon2id over a passphrase, salted by the header's `kdf_salt`.
    Passphrase = 1,
    /// The key file's 64 hex characters are the key material directly, with no stretching -
    /// it already carries a full 256 bits.
    KeyFile = 2,
    /// Both, so a stolen key file alone is useless and a guessed passphrase alone is too.
    KeyFileAndPassphrase = 3,
}

impl KeySource {
    /// Whether mounting this volume requires `--key-file`.
    pub fn needs_key_file(self) -> bool {
        matches!(self, KeySource::KeyFile | KeySource::KeyFileAndPassphrase)
    }

    /// Whether mounting this volume requires a passphrase.
    pub fn needs_passphrase(self) -> bool {
        matches!(self, KeySource::Passphrase | KeySource::KeyFileAndPassphrase)
    }
}

impl std::fmt::Display for KeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            KeySource::None => "None (unencrypted)",
            KeySource::Passphrase => "Passphrase",
            KeySource::KeyFile => "Key file",
            KeySource::KeyFileAndPassphrase => "Key file + passphrase",
        };
        f.pad(s)
    }
}

/// Volume identity and key-verification material. Always stored in plaintext.
///
/// This is the part of a volume that must be readable *before* the key is known, so a mount
/// can tell "you supplied the wrong key" apart from "this volume is corrupt". Without it a
/// wrong key surfaces as an authentication failure deep inside recovery, which is
/// indistinguishable from bitrot and reads to the user like data loss.
///
/// There is no wrapped key here and no indirection: the user's key *is* the volume key
/// (via [`derive_subkey`]). Losing it loses the volume, and changing it means re-encrypting
/// every generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeHeader {
    pub cipher: CipherSuite,
    /// Which credentials reconstruct this volume's key.
    pub key_source: KeySource,
    pub volume_id: [u8; 16],
    /// Argon2id salt. Meaningful only when [`KeySource::needs_passphrase`]; zero otherwise,
    /// since a key file carries full entropy and is used without stretching.
    pub kdf_salt: [u8; 16],
    /// Private: nothing outside this module has business reading or writing the check
    /// value. It is only ever produced by [`VolumeHeader::new_encrypted`] and consumed by
    /// [`VolumeHeader::unlock`].
    kcv_iv: [u8; 12],
    kcv_tag: [u8; 16],
}

impl VolumeHeader {
    /// An unencrypted volume: no key, no check value, zero overhead.
    pub fn plaintext() -> Self {
        Self {
            cipher: CipherSuite::None,
            key_source: KeySource::None,
            volume_id: [0u8; 16],
            kdf_salt: [0u8; 16],
            kcv_iv: [0u8; 12],
            kcv_tag: [0u8; 16],
        }
    }

    /// Creates an encrypted volume header along with the key needed to read and write it.
    ///
    /// `key_source` records how `master` was produced so later mounts ask for the same
    /// credentials; passing [`KeySource::None`] here would describe an encrypted volume as
    /// unencrypted, so it is rejected.
    pub fn new_encrypted(
        master: &MasterKey,
        kdf_salt: [u8; 16],
        key_source: KeySource,
    ) -> Result<(Self, VolumeKey), CryptoError> {
        if key_source == KeySource::None {
            return Err(CryptoError::IoError(
                "an encrypted volume needs a key source other than None".into(),
            ));
        }

        let volume_id = generate_random_16();
        let kcv_iv = generate_random_iv();
        let kcv_tag = compute_kcv(&master.key, &volume_id, &kcv_iv)?;

        let header = Self {
            cipher: CipherSuite::ChaCha20Poly1305,
            key_source,
            volume_id,
            kdf_salt,
            kcv_iv,
            kcv_tag,
        };
        let key = VolumeKey::new(
            volume_id,
            CipherSuite::ChaCha20Poly1305,
            derive_subkey(DATA_KEY_CONTEXT, &master.key),
        );

        Ok((header, key))
    }

    /// Verifies `master` against the key check value and returns the volume key.
    ///
    /// Returns [`CryptoError::WrongKey`] - never [`CryptoError::AuthFailed`] - when the key
    /// is simply wrong, so callers can report that plainly instead of alarming the user
    /// about corruption. The check is the AEAD tag comparison itself, so it is
    /// constant-time.
    pub fn unlock(&self, master: &MasterKey) -> Result<VolumeKey, CryptoError> {
        if self.cipher == CipherSuite::None {
            return Ok(VolumeKey::plaintext_with_volume_id(self.volume_id));
        }

        let kcv_key = derive_subkey(KCV_KEY_CONTEXT, &master.key);
        decrypt_payload(
            CipherSuite::ChaCha20Poly1305,
            &kcv_key,
            &self.kcv_iv,
            &self.volume_id,
            &self.kcv_tag,
        )
        .map_err(|_| CryptoError::WrongKey)?;

        Ok(VolumeKey::new(
            self.volume_id,
            self.cipher,
            derive_subkey(DATA_KEY_CONTEXT, &master.key),
        ))
    }
}

/// Builds the associated data authenticated alongside a record payload.
///
/// The record nonce already covers `generation` and `tx_id` (a mismatch there yields a
/// different nonce, which fails the tag), and `payload_len`/`checksum` are covered
/// implicitly - truncating or extending the ciphertext breaks authentication. `op_code`
/// and `inode` have no such protection, so without binding them a valid ciphertext could
/// be relabelled as a different record type or reattributed to another inode, grafting
/// one file's data onto another. They are bound here instead.
///
/// `payload_len` and `checksum` are deliberately excluded: both are derived from the
/// ciphertext, so feeding them in would make the AAD depend on the encryption's output.
fn record_aad(op_code: u8, tx_id: u64, inode: u64) -> [u8; 17] {
    let mut aad = [0u8; 17];
    aad[0] = op_code;
    aad[1..9].copy_from_slice(&tx_id.to_be_bytes());
    aad[9..17].copy_from_slice(&inode.to_be_bytes());
    aad
}

/// The unlocked key for a volume.
///
/// Immutable for the lifetime of a mount: there is exactly one key, it never rotates, and
/// nothing about it changes at runtime. That is what lets this be a plain value shared by
/// `Arc` with no interior mutability on the write path.
#[derive(Clone)]
pub struct VolumeKey {
    pub volume_id: [u8; 16],
    cipher: CipherSuite,
    key: [u8; 32],
}

impl Drop for VolumeKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Deliberately hand-written rather than derived: a derived `Debug` would print the raw
/// key bytes into any log line, panic message, or assertion failure that formats a value
/// containing one.
impl std::fmt::Debug for VolumeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VolumeKey")
            .field("volume_id", &self.volume_id)
            .field("cipher", &self.cipher)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl VolumeKey {
    fn new(volume_id: [u8; 16], cipher: CipherSuite, key: [u8; 32]) -> Self {
        Self { volume_id, cipher, key }
    }

    /// A no-op key for unencrypted volumes: every operation is an identity pass-through.
    pub fn plaintext() -> Self {
        Self::plaintext_with_volume_id([0u8; 16])
    }

    fn plaintext_with_volume_id(volume_id: [u8; 16]) -> Self {
        Self {
            volume_id,
            cipher: CipherSuite::None,
            key: [0u8; 32],
        }
    }

    /// Convenience helper returning `Arc<VolumeKey>` for unencrypted volumes.
    pub fn plaintext_arc() -> Arc<Self> {
        Arc::new(Self::plaintext())
    }

    pub fn cipher(&self) -> CipherSuite {
        self.cipher
    }

    /// Encrypts a record payload. A plaintext volume returns it untouched.
    ///
    /// `op_code` and `inode` are authenticated but not encrypted - see [`record_aad`].
    pub fn encrypt_record(
        &self,
        generation: u64,
        tx_id: u64,
        op_code: u8,
        inode: u64,
        payload: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if self.cipher == CipherSuite::None {
            return Ok(payload.to_vec());
        }

        let nonce = derive_record_nonce(generation, tx_id);
        let aad = record_aad(op_code, tx_id, inode);
        encrypt_payload(self.cipher, &self.key, &nonce, &aad, payload)
    }

    /// Decrypts a record payload. A plaintext volume returns it untouched.
    ///
    /// Whether a payload is encrypted follows from the volume's cipher alone. Records used
    /// to carry their own `key_id` byte saying so, which was the wrong shape: the record
    /// header is not covered by the payload checksum, so that byte arrived unauthenticated,
    /// and honouring a cleared one let anyone who could write to the storage have the
    /// filesystem hand back raw ciphertext as file contents. A volume-level fact belongs in
    /// the volume header, where the key check value vouches for it.
    ///
    /// Fails with `AuthFailed` if `op_code` or `inode` no longer match the values bound at
    /// write time, even when the ciphertext itself is intact.
    pub fn decrypt_record(
        &self,
        generation: u64,
        tx_id: u64,
        op_code: u8,
        inode: u64,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if self.cipher == CipherSuite::None {
            return Ok(ciphertext.to_vec());
        }

        let nonce = derive_record_nonce(generation, tx_id);
        let aad = record_aad(op_code, tx_id, inode);

        decrypt_payload(self.cipher, &self.key, &nonce, &aad, ciphertext)
    }

    /// Encrypts summary data with an explicit IV and AAD.
    pub fn encrypt_summary(&self, iv: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.cipher == CipherSuite::None {
            return Ok(plaintext.to_vec());
        }
        encrypt_payload(self.cipher, &self.key, iv, aad, plaintext)
    }

    /// Decrypts summary data with an explicit IV and AAD.
    pub fn decrypt_summary(&self, iv: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.cipher == CipherSuite::None {
            return Ok(ciphertext.to_vec());
        }
        decrypt_payload(self.cipher, &self.key, iv, aad, ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stand-in opcode; the crypto layer treats it as an opaque byte.
    const OP: u8 = 1;

    #[test]
    fn test_volume_round_trip() {
        let master = MasterKey::new([0x33u8; 32]);
        let (header, key) = VolumeHeader::new_encrypted(&master, [0u8; 16], KeySource::KeyFile).unwrap();
        assert_eq!(header.cipher, CipherSuite::ChaCha20Poly1305);

        let payload = b"Record payload for the volume key";
        let ct = key.encrypt_record(1, 100, OP, 5, payload).unwrap();
        assert_ne!(&ct[..], &payload[..]);

        // A key recovered by unlocking the stored header decrypts what the original wrote.
        let reopened = header.unlock(&master).unwrap();
        assert_eq!(reopened.decrypt_record(1, 100, OP, 5, &ct).unwrap(), payload);
        assert_eq!(reopened.volume_id, header.volume_id);
    }

    #[test]
    fn test_wrong_key_is_distinguishable_from_corruption() {
        let master = MasterKey::new([0x33u8; 32]);
        let (header, _key) = VolumeHeader::new_encrypted(&master, [0u8; 16], KeySource::KeyFile).unwrap();

        // The whole point of the KCV: a wrong key is reported as WrongKey, not AuthFailed,
        // so a mount never tells the user their intact volume is corrupt.
        let wrong = MasterKey::new([0x99u8; 32]);
        assert_eq!(header.unlock(&wrong).unwrap_err(), CryptoError::WrongKey);

        // And the right key still opens it.
        assert!(header.unlock(&master).is_ok());
    }

    #[test]
    fn test_kcv_cannot_be_transplanted_between_volumes() {
        let master_a = MasterKey::new([0x11u8; 32]);
        let master_b = MasterKey::new([0x22u8; 32]);
        let (header_a, _) = VolumeHeader::new_encrypted(&master_a, [0u8; 16], KeySource::KeyFile).unwrap();
        let (mut header_b, _) = VolumeHeader::new_encrypted(&master_b, [0u8; 16], KeySource::KeyFile).unwrap();

        // Splicing A's check value into B's header must not make A's key open B, because
        // the KCV is bound to the volume ID it was minted for.
        header_b.kcv_iv = header_a.kcv_iv;
        header_b.kcv_tag = header_a.kcv_tag;
        assert_eq!(header_b.unlock(&master_a).unwrap_err(), CryptoError::WrongKey);
    }

    #[test]
    fn test_data_and_kcv_subkeys_are_independent() {
        let master = MasterKey::new([0x44u8; 32]);
        let data = derive_subkey(DATA_KEY_CONTEXT, &master.key);
        let kcv = derive_subkey(KCV_KEY_CONTEXT, &master.key);
        assert_ne!(data, kcv);
        assert_ne!(data, master.key);
        assert_ne!(kcv, master.key);
    }

    #[test]
    fn test_record_aad_binds_opcode_and_inode() {
        let master = MasterKey::new([0x33u8; 32]);
        let (_header, key) = VolumeHeader::new_encrypted(&master, [0u8; 16], KeySource::KeyFile).unwrap();

        let payload = b"extent belonging to inode 5";
        let ct = key.encrypt_record(1, 100, OP, 5, payload).unwrap();

        // Baseline: the untampered record round-trips.
        assert_eq!(key.decrypt_record(1, 100, OP, 5, &ct).unwrap(), payload);

        // Reattributing the payload to a different inode must fail, even though the
        // ciphertext is byte-for-byte intact.
        assert_eq!(
            key.decrypt_record(1, 100, OP, 6, &ct).unwrap_err(),
            CryptoError::AuthFailed
        );

        // Relabelling the record as a different opcode must fail too.
        assert_eq!(
            key.decrypt_record(1, 100, OP + 1, 5, &ct).unwrap_err(),
            CryptoError::AuthFailed
        );

        // Generation and tx_id remain bound via the nonce.
        assert_eq!(
            key.decrypt_record(2, 100, OP, 5, &ct).unwrap_err(),
            CryptoError::AuthFailed
        );
        assert_eq!(
            key.decrypt_record(1, 101, OP, 5, &ct).unwrap_err(),
            CryptoError::AuthFailed
        );
    }

    #[test]
    fn test_plaintext_key_is_pass_through() {
        let key = VolumeKey::plaintext();
        let payload = b"unencrypted bytes";

        let ct = key.encrypt_record(1, 100, OP, 5, payload).unwrap();
        assert_eq!(&ct[..], &payload[..]);
        assert_eq!(key.decrypt_record(1, 100, OP, 5, &ct).unwrap(), payload);
    }

    #[test]
    fn test_summary_round_trip() {
        let master = MasterKey::new([0x66u8; 32]);
        let (header, key) = VolumeHeader::new_encrypted(&master, [0u8; 16], KeySource::KeyFile).unwrap();

        let iv = generate_random_iv();
        let aad = b"summary header bytes";
        let body = b"serialized summary body";

        let ct = key.encrypt_summary(&iv, aad, body).unwrap();
        let reopened = header.unlock(&master).unwrap();
        assert_eq!(reopened.decrypt_summary(&iv, aad, &ct).unwrap(), body);

        // A different AAD (a tampered summary header) must not verify.
        assert_eq!(
            reopened.decrypt_summary(&iv, b"other header", &ct).unwrap_err(),
            CryptoError::AuthFailed
        );
    }
}
