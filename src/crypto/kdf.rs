use crate::crypto::cipher::CryptoError;
use std::fs;
use std::io;
use std::path::Path;
use zeroize::Zeroize;

/// Argon2id parameters: 64 MiB memory, 3 passes, 1 lane.
pub const ARGON2_M_COST_KIB: u32 = 64 * 1024;
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 1;

/// Derives a 256-bit key from a user passphrase and salt using Argon2id.
///
/// Private on purpose: callers go through [`MasterKey::from_passphrase`], so raw key bytes
/// are never handed out unwrapped and always land in a zeroizing holder.
fn derive_master_key_argon2id(passphrase: &[u8], salt: &[u8; 16]) -> Result<[u8; 32], CryptoError> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| CryptoError::IoError(format!("Argon2 params error: {}", e)))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| CryptoError::IoError(format!("Argon2 derivation error: {}", e)))?;

    Ok(key)
}

/// Fast Argon2id parameters for tests.
#[cfg(test)]
fn derive_master_key_argon2id_fast(passphrase: &[u8], salt: &[u8; 16]) -> Result<[u8; 32], CryptoError> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params =
        Params::new(1024, 1, 1, Some(32)).map_err(|e| CryptoError::IoError(format!("Argon2 params error: {}", e)))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| CryptoError::IoError(format!("Argon2 derivation error: {}", e)))?;

    Ok(key)
}

/// Number of hex characters encoding a 256-bit key.
pub const KEY_HEX_LEN: usize = 64;

/// Parses a key file's contents as `KEY_HEX_LEN` hex characters, ignoring surrounding
/// whitespace. `Err` carries a human-readable reason.
fn parse_hex_key(content: &[u8]) -> Result<[u8; 32], String> {
    let text = std::str::from_utf8(content)
        .map_err(|_| "file contains binary data, not hex text".to_string())?
        .trim();

    let found = text.chars().count();
    if found != KEY_HEX_LEN {
        return Err(format!("expected {} hex characters, found {}", KEY_HEX_LEN, found));
    }
    if let Some(bad) = text.chars().find(|c| !c.is_ascii_hexdigit()) {
        return Err(format!("contains non-hex character {:?}", bad));
    }

    // Every character is now a verified ASCII hex digit, so byte-indexing is safe.
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(key)
}

/// Loads a 256-bit key from a file containing exactly `KEY_HEX_LEN` hex characters.
///
/// Hex is the only accepted encoding, and the file is validated on every use - at `init`
/// and at every mount - so a malformed key file is rejected outright rather than quietly
/// becoming *some* key.
///
/// This function used to guess between three encodings by content: exactly 32 bytes was
/// taken as a raw key, 64 hex characters were decoded, and anything else was BLAKE3-hashed.
/// Guessing made a single stray byte change both the key *and* the branch that produced it,
/// with no error - appending a newline to a raw 32-byte key silently moved it to the hash
/// branch and produced a different, equally valid key. Only hex survives that round trip
/// intact, because it is the one form where surrounding whitespace can be trimmed without
/// ambiguity.
fn load_key_from_file(path: impl AsRef<Path>) -> io::Result<[u8; 32]> {
    let path = path.as_ref();
    // `fs::read` does not name the path in its error, and callers pass this straight to the
    // user, so attach it here rather than leaving them with a bare "No such file".
    let content = fs::read(path)
        .map_err(|e| io::Error::new(e.kind(), format!("cannot read key file '{}': {}", path.display(), e)))?;

    parse_hex_key(&content).map_err(|reason| {
        let mut msg = format!(
            "key file '{}' is not a valid key: {}.\n\
             Expected {} hex characters encoding a 256-bit key; surrounding whitespace is ignored.\n\
             Generate one with: openssl rand -hex 32",
            path.display(),
            reason,
            KEY_HEX_LEN
        );
        if content.len() == 32 {
            msg.push_str(
                "\nThis file is exactly 32 bytes - if it is a raw binary key from an older \
                 version, convert it with: xxd -p -c 32 <file>",
            );
        }
        io::Error::new(io::ErrorKind::InvalidData, msg)
    })
}

/// Builds the Argon2id password material binding a key file to a passphrase.
///
/// The key file's 32 bytes come first precisely because they are fixed-width. With a
/// variable-length part on either side of the boundary the encoding would be ambiguous:
/// `("ab", "cd")` and `("a", "bcd")` would produce identical material and so derive the
/// same key from different credentials.
fn combined_material(key_bytes: &[u8; 32], passphrase: &str) -> Vec<u8> {
    let mut material = Vec::with_capacity(key_bytes.len() + passphrase.len());
    material.extend_from_slice(key_bytes);
    material.extend_from_slice(passphrase.as_bytes());
    material
}

/// Prompts the user interactively on the terminal for a password without echo.
pub fn prompt_passphrase(prompt: &str) -> io::Result<String> {
    rpassword::prompt_password(prompt)
}

/// A securely zeroized master key wrapper.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct MasterKey {
    pub key: [u8; 32],
}

impl MasterKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn from_passphrase(passphrase: &str, salt: &[u8; 16]) -> Result<Self, CryptoError> {
        let key = derive_master_key_argon2id(passphrase.as_bytes(), salt)?;
        Ok(Self { key })
    }

    pub fn from_file(path: impl AsRef<Path>) -> io::Result<Self> {
        let key = load_key_from_file(path)?;
        Ok(Self { key })
    }

    /// Derives a key that requires *both* a key file and a passphrase.
    ///
    /// Both secrets go in as Argon2id password material with the volume's random salt kept
    /// in the salt slot. Putting the passphrase in the salt slot instead would be the wrong
    /// shape: Argon2 rejects salts under 8 bytes, and a salt's job is per-volume uniqueness,
    /// not secrecy - KDF security arguments do not assume it is hidden. Feeding both as
    /// password material keeps the memory-hard cost on every guess, so an attacker holding a
    /// stolen key file still pays full Argon2 per passphrase attempt.
    ///
    /// The key file's 32 bytes come first precisely because they are fixed-width: with a
    /// variable-length part on either side of the boundary, `("ab", "cd")` and `("a", "bcd")`
    /// would concatenate identically and collide.
    pub fn from_file_and_passphrase(path: impl AsRef<Path>, passphrase: &str, salt: &[u8; 16]) -> io::Result<Self> {
        let mut key_bytes = load_key_from_file(path)?;
        let mut material = combined_material(&key_bytes, passphrase);
        key_bytes.zeroize();

        // Derive before propagating, so the combined secret is wiped on the error path too.
        let derived = derive_master_key_argon2id(&material, salt);
        material.zeroize();

        Ok(Self {
            key: derived.map_err(io::Error::from)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2id_derivation_deterministic() {
        let salt = [0x77u8; 16];
        let p1 = "super_secure_passphrase_2026";
        let k1 = derive_master_key_argon2id_fast(p1.as_bytes(), &salt).unwrap();
        let k2 = derive_master_key_argon2id_fast(p1.as_bytes(), &salt).unwrap();
        assert_eq!(k1, k2);

        let k_diff_salt = derive_master_key_argon2id_fast(p1.as_bytes(), &[0x88u8; 16]).unwrap();
        assert_ne!(k1, k_diff_salt);

        let k_diff_pass = derive_master_key_argon2id_fast(b"different_pass", &salt).unwrap();
        assert_ne!(k1, k_diff_pass);
    }

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn load(contents: &[u8]) -> io::Result<[u8; 32]> {
        let temp = tempfile::NamedTempFile::new().unwrap();
        fs::write(temp.path(), contents).unwrap();
        load_key_from_file(temp.path())
    }

    #[test]
    fn test_hex_key_survives_whitespace_round_trips() {
        let expected = load(HEX.as_bytes()).unwrap();
        assert_eq!(expected[0], 0x01);
        assert_eq!(expected[1], 0x23);
        assert_eq!(expected[31], 0xef);

        // The point of mandating hex: the encoding is stable across the mangling that key
        // files actually suffer - editors appending newlines, shells adding whitespace,
        // clipboards changing case. All of these must yield the very same key.
        for variant in [
            format!("{}\n", HEX),
            format!("{}\r\n", HEX),
            format!("  {}  \n", HEX),
            HEX.to_uppercase(),
            format!("{}\n", HEX.to_uppercase()),
        ] {
            assert_eq!(load(variant.as_bytes()).unwrap(), expected, "variant {:?}", variant);
        }
    }

    #[test]
    fn test_non_hex_key_files_are_rejected() {
        // Each of these used to be silently accepted as *some* key by the old
        // guess-the-encoding loader. They must now fail loudly instead.
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("raw 32 bytes", vec![0x55u8; 32]),
            ("binary blob", vec![0xFFu8; 100]),
            ("passphrase text", b"hunter2".to_vec()),
            ("empty file", Vec::new()),
            ("too short", HEX.as_bytes()[..63].to_vec()),
            ("too long", format!("{}0", HEX).into_bytes()),
            ("non-hex character", HEX.replace('0', "z").into_bytes()),
        ];

        for (name, contents) in cases {
            let err = load(&contents).expect_err(name);
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{}", name);
            assert!(
                err.to_string().contains("is not a valid key"),
                "{}: unhelpful error: {}",
                name,
                err
            );
        }
    }

    #[test]
    fn test_master_key_from_file_enforces_hex() {
        // `init` and every mount reach key files through `MasterKey::from_file`, so the
        // validation has to bite at this entry point - not merely inside the private
        // loader - for both paths to be covered.
        let temp = tempfile::NamedTempFile::new().unwrap();

        fs::write(temp.path(), [0x55u8; 32]).unwrap();
        assert!(MasterKey::from_file(temp.path()).is_err(), "raw key must be rejected");

        fs::write(temp.path(), format!("{}\n", HEX)).unwrap();
        assert_eq!(
            MasterKey::from_file(temp.path()).unwrap().key,
            load(HEX.as_bytes()).unwrap()
        );
    }

    #[test]
    fn test_combined_material_is_unambiguous() {
        // Pure input construction, so this needs no Argon2 and stays fast. The property
        // that matters is that no two distinct credential pairs collapse to the same
        // material - if they did, two different (key file, passphrase) pairs would open
        // the same volume.
        let file_a = [0xAAu8; 32];
        let file_b = [0xBBu8; 32];

        // The classic split-boundary collision, which a variable-width prefix would allow.
        assert_ne!(combined_material(&file_a, "ab"), combined_material(&file_a, "abc"));
        // Either factor changing must change the material.
        assert_ne!(combined_material(&file_a, "pass"), combined_material(&file_b, "pass"));
        assert_ne!(combined_material(&file_a, "pass"), combined_material(&file_a, "Pass"));
        // The key file is carried verbatim as a fixed-width prefix.
        assert_eq!(&combined_material(&file_a, "pass")[..32], &file_a[..]);
        assert_eq!(combined_material(&file_a, "pass").len(), 36);
    }

    #[test]
    fn test_key_file_plus_passphrase_round_trips_and_needs_both() {
        // One real end-to-end derivation: Argon2 itself is covered by the fast-parameter
        // test above, so this only has to prove the wiring.
        let temp = tempfile::NamedTempFile::new().unwrap();
        fs::write(temp.path(), HEX).unwrap();
        let salt = [0x42u8; 16];

        let both = MasterKey::from_file_and_passphrase(temp.path(), "correct horse", &salt).unwrap();
        let again = MasterKey::from_file_and_passphrase(temp.path(), "correct horse", &salt).unwrap();
        assert_eq!(both.key, again.key, "same credentials must reproduce the same key");

        // Presenting only the key file must not open a two-factor volume. (`from_file` does
        // no derivation, so this comparison is free.)
        assert_ne!(both.key, MasterKey::from_file(temp.path()).unwrap().key);
    }

    #[test]
    fn test_raw_32_byte_key_file_gets_a_conversion_hint() {
        // Anyone carrying a raw key file from before hex was mandatory should be told how
        // to convert it, not just that their file is wrong.
        let err = load(&[0x55u8; 32]).unwrap_err();
        assert!(err.to_string().contains("xxd -p -c 32"), "no conversion hint: {}", err);
    }
}
