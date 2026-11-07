//! Agent key files, `private-keys-v1.d/<KEYGRIP>.key`.
//!
//! Reads the extended format (`Key:` items with GnuPG's line folding) and
//! the older canonical format, removes `openpgp-s2k3-ocb-aes` and
//! `openpgp-s2k3-sha1-aes-cbc` protection, and writes keys protected the
//! way gpg-agent does (`agent/protect.c`), so either agent can read them.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;
use sha1::{Digest, Sha1};
use tracing::debug;
use zeroize::Zeroizing;

use super::sexp::{
    CanonicalParser,
    SexpNode,
    parse_canonical,
    parse_gpg_sexp,
    push_atom,
    push_param,
    render_advanced,
};
use crate::error::{Error, Result};

/// GnuPG's calibrated default S2K byte count, as seen in its own key files.
pub const DEFAULT_S2K_COUNT: u64 = 131_585_024;

/// A key's algorithm and parameters, public and secret, as in the agent's
/// `(private-key (ALGO (curve ..) (flags ..) (NAME VALUE)...))`.
pub struct KeyMaterial {
    pub algo: String,
    pub curve: Option<String>,
    pub flags: Vec<String>,
    pub params: Vec<(String, Zeroizing<Vec<u8>>)>,
}

/// Names only: the values include secret key material.
impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("algo", &self.algo)
            .field("curve", &self.curve)
            .field("flags", &self.flags)
            .field(
                "params",
                &self
                    .params
                    .iter()
                    .map(|(n, _)| n.as_str())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl KeyMaterial {
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.params
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_slice())
    }

    /// Names of the secret parameters for this algorithm. RSA's `q` is a
    /// secret prime while ECC's `q` is the public point.
    fn secret_names(&self) -> Result<&'static [&'static str]> {
        match self.algo.as_str() {
            "rsa" => Ok(&["d", "p", "q", "u"]),
            "ecc" | "ecdsa" | "eddsa" | "ecdh" => Ok(&["d"]),
            other => Err(Error::UnsupportedKeyType(format!("algorithm {other}"))),
        }
    }
}

/// Read and unprotect a key file.
pub fn read_key_file(path: &Path, passphrase: &str) -> Result<KeyMaterial> {
    let bytes = Zeroizing::new(std::fs::read(path)?);
    parse_key_file(&bytes, passphrase)
}

pub fn parse_key_file(bytes: &[u8], passphrase: &str) -> Result<KeyMaterial> {
    let canonical = key_canonical(bytes)?;
    let root = parse_canonical(&canonical)?;
    let items = root.as_list().unwrap_or_default();
    let (Some(kind), Some(key)) = (root.name(), items.get(1).and_then(SexpNode::as_list)) else {
        return Err(Error::SexpParse("expected (KIND (ALGO ...))".into()));
    };
    match kind {
        b"private-key" => material_from_list(key, Vec::new()),
        b"protected-private-key" => material_from_list(key, unprotect(&canonical, passphrase)?),
        b"shadowed-private-key" => Err(Error::UnsupportedKeyType(
            "key is on a smartcard (shadowed)".into(),
        )),
        other => Err(Error::UnsupportedKeyType(format!(
            "key file type {}",
            String::from_utf8_lossy(other)
        ))),
    }
}

/// Build key material from `(ALGO (NAME VALUE)...)`, adding secret
/// parameters that were decrypted separately.
pub fn material_from_list(
    key: &[SexpNode],
    secret: Vec<(String, Zeroizing<Vec<u8>>)>,
) -> Result<KeyMaterial> {
    let algo = key
        .first()
        .and_then(SexpNode::as_atom)
        .ok_or_else(|| Error::SexpParse("missing key algorithm".into()))?;
    let mut material = KeyMaterial {
        algo: String::from_utf8_lossy(algo).to_ascii_lowercase(),
        curve: None,
        flags: Vec::new(),
        params: Vec::new(),
    };
    for item in &key[1..] {
        let Some(list) = item.as_list() else { continue };
        let Some(name) = item.name() else { continue };
        let value = list.get(1).and_then(SexpNode::as_atom);
        match (name, value) {
            (b"curve", Some(v)) => material.curve = Some(String::from_utf8_lossy(v).into_owned()),
            (b"flags", _) => {
                material.flags = list[1..]
                    .iter()
                    .filter_map(SexpNode::as_atom)
                    .map(|f| String::from_utf8_lossy(f).into_owned())
                    .collect();
            }
            (b"protected" | b"protected-at" | b"shadowed", _) => {}
            (_, Some(v)) => material.params.push((
                String::from_utf8_lossy(name).into_owned(),
                Zeroizing::new(v.to_vec()),
            )),
            (_, None) => {}
        }
    }
    material.params.extend(secret);
    Ok(material)
}

/// The key's S-expression in canonical form.
fn key_canonical(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if bytes.first() == Some(&b'(') {
        return Ok(Zeroizing::new(bytes.to_vec()));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| Error::InvalidMessageFormat)?;
    let value = extended_key_value(text)
        .ok_or_else(|| Error::UnsupportedKeyType("no Key: item in key file".into()))?;
    Ok(Zeroizing::new(parse_gpg_sexp(&value)?.to_canonical()))
}

/// The value of the `Key:` item, unfolded like GnuPG's name-value parser
/// (`common/name-value.c`): every line of the value loses one leading
/// whitespace character and its trailing whitespace, and the pieces are
/// joined without separators. A fold may therefore split a token.
fn extended_key_value(text: &str) -> Option<Zeroizing<String>> {
    let mut value: Option<Zeroizing<String>> = None;
    let mut swallow_ws = false;
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let piece = match &value {
            None => match line.get(..4) {
                Some(name) if name.eq_ignore_ascii_case("key:") => &line[4..],
                _ => continue,
            },
            Some(_) if line.starts_with([' ', '\t']) => line,
            Some(_) => break,
        };
        let v = value.get_or_insert_with(|| Zeroizing::new(String::new()));
        let piece = if swallow_ws {
            piece.trim_start()
        } else {
            piece.strip_prefix([' ', '\t']).unwrap_or(piece)
        };
        let piece = piece.trim_end();
        if piece.is_empty() {
            v.push('\n');
            swallow_ws = true;
        } else {
            v.push_str(piece);
            swallow_ws = false;
        }
    }
    value
}

struct ProtectedKeyParams {
    salt: [u8; 8],
    s2k_count: u64,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    is_ocb: bool,
}

/// Decrypt the `(protected ...)` element and return the secret parameters.
fn unprotect(canonical: &[u8], passphrase: &str) -> Result<Vec<(String, Zeroizing<Vec<u8>>)>> {
    let (params, aad1, aad2) = extract_canonical_params(canonical)?;
    debug!(
        "s2k={} nonce_len={} ct_len={} is_ocb={}",
        params.s2k_count,
        params.nonce.len(),
        params.ciphertext.len(),
        params.is_ocb
    );
    let key = derive_s2k_key(passphrase, &params.salt, params.s2k_count, 16);
    let decrypted = if params.is_ocb {
        decrypt_ocb(&key, &params.nonce, &aad1, &aad2, &params.ciphertext)?
    } else {
        decrypt_cbc(&key, &params.nonce, &params.ciphertext)?
    };
    extract_canonical_mpis(&decrypted)
}

fn extract_canonical_params(canonical: &[u8]) -> Result<(ProtectedKeyParams, Vec<u8>, Vec<u8>)> {
    let mut parser = CanonicalParser::new(canonical);

    parser.expect_list_start()?;
    let outer_name = parser.read_atom()?;
    if outer_name != b"protected-private-key" {
        return Err(Error::SexpParse("expected protected-private-key".into()));
    }

    let aad_begin = parser.position();

    parser.expect_list_start()?;
    let _algo = parser.read_atom()?;

    let mut hole_begin = 0;
    let mut hole_end = 0;
    let mut params = None;

    while !parser.peek_is_list_end() {
        let item_start = parser.position();

        if parser.peek_is_list() {
            parser.expect_list_start()?;

            if !parser.peek_is_list_end() && !parser.peek_is_list() {
                let name = parser.read_atom()?;

                if name == b"protected" {
                    hole_begin = item_start;

                    let method = parser.read_atom()?;
                    let is_ocb = match method {
                        b"openpgp-s2k3-ocb-aes" => true,
                        b"openpgp-s2k3-sha1-aes-cbc" => false,
                        other => {
                            return Err(Error::UnsupportedKeyType(format!(
                                "protection {}",
                                String::from_utf8_lossy(other)
                            )));
                        }
                    };

                    parser.expect_list_start()?;
                    parser.expect_list_start()?;
                    let hash_type = parser.read_atom()?;
                    if hash_type != b"sha1" {
                        return Err(Error::SexpParse("expected sha1".into()));
                    }

                    let salt_data = parser.read_atom()?;
                    let salt: [u8; 8] = salt_data
                        .try_into()
                        .map_err(|_| Error::SexpParse("expected 8-byte salt".into()))?;

                    let count_str = std::str::from_utf8(parser.read_atom()?)
                        .map_err(|_| Error::SexpParse("invalid count string".into()))?;
                    let s2k_count: u64 = count_str
                        .parse()
                        .map_err(|_| Error::SexpParse("invalid count".into()))?;

                    parser.expect_list_end()?;

                    let nonce = parser.read_atom()?.to_vec();
                    parser.expect_list_end()?;

                    let ciphertext = parser.read_atom()?.to_vec();

                    params = Some(ProtectedKeyParams {
                        salt,
                        s2k_count,
                        nonce,
                        ciphertext,
                        is_ocb,
                    });
                }
            }

            while !parser.peek_is_list_end() {
                parser.skip_sexp()?;
            }
            parser.expect_list_end()?;

            if hole_begin == item_start {
                hole_end = parser.position();
            }
        } else {
            parser.skip_sexp()?;
        }
    }

    parser.expect_list_end()?;
    let aad_end = parser.position();

    let params = params.ok_or(Error::SexpParse("no protected section found".into()))?;

    let aad1 = canonical[aad_begin..hole_begin].to_vec();
    let aad2 = canonical[hole_end..aad_end].to_vec();
    Ok((params, aad1, aad2))
}

/// OpenPGP iterated and salted S2K with SHA-1 (`count` is the byte count).
fn derive_s2k_key(
    passphrase: &str,
    salt: &[u8; 8],
    count: u64,
    key_len: usize,
) -> Zeroizing<Vec<u8>> {
    let mut salted = Zeroizing::new(Vec::with_capacity(8 + passphrase.len()));
    salted.extend_from_slice(salt);
    salted.extend_from_slice(passphrase.as_bytes());
    s2k_iterated::<Sha1>(&salted, count, key_len)
}

/// Hash `salted` repeatedly until `count` bytes (at least one copy) went in,
/// preloading `i` zero bytes for the `i`-th hash context, and concatenate
/// the digests up to `key_len` (RFC 4880 section 3.7.1.3).
pub fn s2k_iterated<D: Digest>(salted: &[u8], count: u64, key_len: usize) -> Zeroizing<Vec<u8>> {
    let mut result = Zeroizing::new(Vec::with_capacity(key_len));
    let total = usize::try_from(count)
        .unwrap_or(usize::MAX)
        .max(salted.len());
    let mut preload = 0;
    while result.len() < key_len {
        let mut hasher = D::new();
        for _ in 0..preload {
            hasher.update([0u8]);
        }
        let mut hashed = 0;
        while hashed < total {
            let n = salted.len().min(total - hashed);
            hasher.update(&salted[..n]);
            hashed += n;
        }
        let digest = hasher.finalize();
        let take = (key_len - result.len()).min(digest.len());
        result.extend_from_slice(&digest[..take]);
        preload += 1;
    }
    result
}

#[allow(deprecated)]
fn decrypt_ocb(
    key: &[u8],
    nonce: &[u8],
    aad1: &[u8],
    aad2: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    use aes::Aes128;
    use ocb3::Ocb3;
    use ocb3::aead::generic_array::GenericArray;
    use ocb3::aead::{AeadInPlace, KeyInit};

    if ciphertext.len() < 16 || nonce.len() != 12 {
        return Err(Error::KeyDecryptionFailed);
    }
    let (ct, tag) = ciphertext.split_at(ciphertext.len() - 16);
    let aad = [aad1, aad2].concat();
    let ocb: Ocb3<Aes128> = Ocb3::new(GenericArray::from_slice(key));
    let mut buffer = Zeroizing::new(ct.to_vec());
    ocb.decrypt_in_place_detached(
        GenericArray::from_slice(nonce),
        &aad,
        &mut buffer,
        GenericArray::from_slice(tag),
    )
    .map_err(|_| Error::KeyDecryptionFailed)?;
    Ok(buffer)
}

fn decrypt_cbc(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    use aes::Aes128;
    use aes::cipher::{BlockDecryptMut, KeyIvInit};

    let cipher = cbc::Decryptor::<Aes128>::new_from_slices(key, iv)
        .map_err(|_| Error::KeyDecryptionFailed)?;
    let mut buffer = Zeroizing::new(ciphertext.to_vec());
    let len = cipher
        .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buffer)
        .map_err(|_| Error::KeyDecryptionFailed)?
        .len();
    buffer.truncate(len);
    Ok(buffer)
}

/// Parse the decrypted `((NAME VALUE)...)` list (followed by a hash and
/// padding for CBC).
fn extract_canonical_mpis(decrypted: &[u8]) -> Result<Vec<(String, Zeroizing<Vec<u8>>)>> {
    let mut mpis = Vec::new();
    let mut parser = CanonicalParser::new(decrypted);
    parser.expect_list_start()?;
    parser.expect_list_start()?;
    while !parser.peek_is_list_end() {
        parser.expect_list_start()?;
        let name = parser.read_atom()?;
        let value = parser.read_atom()?;
        mpis.push((
            String::from_utf8_lossy(name).into_owned(),
            Zeroizing::new(value.to_vec()),
        ));
        parser.expect_list_end()?;
    }
    Ok(mpis)
}

/// The unprotected `(private-key (ALGO ...))` form, for `--no-protection`.
pub fn unprotected(material: &KeyMaterial) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(b"(11:private-key(".to_vec());
    push_atom(&mut out, material.algo.as_bytes());
    if let Some(curve) = &material.curve {
        push_param(&mut out, b"curve", curve.as_bytes());
    }
    if !material.flags.is_empty() {
        out.push(b'(');
        push_atom(&mut out, b"flags");
        for flag in &material.flags {
            push_atom(&mut out, flag.as_bytes());
        }
        out.push(b')');
    }
    for (name, value) in &material.params {
        push_param(&mut out, name.as_bytes(), value);
    }
    out.extend_from_slice(b"))");
    out
}

/// Protect `material` with `passphrase` exactly like gpg-agent's
/// `agent_protect`: OCB over `((secret params))`, with the public
/// parameters and the `protected-at` timestamp as associated data.
#[allow(deprecated)]
pub fn protect(
    material: &KeyMaterial,
    passphrase: &str,
    s2k_count: u64,
) -> Result<Zeroizing<Vec<u8>>> {
    use aes::Aes128;
    use ocb3::Ocb3;
    use ocb3::aead::generic_array::GenericArray;
    use ocb3::aead::{AeadInPlace, KeyInit};

    let secret_names = material.secret_names()?;
    let mut public = vec![b'('];
    push_atom(&mut public, material.algo.as_bytes());
    if let Some(curve) = &material.curve {
        push_param(&mut public, b"curve", curve.as_bytes());
    }
    if !material.flags.is_empty() {
        public.push(b'(');
        push_atom(&mut public, b"flags");
        for flag in &material.flags {
            push_atom(&mut public, flag.as_bytes());
        }
        public.push(b')');
    }
    let mut plain = Zeroizing::new(b"((".to_vec());
    for (name, value) in &material.params {
        if secret_names.contains(&name.as_str()) {
            push_param(&mut plain, name.as_bytes(), value);
        } else {
            push_param(&mut public, name.as_bytes(), value);
        }
    }
    plain.extend_from_slice(b"))");

    let mut protected_at = b"(12:protected-at".to_vec();
    push_atom(
        &mut protected_at,
        iso_timestamp(SystemTime::now()).as_bytes(),
    );
    protected_at.push(b')');

    let mut salt = [0u8; 8];
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let key = derive_s2k_key(passphrase, &salt, s2k_count, 16);

    let aad = [&public[..], &protected_at, b")"].concat();
    let ocb: Ocb3<Aes128> = Ocb3::new(GenericArray::from_slice(&key));
    let tag = ocb
        .encrypt_in_place_detached(GenericArray::from_slice(&nonce), &aad, &mut plain)
        .map_err(|_| Error::SigningFailed)?;
    let mut sealed = plain.to_vec();
    sealed.extend_from_slice(&tag);

    let mut out = Zeroizing::new(b"(21:protected-private-key".to_vec());
    out.extend_from_slice(&public);
    out.extend_from_slice(b"(9:protected20:openpgp-s2k3-ocb-aes((4:sha1");
    push_atom(&mut out, &salt);
    push_atom(&mut out, s2k_count.to_string().as_bytes());
    out.push(b')');
    push_atom(&mut out, &nonce);
    out.push(b')');
    push_atom(&mut out, &sealed);
    out.push(b')');
    out.extend_from_slice(&protected_at);
    out.extend_from_slice(b"))");
    Ok(out)
}

/// Whether a key file is passphrase-protected (as opposed to plain or on a
/// smartcard).
pub fn is_protected(bytes: &[u8]) -> bool {
    key_canonical(bytes)
        .and_then(|canonical| parse_canonical(&canonical))
        .is_ok_and(|root| root.name() == Some(b"protected-private-key"))
}

/// The extended-format text of a key file for `canonical`.
pub fn render_key_file(canonical: &[u8]) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(format!(
        "Created: {}\nKey: {}\n",
        iso_timestamp(SystemTime::now()),
        render_advanced(&parse_canonical(canonical)?)
    )))
}

/// Write a key file in the extended format, mode 0600, atomically. Refuses
/// to replace an existing key unless `force` is set.
pub fn write_key_file(dir: &Path, keygrip: &str, canonical: &[u8], force: bool) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("{keygrip}.key"));
    if !force && path.exists() {
        return Err(Error::KeyExists(keygrip.to_string()));
    }
    let text = render_key_file(canonical)?;
    let tmp = dir.join(format!(".{keygrip}.key.keyoxide-{}", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    let written = file
        .write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::rename(&tmp, &path));
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    Ok(written?)
}

/// `YYYYMMDDTHHMMSS` in UTC, GnuPG's compact ISO time.
fn iso_timestamp(time: SystemTime) -> String {
    let secs = time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use tracing_test::traced_test;

    use super::*;

    const JUNK_PROTECTED_RSA: &str = "Key: (protected-private-key (rsa (n #01#) (e #010001#)
 (protected openpgp-s2k3-sha1-aes-cbc ((sha1 #0001020304050607# \"1\")
 #00000000000000000000000000000000#) #00000000000000000000000000000000#)))
";

    #[test]
    #[traced_test]
    fn protected_key_debug_logs_never_expose_derived_key_material() {
        const PASSPHRASE: &str = "sentinel-passphrase";
        let leaked = hex::encode(&*derive_s2k_key(
            PASSPHRASE,
            &[0, 1, 2, 3, 4, 5, 6, 7],
            1,
            16,
        ));
        let _ = parse_key_file(JUNK_PROTECTED_RSA.as_bytes(), PASSPHRASE);
        assert!(!logs_contain(&leaked));
    }

    #[test]
    fn unfolds_lines_split_inside_tokens() {
        // Real GnuPG 2.5 output folds anywhere, including inside "protected".
        let text = "Created: 20261107T052202\nKey: (protected-private-key (ecc (curve \"NIST P-256\")(q\n  #04AB#)(prote\n cted openpgp-s2k3-ocb-aes ((sha1 #0511209CD38ABEEC#\n  \"131585024\")#83B2#)#82EA11\n 16#)(protected-at \"20261107T052202\")))\n";
        let value = extended_key_value(text).unwrap();
        assert!(
            value.contains("(q #04AB#)(protected openpgp-s2k3-ocb-aes"),
            "{}",
            *value
        );
        assert!(value.contains("#82EA1116#"), "{}", *value);
    }

    #[test]
    fn protect_roundtrips_through_the_reader() {
        let material = KeyMaterial {
            algo: "ecc".into(),
            curve: Some("Curve25519".into()),
            flags: vec!["djb-tweak".into()],
            params: vec![
                (
                    "q".into(),
                    Zeroizing::new([&[0x40][..], &[7u8; 32]].concat()),
                ),
                ("d".into(), Zeroizing::new(vec![9u8; 32])),
            ],
        };
        let canonical = protect(&material, "pw", 1024).unwrap();
        let dir = tempfile::tempdir().unwrap();
        write_key_file(dir.path(), "ABCD", &canonical, false).unwrap();
        assert!(matches!(
            write_key_file(dir.path(), "ABCD", &canonical, false),
            Err(Error::KeyExists(_))
        ));
        let path = dir.path().join("ABCD.key");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let back = read_key_file(&path, "pw").unwrap();
        assert_eq!(back.curve.as_deref(), Some("Curve25519"));
        assert_eq!(back.flags, ["djb-tweak"]);
        assert_eq!(back.get("d"), Some(&[9u8; 32][..]));
        assert_eq!(back.get("q").map(<[u8]>::len), Some(33));
        assert!(matches!(
            read_key_file(&path, "wrong"),
            Err(Error::KeyDecryptionFailed)
        ));
    }

    #[test]
    fn iso_timestamp_formats_utc() {
        let t = UNIX_EPOCH + std::time::Duration::from_secs(1_794_027_967);
        assert_eq!(iso_timestamp(t), "20261107T050607");
    }
}
