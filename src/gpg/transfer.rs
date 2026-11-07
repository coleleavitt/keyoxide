//! `(openpgp-private-key ...)`: the form `gpg --import` hands the agent a
//! secret key in (`g10/import.c`), still under its OpenPGP passphrase
//! protection. Converted the way `agent/cvt-openpgp.c` does.

use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use rand::RngCore;
use sha1::{Digest, Sha1};
use sha2::{Sha256, Sha384, Sha512};
use zeroize::Zeroizing;

use super::curve::Curve;
use super::keyfile::{KeyMaterial, s2k_iterated};
use super::keygen::std_mpi;
use super::sexp::{SexpNode, push_atom};
use crate::error::{Error, Result};

/// Convert a transfer key. `passphrase` unlocks OpenPGP-protected secrets;
/// a wrong one yields `Error::BadPassphrase` so the caller can try another.
pub fn convert(root: &SexpNode, passphrase: &str) -> Result<KeyMaterial> {
    let field = |name: &str| -> Option<&[SexpNode]> {
        root.as_list()?
            .iter()
            .find(|item| item.name() == Some(name.as_bytes()))?
            .as_list()
    };
    let version =
        atom_text(field("version").and_then(|l| l.get(1))).ok_or(Error::MissingField("version"))?;
    if version != "4" && version != "5" {
        return Err(Error::UnsupportedKeyType(format!(
            "OpenPGP key version {version}"
        )));
    }
    let algo = atom_text(field("algo").and_then(|l| l.get(1)))
        .ok_or(Error::MissingField("algo"))?
        .to_ascii_lowercase();
    let (curve, public_names, secret_names): (Option<Curve>, &[&str], &[&str]) = match algo.as_str()
    {
        "rsa" => (None, &["n", "e"], &["d", "p", "q", "u"]),
        "ecc" | "ecdsa" | "eddsa" | "ecdh" => {
            let name = atom_text(field("curve").and_then(|l| l.get(1)))
                .ok_or(Error::MissingField("curve"))?;
            let curve = Curve::from_name(&name)
                .ok_or_else(|| Error::UnsupportedKeyType(format!("curve {name}")))?;
            (Some(curve), &["q"], &["d"])
        }
        other => return Err(Error::UnsupportedKeyType(format!("algorithm {other}"))),
    };

    // (skey _ PUB _ PUB ... e ENCRYPTED) or with plain `_ SECRET` values.
    let skey = field("skey").ok_or(Error::MissingField("skey"))?;
    let mut values = Vec::new();
    for pair in skey[1..].chunks(2) {
        let [tag, value] = pair else {
            return Err(Error::SexpParse("odd skey list".into()));
        };
        let (Some(tag), Some(value)) = (tag.as_atom(), value.as_atom()) else {
            return Err(Error::SexpParse("bad skey item".into()));
        };
        values.push((tag == b"e", value));
    }
    if values.len() <= public_names.len()
        || values[..public_names.len()].iter().any(|(enc, _)| *enc)
    {
        return Err(Error::SexpParse("public parameters missing".into()));
    }

    let protection = field("protection").ok_or(Error::MissingField("protection"))?;
    let mode = atom_text(protection.get(1)).ok_or(Error::MissingField("protection"))?;
    let secrets: Vec<Zeroizing<Vec<u8>>> = if mode == "none" {
        values[public_names.len()..]
            .iter()
            .map(|(_, v)| Zeroizing::new(v.to_vec()))
            .collect()
    } else {
        let (true, blob) = values[public_names.len()] else {
            return Err(Error::SexpParse(
                "protected key without encrypted part".into(),
            ));
        };
        let plain = decrypt_protected(protection, &mode, blob, passphrase)?;
        read_mpis(&plain, secret_names.len())?
    };
    if secrets.len() != secret_names.len() {
        return Err(Error::SexpParse("wrong number of secret parameters".into()));
    }

    let mut params: Vec<(String, Zeroizing<Vec<u8>>)> = public_names
        .iter()
        .zip(&values)
        .map(|(name, (_, v))| ((*name).to_string(), Zeroizing::new(v.to_vec())))
        .collect();
    for (name, value) in secret_names.iter().zip(secrets) {
        // RSA values are written like libgcrypt's %m (signed STD format);
        // ECC values are opaque bytes and stay as they are.
        let value = if curve.is_none() {
            std_mpi(&value)
        } else {
            value
        };
        params.push(((*name).to_string(), value));
    }
    Ok(KeyMaterial {
        algo: if curve.is_some() {
            "ecc".into()
        } else {
            "rsa".into()
        },
        curve: curve.map(|c| c.name().to_string()),
        flags: curve.map_or_else(Vec::new, |c| {
            c.flags().iter().map(ToString::to_string).collect()
        }),
        params,
    })
}

/// Coded S2K count 255 (65011712 bytes), what gpg-agent uses for exports
/// with its calibrated count (`get_standard_s2k_count_rfc4880`).
const EXPORT_S2K_CODED: u64 = 255;

/// Build the transfer key gpg-agent returns for `EXPORT_KEY --openpgp`
/// (`convert_to_openpgp`): the secret values as OpenPGP MPIs plus a SHA-1,
/// encrypted with AES-128-CFB under an iterated SHA-1 S2K of `passphrase`.
/// The result is padded with zeros to a multiple of 8 for AES key wrap.
pub fn to_openpgp(material: &KeyMaterial, passphrase: &str) -> Result<Zeroizing<Vec<u8>>> {
    let (public_names, secret_names): (&[&str], &[&str]) = if material.algo == "rsa" {
        (&["n", "e"], &["d", "p", "q", "u"])
    } else {
        (&["q"], &["d"])
    };

    let mut plain = Zeroizing::new(Vec::new());
    for name in secret_names {
        let value = material
            .get(name)
            .ok_or_else(|| Error::MissingField("secret parameter"))?;
        let start = value.iter().position(|&b| b != 0).unwrap_or(value.len());
        let digits = &value[start..];
        let bits = digits.first().map_or(0, |b| {
            (digits.len() - 1) * 8 + (8 - b.leading_zeros() as usize)
        });
        plain.extend_from_slice(
            &u16::try_from(bits)
                .map_err(|_| Error::InvalidMessageFormat)?
                .to_be_bytes(),
        );
        plain.extend_from_slice(digits);
    }
    let checksum = Sha1::digest(&*plain);
    plain.extend_from_slice(&checksum);

    let mut iv = [0u8; 16];
    let mut salt = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut iv);
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let mut salted = Zeroizing::new(salt.to_vec());
    salted.extend_from_slice(passphrase.as_bytes());
    let key = s2k_iterated::<Sha1>(&salted, decode_s2k_count(EXPORT_S2K_CODED), 16);
    cfb_mode::Encryptor::<aes::Aes128>::new_from_slices(&key, &iv)
        .map_err(|_| Error::InvalidMessageFormat)?
        .encrypt(&mut plain);

    let mut out = Zeroizing::new(b"(19:openpgp-private-key(7:version1:4)(4:algo".to_vec());
    push_atom(&mut out, material.algo.as_bytes());
    out.push(b')');
    if let Some(curve) = &material.curve {
        out.extend_from_slice(b"(5:curve");
        push_atom(&mut out, curve.as_bytes());
        out.push(b')');
    }
    out.extend_from_slice(b"(4:skey");
    for name in public_names {
        out.extend_from_slice(b"1:_");
        push_atom(
            &mut out,
            material
                .get(name)
                .ok_or(Error::MissingField("public parameter"))?,
        );
    }
    out.extend_from_slice(b"1:e");
    push_atom(&mut out, &plain);
    out.extend_from_slice(b")(10:protection4:sha13:aes");
    push_atom(&mut out, &iv);
    out.extend_from_slice(b"1:34:sha1");
    push_atom(&mut out, &salt);
    push_atom(&mut out, EXPORT_S2K_CODED.to_string().as_bytes());
    out.extend_from_slice(b"))");
    while out.len() % 8 != 0 || out.len() < 16 {
        out.push(0);
    }
    Ok(out)
}

fn atom_text(node: Option<&SexpNode>) -> Option<String> {
    node.and_then(SexpNode::as_atom)
        .map(|a| String::from_utf8_lossy(a).into_owned())
}

/// `(protection sha1|sum CIPHER IV S2KMODE S2KHASH SALT COUNT)`: OpenPGP
/// secret-key encryption with plain CFB and a SHA-1 or 16-bit checksum.
fn decrypt_protected(
    protection: &[SexpNode],
    mode: &str,
    blob: &[u8],
    passphrase: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let atom = |i: usize| {
        protection
            .get(i)
            .and_then(SexpNode::as_atom)
            .ok_or(Error::MissingField("protection"))
    };
    let text = |i: usize| atom(i).map(|a| String::from_utf8_lossy(a).to_ascii_lowercase());
    let cipher = text(2)?;
    let iv = atom(3)?;
    let s2k_mode = text(4)?;
    let hash = text(5)?;
    let salt = atom(6)?;
    let count: u64 = text(7)?
        .parse()
        .map_err(|_| Error::SexpParse("bad S2K count".into()))?;

    let key_len = match cipher.as_str() {
        "aes" | "aes128" => 16,
        "aes192" => 24,
        "aes256" => 32,
        other => {
            return Err(Error::UnsupportedAlgorithm(format!(
                "protection cipher {other}"
            )));
        }
    };
    let mut salted = Zeroizing::new(Vec::new());
    let byte_count = match s2k_mode.as_str() {
        "0" => 0,
        "1" | "3" => {
            salted.extend_from_slice(salt);
            if s2k_mode == "3" {
                decode_s2k_count(count)
            } else {
                0
            }
        }
        other => return Err(Error::UnsupportedAlgorithm(format!("S2K mode {other}"))),
    };
    salted.extend_from_slice(passphrase.as_bytes());
    let key = match hash.as_str() {
        "sha1" => s2k_iterated::<Sha1>(&salted, byte_count, key_len),
        "sha256" => s2k_iterated::<Sha256>(&salted, byte_count, key_len),
        "sha384" => s2k_iterated::<Sha384>(&salted, byte_count, key_len),
        "sha512" => s2k_iterated::<Sha512>(&salted, byte_count, key_len),
        other => return Err(Error::UnsupportedAlgorithm(format!("S2K hash {other}"))),
    };

    let mut plain = Zeroizing::new(blob.to_vec());
    let bad = |_| Error::UnsupportedAlgorithm("protection IV length".into());
    match key_len {
        16 => cfb_mode::Decryptor::<aes::Aes128>::new_from_slices(&key, iv)
            .map_err(bad)?
            .decrypt(&mut plain),
        24 => cfb_mode::Decryptor::<aes::Aes192>::new_from_slices(&key, iv)
            .map_err(bad)?
            .decrypt(&mut plain),
        _ => cfb_mode::Decryptor::<aes::Aes256>::new_from_slices(&key, iv)
            .map_err(bad)?
            .decrypt(&mut plain),
    }

    let body_len = if mode == "sha1" {
        let body = plain.len().checked_sub(20).ok_or(Error::BadPassphrase)?;
        if Sha1::digest(&plain[..body])[..] != plain[body..] {
            return Err(Error::BadPassphrase);
        }
        body
    } else {
        let body = plain.len().checked_sub(2).ok_or(Error::BadPassphrase)?;
        let sum = plain[..body]
            .iter()
            .fold(0u16, |acc, &b| acc.wrapping_add(u16::from(b)));
        if sum.to_be_bytes()[..] != plain[body..] {
            return Err(Error::BadPassphrase);
        }
        body
    };
    plain.truncate(body_len);
    Ok(plain)
}

/// OpenPGP coded S2K iteration count (RFC 4880 section 3.7.1.3).
fn decode_s2k_count(coded: u64) -> u64 {
    if coded > 255 {
        return coded;
    }
    (16 + (coded & 15)) << ((coded >> 4) + 6)
}

/// Read `n` OpenPGP MPIs (2-byte bit count, then the bytes).
fn read_mpis(mut data: &[u8], n: usize) -> Result<Vec<Zeroizing<Vec<u8>>>> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let [hi, lo, rest @ ..] = data else {
            return Err(Error::BadPassphrase);
        };
        let len = usize::from(u16::from_be_bytes([*hi, *lo])).div_ceil(8);
        if rest.len() < len {
            return Err(Error::BadPassphrase);
        }
        out.push(Zeroizing::new(rest[..len].to_vec()));
        data = &rest[len..];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpg::sexp::parse_gpg_sexp;

    #[test]
    fn coded_s2k_counts_decode() {
        assert_eq!(decode_s2k_count(96), 65_536);
        assert_eq!(decode_s2k_count(255), 65_011_712);
        assert_eq!(decode_s2k_count(131_585_024), 131_585_024);
    }

    #[test]
    fn unprotected_ed25519_transfer_key_converts() {
        let text = "(openpgp-private-key (version \"4\") (algo eddsa) (curve Ed25519)
            (skey _ #40AABB# _ #0102#) (csum \"0\") (protection none))";
        let material = convert(&parse_gpg_sexp(text).unwrap(), "unused").unwrap();
        assert_eq!(material.algo, "ecc");
        assert_eq!(material.curve.as_deref(), Some("Ed25519"));
        assert_eq!(material.flags, ["eddsa"]);
        assert_eq!(material.get("q"), Some(&[0x40, 0xAA, 0xBB][..]));
        assert_eq!(material.get("d"), Some(&[1, 2][..]));
    }

    #[test]
    fn export_roundtrips_through_import() {
        use crate::gpg::sexp::{canonical_len, parse_canonical};
        for param in [
            "(genkey(ecc(curve 7:Ed25519)(flags eddsa)))",
            "(genkey(ecc(curve 10:Curve25519)(flags djb-tweak)))",
            "(genkey(rsa(nbits 4:2048)))",
        ] {
            let material = crate::gpg::keygen::generate(&parse_gpg_sexp(param).unwrap()).unwrap();
            let exported = to_openpgp(&material, "pw").unwrap();
            assert_eq!(exported.len() % 8, 0);
            let root = parse_canonical(&exported[..canonical_len(&exported).unwrap()]).unwrap();
            assert!(
                matches!(convert(&root, "nope"), Err(Error::BadPassphrase)),
                "{param}"
            );
            let back = convert(&root, "pw").unwrap();
            for (name, value) in &material.params {
                let strip = |v: &[u8]| {
                    v.iter()
                        .skip_while(|b| **b == 0)
                        .copied()
                        .collect::<Vec<_>>()
                };
                assert_eq!(
                    strip(back.get(name).unwrap()),
                    strip(value),
                    "{param} {name}"
                );
            }
        }
    }

    #[test]
    fn protected_transfer_key_rejects_wrong_passphrase() {
        // A SHA-1-checked blob that cannot decrypt to a matching digest.
        let text = "(openpgp-private-key (version \"4\") (algo eddsa) (curve Ed25519)
            (skey _ #40AABB# e #00112233445566778899AABBCCDDEEFF0011223344556677#)
            (csum \"0\")
            (protection sha1 aes #000102030405060708090A0B0C0D0E0F# \"3\" sha256 #0102030405060708# \"96\"))";
        let err = convert(&parse_gpg_sexp(text).unwrap(), "wrong").unwrap_err();
        assert!(matches!(err, Error::BadPassphrase), "{err}");
    }
}
