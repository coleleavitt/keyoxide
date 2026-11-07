//! Keygrips: the 20-byte names gpg uses for agent keys, computed as
//! libgcrypt's `gcry_pk_get_keygrip` does (`cipher/rsa.c`, `cipher/ecc.c`).

use sha1::{Digest, Sha1};

use super::curve::Curve;
use super::keyfile::KeyMaterial;
use crate::error::{Error, Result};

/// The keygrip as upper-case hex, the key file's name.
pub fn keygrip_hex(material: &KeyMaterial) -> Result<String> {
    Ok(hex::encode_upper(keygrip(material)?))
}

pub fn keygrip(material: &KeyMaterial) -> Result<[u8; 20]> {
    match material.algo.as_str() {
        // SHA-1 of the `n` atom exactly as stored (with its sign byte).
        "rsa" => {
            let n = material.get("n").ok_or(Error::MissingField("n"))?;
            Ok(Sha1::digest(n).into())
        }
        "ecc" | "ecdsa" | "eddsa" | "ecdh" => {
            let name = material
                .curve
                .as_deref()
                .ok_or(Error::MissingField("curve"))?;
            let curve = Curve::from_name(name)
                .ok_or_else(|| Error::UnsupportedKeyType(format!("curve {name}")))?;
            let q = material.get("q").ok_or(Error::MissingField("q"))?;
            Ok(ecc_keygrip(curve, q))
        }
        other => Err(Error::UnsupportedKeyType(format!("algorithm {other}"))),
    }
}

/// SHA-1 over `(1:p..)(1:a..)(1:b..)(1:g..)(1:n..)(1:q..)`: curve values as
/// minimal magnitudes, `g` as `04 || gx || gy`, and `q` raw except that the
/// 0x40 prefix of an Ed25519 or Curve25519 point is dropped.
fn ecc_keygrip(curve: Curve, q: &[u8]) -> [u8; 20] {
    let [p, a, b, n, gx, gy] = curve.domain();
    let g = format!("04{gx}{gy}");
    let compact = matches!(curve, Curve::Ed25519 | Curve::Curve25519)
        && q.len() % 2 == 1
        && q.first() == Some(&0x40);
    let q = if compact { &q[1..] } else { q };

    let mut hasher = Sha1::new();
    let mut put = |name: char, value: &[u8]| {
        hasher.update(format!("(1:{name}{}:", value.len()));
        hasher.update(value);
        hasher.update(b")");
    };
    for (name, hex_value) in [('p', p), ('a', a), ('b', b), ('g', g.as_str()), ('n', n)] {
        let bytes = hex::decode(hex_value).expect("curve constants are valid hex");
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
        put(name, &bytes[start..]);
    }
    put('q', q);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::*;

    /// (curve or "rsa", public q or n as stored, keygrip) from keys made by
    /// GnuPG 2.5.20 with libgcrypt.
    const VECTORS: &[(&str, &str, &str)] = &[
        (
            "NIST P-256",
            "04EF33A60A2BA82D1B45DC48F08536F5F37038C01450FAA8F68AEDD09195DE2B820EF96CF32C613D29A6D0F85A96DC60382E2CC4392DFBCF1ED1FD4C4C97D0A6DE",
            "8DA449D9A81B0FFE7CA010BA3413B1D6EFD43296",
        ),
        (
            "rsa",
            "00E42036431C675001C05520E023498EEA93D341DFB640351589CF23B63B079B87C1FCB23AF340DF219B8D2407CC5BF90B3884D52F0CC485E5D19827874926C3C7CFCEB7CEC73C2825C47AE03A6FF601A26EC98C9E4F7469A5435C1F9218BBE42C005D02D28715F4CF55C9C722F041E24424C7539873BFDB4FA867B06E478D7C49F5251503F5051FF1B413D70C7C300C488A8635BE8E1211FAD496537EDF66C8F5D955609E225A7A41E5A812E9987623D9308CAC2DA2FBC1BB2AA196E6306992FCFF55089A7E25B1FBC09F9911AA6F73540614F63CB06B3DFEB326F6427ACDEE536E611C85E61BECB5CA7C95AC4297280282EB63EC2AD7B2E4E66086A3BD541EFB",
            "A7D46A3B35FDF6FA2B0C36A47348F7C6FC08C4A1",
        ),
        (
            "Ed25519",
            "403936C6F355F661A614D05ED863759E52E798C8A7DC83EBAC8F46B34DB1FB9381",
            "D8FD054085A8F37DB5A9F0F11A2232492BD22A0F",
        ),
        (
            "Curve25519",
            "40E0F45DE8F199035BEA345096060E9C48B24309105286E8E646D19DC526BFC97A",
            "E5C792BC47889F55D4E7755A8658984F4121FFDE",
        ),
        (
            "NIST P-256",
            "04C2060A345E0BA0E6991FCE248D531DE216D38896C1AD6179E584802D369E31A66FA897DF6EBE59DF9E9A24D478228E847E70C3B2FF3FD752D08699E2F772AA3C",
            "FFDDE540BE6FCC7211215A4C6826CA48ED44BFD1",
        ),
    ];

    #[test]
    fn keygrips_match_gnupg() {
        for (curve, public, expected) in VECTORS {
            let rsa = *curve == "rsa";
            let material = KeyMaterial {
                algo: if rsa { "rsa" } else { "ecc" }.into(),
                curve: (!rsa).then(|| (*curve).to_string()),
                flags: Vec::new(),
                params: vec![(
                    if rsa { "n" } else { "q" }.into(),
                    Zeroizing::new(hex::decode(public).unwrap()),
                )],
            };
            assert_eq!(keygrip_hex(&material).unwrap(), *expected, "{curve}");
        }
    }
}
