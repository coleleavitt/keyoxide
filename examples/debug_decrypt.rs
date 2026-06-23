use std::fs;

use keyoxide::gpg::sexp::{CanonicalParser, parse_gpg_sexp};
use sha1::Sha1;
use sha2::Digest;

fn main() {
    let keyfile =
        "/home/cole/.gnupg/private-keys-v1.d/0C34BD7F15B85CF01FFA4399E50F5C95717D7081.key";
    let passphrase =
        std::env::var("KEYOXIDE_PASSPHRASE").expect("set KEYOXIDE_PASSPHRASE to run this example");

    let content = fs::read_to_string(keyfile).unwrap();
    let sexp_start = content.find("(protected-private-key").unwrap();
    let sexp_content = &content[sexp_start..];

    let sexp = parse_gpg_sexp(sexp_content).unwrap();
    let canonical = sexp.to_canonical();
    println!("Canonical length: {} bytes", canonical.len());

    // Parse and decrypt
    let mut parser = CanonicalParser::new(&canonical);
    parser.expect_list_start().unwrap();
    let _ = parser.read_atom().unwrap(); // "protected-private-key"

    let aad_begin = parser.position();
    parser.expect_list_start().unwrap();
    let algo = parser.read_atom().unwrap();
    println!("Algorithm: {:?}", String::from_utf8_lossy(algo));

    // Find protected section
    let mut hole_begin = 0;
    let mut hole_end = 0;
    let mut salt = [0u8; 8];
    let mut s2k_count = 0u64;
    let mut nonce = Vec::new();
    let mut ciphertext = Vec::new();

    while !parser.peek_is_list_end() {
        let item_start = parser.position();

        if parser.peek_is_list() {
            parser.expect_list_start().unwrap();

            if !parser.peek_is_list_end() && !parser.peek_is_list() {
                let name = parser.read_atom().unwrap();

                if name == b"protected" {
                    hole_begin = item_start;
                    let _ = parser.read_atom().unwrap(); // method

                    parser.expect_list_start().unwrap();
                    parser.expect_list_start().unwrap();
                    let _ = parser.read_atom().unwrap(); // sha1

                    let salt_data = parser.read_atom().unwrap();
                    salt.copy_from_slice(salt_data);

                    let count_str = parser.read_atom().unwrap();
                    s2k_count = std::str::from_utf8(count_str).unwrap().parse().unwrap();

                    parser.expect_list_end().unwrap();
                    nonce = parser.read_atom().unwrap().to_vec();
                    parser.expect_list_end().unwrap();
                    ciphertext = parser.read_atom().unwrap().to_vec();
                }
            }

            while !parser.peek_is_list_end() {
                parser.skip_sexp().unwrap();
            }
            parser.expect_list_end().unwrap();

            if hole_begin == item_start {
                hole_end = parser.position();
            }
        } else {
            parser.skip_sexp().unwrap();
        }
    }

    parser.expect_list_end().unwrap();
    let aad_end = parser.position();

    let aad1 = &canonical[aad_begin..hole_begin];
    let aad2 = &canonical[hole_end..aad_end];

    println!("AAD1: {} bytes", aad1.len());
    println!("AAD2: {} bytes", aad2.len());
    println!("Ciphertext: {} bytes", ciphertext.len());

    // Derive key
    let key = derive_s2k_key(&passphrase, &salt, s2k_count, 16);
    println!("Key: {}", hex::encode(&key));

    // Decrypt
    use aes::Aes128;
    use ocb3::Ocb3;
    use ocb3::aead::generic_array::GenericArray;
    use ocb3::aead::{AeadInPlace, KeyInit};

    let key_arr: &GenericArray<u8, _> = GenericArray::from_slice(&key);
    let ocb: Ocb3<Aes128> = Ocb3::new(key_arr);

    let mut aad = Vec::with_capacity(aad1.len() + aad2.len());
    aad.extend_from_slice(aad1);
    aad.extend_from_slice(aad2);

    let tag_start = ciphertext.len() - 16;
    let mut buffer = ciphertext[..tag_start].to_vec();
    let tag = &ciphertext[tag_start..];

    let nonce_arr = GenericArray::from_slice(&nonce);
    let tag_arr = GenericArray::from_slice(tag);

    ocb.decrypt_in_place_detached(nonce_arr, &aad, &mut buffer, tag_arr)
        .unwrap();

    println!("\nDecrypted ({} bytes):", buffer.len());
    println!("First 200 bytes:");
    for (i, b) in buffer.iter().take(200).enumerate() {
        if *b >= 32 && *b < 127 {
            print!("{}", *b as char);
        } else {
            print!("\\x{:02x}", b);
        }
        if (i + 1) % 80 == 0 {
            println!();
        }
    }
    println!("\n");

    // Parse the decrypted canonical S-expression
    println!("Parsing decrypted data as canonical S-expression:");
    let mut dec_parser = CanonicalParser::new(&buffer);
    dec_parser.expect_list_start().unwrap();
    dec_parser.expect_list_start().unwrap();

    while !dec_parser.peek_is_list_end() {
        dec_parser.expect_list_start().unwrap();
        let name = dec_parser.read_atom().unwrap();
        let value = dec_parser.read_atom().unwrap();
        println!("  {}: {} bytes", String::from_utf8_lossy(name), value.len());
        dec_parser.expect_list_end().unwrap();
    }
}

fn derive_s2k_key(passphrase: &str, salt: &[u8; 8], count: u64, key_len: usize) -> Vec<u8> {
    let mut result = vec![0u8; key_len];
    let pass_bytes = passphrase.as_bytes();

    let salted_len = salt.len() + pass_bytes.len();
    let mut salted = vec![0u8; salted_len];
    salted[..8].copy_from_slice(salt);
    salted[8..].copy_from_slice(pass_bytes);

    let total_bytes = count.max(salted_len as u64) as usize;

    let mut prefix_byte = 0u8;
    let mut key_offset = 0;

    while key_offset < key_len {
        let mut hasher = Sha1::new();

        for _ in 0..prefix_byte {
            hasher.update([0u8]);
        }

        let mut hashed = 0;
        while hashed < total_bytes {
            let chunk_len = salted_len.min(total_bytes - hashed);
            hasher.update(&salted[..chunk_len]);
            hashed += chunk_len;
        }

        let digest = hasher.finalize();
        let copy_len = (key_len - key_offset).min(digest.len());
        result[key_offset..key_offset + copy_len].copy_from_slice(&digest[..copy_len]);
        key_offset += copy_len;
        prefix_byte += 1;
    }

    result
}
