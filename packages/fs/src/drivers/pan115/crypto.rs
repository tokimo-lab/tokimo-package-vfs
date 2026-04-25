use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use num_bigint::BigUint;
use rand_core::{OsRng, RngCore};

use tokimo_vfs_core::error::{TokimoVfsError, Result};

const XOR_KEY_SEED: [u8; 144] = [
    0xf0, 0xe5, 0x69, 0xae, 0xbf, 0xdc, 0xbf, 0x8a, 0x1a, 0x45, 0xe8, 0xbe, 0x7d, 0xa6, 0x73, 0xb8, 0xde, 0x8f, 0xe7,
    0xc4, 0x45, 0xda, 0x86, 0xc4, 0x9b, 0x64, 0x8b, 0x14, 0x6a, 0xb4, 0xf1, 0xaa, 0x38, 0x01, 0x35, 0x9e, 0x26, 0x69,
    0x2c, 0x86, 0x00, 0x6b, 0x4f, 0xa5, 0x36, 0x34, 0x62, 0xa6, 0x2a, 0x96, 0x68, 0x18, 0xf2, 0x4a, 0xfd, 0xbd, 0x6b,
    0x97, 0x8f, 0x4d, 0x8f, 0x89, 0x13, 0xb7, 0x6c, 0x8e, 0x93, 0xed, 0x0e, 0x0d, 0x48, 0x3e, 0xd7, 0x2f, 0x88, 0xd8,
    0xfe, 0xfe, 0x7e, 0x86, 0x50, 0x95, 0x4f, 0xd1, 0xeb, 0x83, 0x26, 0x34, 0xdb, 0x66, 0x7b, 0x9c, 0x7e, 0x9d, 0x7a,
    0x81, 0x32, 0xea, 0xb6, 0x33, 0xde, 0x3a, 0xa9, 0x59, 0x34, 0x66, 0x3b, 0xaa, 0xba, 0x81, 0x60, 0x48, 0xb9, 0xd5,
    0x81, 0x9c, 0xf8, 0x6c, 0x84, 0x77, 0xff, 0x54, 0x78, 0x26, 0x5f, 0xbe, 0xe8, 0x1e, 0x36, 0x9f, 0x34, 0x80, 0x5c,
    0x45, 0x2c, 0x9b, 0x76, 0xd5, 0x1b, 0x8f, 0xcc, 0xc3, 0xb8, 0xf5,
];

const XOR_CLIENT_KEY: [u8; 12] = [0x78, 0x06, 0xad, 0x4c, 0x33, 0x86, 0x5d, 0x18, 0x4c, 0x01, 0x3f, 0x46];

const RSA_MODULUS_HEX: &str = concat!(
    "8686980c0f5a24c4b9d43020cd2c22703ff3f450756529058b1cf88f09b86021",
    "36477198a6e2683149659bd122c33592fdb5ad47944ad1ea4d36c6b172aad633",
    "8c3bb6ac6227502d010993ac967d1aef00f0c8e038de2e4d3bc2ec368af2e9f1",
    "0a6f1eda4f7262f136420c07c331b871bf139f74f3010e3c4fe57df3afb71683",
);

const RSA_EXPONENT_HEX: &str = "10001";
const KEY_LEN: usize = 128;

pub fn generate_key() -> [u8; 16] {
    let mut key = [0_u8; 16];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn encode_payload(input: &[u8], key: &[u8; 16]) -> String {
    let mut buf = vec![0_u8; 16 + input.len()];
    buf[..16].copy_from_slice(key);
    buf[16..].copy_from_slice(input);

    xor_transform(&mut buf[16..], &xor_derive_key(key, 4));
    buf[16..].reverse();
    xor_transform(&mut buf[16..], &XOR_CLIENT_KEY);

    BASE64_STANDARD.encode(rsa_cipher(&buf))
}

pub fn decode_payload(input: &str, key: &[u8; 16]) -> Result<Vec<u8>> {
    let decoded = BASE64_STANDARD
        .decode(input)
        .map_err(|err| TokimoVfsError::Other(format!("pan115 decode base64 failed: {err}")))?;
    let decrypted = rsa_cipher(&decoded);
    if decrypted.len() < 16 {
        return Err(TokimoVfsError::Other(
            "pan115 decode payload is shorter than key size".into(),
        ));
    }

    let mut output = decrypted[16..].to_vec();
    xor_transform(&mut output, &xor_derive_key(&decrypted[..16], 12));
    output.reverse();
    xor_transform(&mut output, &xor_derive_key(key, 4));
    Ok(output)
}

fn xor_derive_key(seed: &[u8], size: usize) -> Vec<u8> {
    let mut key = vec![0_u8; size];
    for index in 0..size {
        key[index] = seed[index].wrapping_add(XOR_KEY_SEED[size * index]);
        key[index] ^= XOR_KEY_SEED[size * (size - index - 1)];
    }
    key
}

fn xor_transform(data: &mut [u8], key: &[u8]) {
    let key_len = key.len();
    let prefix = data.len() % 4;
    for index in 0..prefix {
        data[index] ^= key[index % key_len];
    }
    for index in prefix..data.len() {
        data[index] ^= key[(index - prefix) % key_len];
    }
}

fn rsa_cipher(input: &[u8]) -> Vec<u8> {
    let modulus = BigUint::parse_bytes(RSA_MODULUS_HEX.as_bytes(), 16).expect("pan115 modulus must be valid hex");
    let exponent = BigUint::parse_bytes(RSA_EXPONENT_HEX.as_bytes(), 16).expect("pan115 exponent must be valid hex");

    let mut output = Vec::new();
    for chunk in input.chunks(KEY_LEN - 11) {
        if chunk.is_empty() {
            continue;
        }

        let block = if input.len() > KEY_LEN {
            rsa_encrypt_block(chunk, &modulus, &exponent)
        } else if input.len().is_multiple_of(KEY_LEN) && chunk.len() == KEY_LEN {
            rsa_decrypt_block(chunk, &modulus, &exponent)
        } else {
            rsa_encrypt_block(chunk, &modulus, &exponent)
        };
        output.extend(block);
    }

    if input.len().is_multiple_of(KEY_LEN) {
        let mut decrypted = Vec::new();
        for chunk in input.chunks(KEY_LEN) {
            decrypted.extend(rsa_decrypt_block(chunk, &modulus, &exponent));
        }
        return decrypted;
    }

    output
}

fn rsa_encrypt_block(chunk: &[u8], modulus: &BigUint, exponent: &BigUint) -> Vec<u8> {
    let pad_size = KEY_LEN - chunk.len() - 3;
    let mut padded = vec![0_u8; KEY_LEN];
    padded[1] = 2;

    let mut random = vec![0_u8; pad_size];
    OsRng.fill_bytes(&mut random);
    for (index, byte) in random.into_iter().enumerate() {
        padded[2 + index] = byte % 0xff + 1;
    }
    padded[pad_size + 2] = 0;
    padded[pad_size + 3..].copy_from_slice(chunk);

    let encrypted = BigUint::from_bytes_be(&padded).modpow(exponent, modulus);
    let bytes = encrypted.to_bytes_be();
    if bytes.len() >= KEY_LEN {
        return bytes;
    }

    let mut output = vec![0_u8; KEY_LEN - bytes.len()];
    output.extend(bytes);
    output
}

fn rsa_decrypt_block(chunk: &[u8], modulus: &BigUint, exponent: &BigUint) -> Vec<u8> {
    let decrypted = BigUint::from_bytes_be(chunk).modpow(exponent, modulus);
    let bytes = decrypted.to_bytes_be();
    for index in 1..bytes.len() {
        if bytes[index] == 0 {
            return bytes[index + 1..].to_vec();
        }
    }
    Vec::new()
}
