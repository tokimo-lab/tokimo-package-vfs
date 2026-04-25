//! Crypto primitives needed for NTLMv2:
//! * MD4 and MD5 hashing (via the `md4` / `md-5` crates)
//! * HMAC-MD5
//! * RC4 (RFC 6229) — implemented inline to avoid a dedicated crate.

use hmac::{Hmac, Mac};
use md4::{Digest, Md4};
use md5::Md5;
use sha2::digest::KeyInit;

type HmacMd5 = Hmac<Md5>;

/// MD4 of `data`.
pub fn md4(data: &[u8]) -> [u8; 16] {
    let mut h = Md4::new();
    h.update(data);
    h.finalize().into()
}

/// MD5 of `data` (single-shot). Currently unused but kept as a primitive.
#[allow(dead_code)]
pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(data);
    h.finalize().into()
}

/// HMAC-MD5 of `data` keyed with `key`.
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = <HmacMd5 as KeyInit>::new_from_slice(key).expect("HMAC-MD5 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// HMAC-MD5 of two concatenated buffers, avoiding an intermediate allocation.
pub fn hmac_md5_concat(key: &[u8], a: &[u8], b: &[u8]) -> [u8; 16] {
    let mut mac = <HmacMd5 as KeyInit>::new_from_slice(key).expect("HMAC-MD5 accepts any key length");
    mac.update(a);
    mac.update(b);
    mac.finalize().into_bytes().into()
}

/// In-place RC4 keystream encryption/decryption.
pub fn rc4(key: &[u8], data: &mut [u8]) {
    let mut s: [u8; 256] = [0; 256];
    for (i, slot) in s.iter_mut().enumerate() {
        *slot = i as u8;
    }
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let mut i: u8 = 0;
    let mut j: u8 = 0;
    for byte in data.iter_mut() {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
        *byte ^= k;
    }
}

/// Encode an ASCII string as UTF-16 little-endian bytes.
pub fn utf16_le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// Encode `s` upper-cased, as UTF-16 LE.
pub fn utf16_le_upper(s: &str) -> Vec<u8> {
    s.to_uppercase().encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6229 test vector: key=0102030405, plaintext=zeros[16] →
    /// keystream b2 39 63 05 f0 3d c0 27 cc c3 52 4a 0a 11 18 a8.
    #[test]
    fn rc4_rfc6229_vector() {
        let key = [0x01, 0x02, 0x03, 0x04, 0x05];
        let mut buf = [0u8; 16];
        rc4(&key, &mut buf);
        assert_eq!(
            buf,
            [
                0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27, 0xcc, 0xc3, 0x52, 0x4a, 0x0a, 0x11, 0x18, 0xa8
            ]
        );
    }

    /// RFC 1321 MD5 test: MD5("") = d41d8cd98f00b204e9800998ecf8427e.
    #[test]
    fn md5_empty() {
        assert_eq!(
            md5(b""),
            [0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e]
        );
    }
}
