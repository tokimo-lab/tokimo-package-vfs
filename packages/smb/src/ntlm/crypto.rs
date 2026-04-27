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
            [
                0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e
            ]
        );
    }

    /// RFC 1320 MD4 test: MD4("abc") = a448017aaf21d8525fc10ae87aa6729d.
    #[test]
    fn md4_abc() {
        assert_eq!(
            md4(b"abc"),
            [
                0xa4, 0x48, 0x01, 0x7a, 0xaf, 0x21, 0xd8, 0x52, 0x5f, 0xc1, 0x0a, 0xe8, 0x7a, 0xa6, 0x72, 0x9d
            ]
        );
    }

    /// RFC 2202 §2 test case 1: HMAC-MD5(key=0x0b×16, "Hi There")
    /// = 9294727a3638bb1c13f48ef8158bfc9d.
    #[test]
    fn hmac_md5_rfc2202_case1() {
        let key = [0x0b; 16];
        assert_eq!(
            hmac_md5(&key, b"Hi There"),
            [
                0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c, 0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b, 0xfc, 0x9d
            ]
        );
    }

    /// `hmac_md5_concat(k, a, b)` must match `hmac_md5(k, a || b)`.
    #[test]
    fn hmac_md5_concat_matches_singleshot() {
        let key = b"the-key-doesnt-have-to-be-16b";
        let a = b"hello, ";
        let b = b"world!";
        let mut combined = Vec::new();
        combined.extend_from_slice(a);
        combined.extend_from_slice(b);
        assert_eq!(hmac_md5_concat(key, a, b), hmac_md5(key, &combined));
    }

    /// RC4 is its own inverse: encrypting then decrypting must round-trip.
    #[test]
    fn rc4_round_trip() {
        let key = b"NTLMv2-session-key-16b";
        let plain = b"AUTHENTICATE_MESSAGE keyexchange payload";
        let mut buf = plain.to_vec();
        rc4(key, &mut buf);
        assert_ne!(&buf[..], &plain[..], "RC4 should mutate the buffer");
        rc4(key, &mut buf);
        assert_eq!(&buf[..], &plain[..]);
    }

    #[test]
    fn utf16_le_basic() {
        assert_eq!(utf16_le("Hi"), vec![b'H', 0, b'i', 0]);
    }

    #[test]
    fn utf16_le_upper_lowercases_input() {
        assert_eq!(utf16_le_upper("user"), utf16_le("USER"));
    }
}
