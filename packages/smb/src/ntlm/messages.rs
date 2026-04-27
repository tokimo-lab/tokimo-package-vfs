//! NTLMSSP message serialization (Type 1 / 2 / 3).

use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;

use crate::Error;

use super::AuthIdentity;
use super::crypto::{hmac_md5, hmac_md5_concat, md4, rc4, utf16_le, utf16_le_upper};

/// "NTLMSSP\0" signature.
const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

const MSG_TYPE_NEGOTIATE: u32 = 0x0000_0001;
const MSG_TYPE_CHALLENGE: u32 = 0x0000_0002;
const MSG_TYPE_AUTHENTICATE: u32 = 0x0000_0003;

// Negotiate flags – \[MS-NLMP\] 2.2.2.5.
const NTLMSSP_NEGOTIATE_UNICODE: u32 = 0x0000_0001;
const NTLMSSP_REQUEST_TARGET: u32 = 0x0000_0004;
const NTLMSSP_NEGOTIATE_SIGN: u32 = 0x0000_0010;
const NTLMSSP_NEGOTIATE_SEAL: u32 = 0x0000_0020;
const NTLMSSP_NEGOTIATE_NTLM: u32 = 0x0000_0200;
const NTLMSSP_NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
const NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
const NTLMSSP_NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
const NTLMSSP_NEGOTIATE_VERSION: u32 = 0x0200_0000;
const NTLMSSP_NEGOTIATE_128: u32 = 0x2000_0000;
const NTLMSSP_NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
const NTLMSSP_NEGOTIATE_56: u32 = 0x8000_0000;

/// AV_PAIR identifiers — \[MS-NLMP\] 2.2.2.1.
const MSV_AV_EOL: u16 = 0x0000;
const MSV_AV_TIMESTAMP: u16 = 0x0007;
const MSV_AV_FLAGS: u16 = 0x0006;
const MSV_AV_TARGET_NAME: u16 = 0x0009;
const MSV_AV_CHANNEL_BINDINGS: u16 = 0x000a;

/// Re-export so `Authenticator` can build "cifs/host"-style SPNs.
#[derive(Debug, Clone)]
pub struct TargetName(pub String);

/// Parsed `CHALLENGE_MESSAGE` (Type 2).
#[derive(Debug, Clone)]
pub(crate) struct Challenge {
    pub server_challenge: [u8; 8],
    #[allow(dead_code)]
    pub negotiate_flags: u32,
    /// Raw `TargetInfo` payload (concatenated AV_PAIRs, EOL included).
    pub target_info: Vec<u8>,
}

/// Build the NEGOTIATE_MESSAGE (Type 1).
pub(crate) fn build_negotiate(workstation: &str, domain: Option<&str>) -> Vec<u8> {
    // Flags advertised by the client. We always negotiate UNICODE + extended
    // session security + 128-bit + key-exchange, so SMB signing/sealing works.
    let flags = NTLMSSP_NEGOTIATE_UNICODE
        | NTLMSSP_REQUEST_TARGET
        | NTLMSSP_NEGOTIATE_SIGN
        | NTLMSSP_NEGOTIATE_SEAL
        | NTLMSSP_NEGOTIATE_NTLM
        | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        | NTLMSSP_NEGOTIATE_VERSION
        | NTLMSSP_NEGOTIATE_128
        | NTLMSSP_NEGOTIATE_56
        | NTLMSSP_NEGOTIATE_KEY_EXCH;

    // For NEGOTIATE we send empty domain/workstation buffers; they're
    // OEM-encoded and most servers ignore them. The challenge always carries
    // canonical target info anyway.
    let _ = (workstation, domain);

    let header_size: u32 = 8 + 4 + 4 + 8 + 8 + 8;
    let mut buf = Vec::with_capacity(header_size as usize);
    buf.extend_from_slice(NTLMSSP_SIGNATURE);
    buf.extend_from_slice(&MSG_TYPE_NEGOTIATE.to_le_bytes());
    buf.extend_from_slice(&flags.to_le_bytes());
    // DomainNameFields (len=0, maxlen=0, offset=header_size)
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&header_size.to_le_bytes());
    // WorkstationFields (len=0, maxlen=0, offset=header_size)
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&header_size.to_le_bytes());
    // Version: ProductMajor=10, ProductMinor=0, Build=19041, Reserved=0,0,0, NTLMRevision=15
    buf.extend_from_slice(&[10, 0, 0x61, 0x4a, 0, 0, 0, 0x0f]);
    debug_assert_eq!(buf.len() as u32, header_size);
    buf
}

/// Read the (length, offset) pair of a buffer descriptor at `pos`.
fn read_field(input: &[u8], pos: usize) -> Result<(u16, u32), Error> {
    if input.len() < pos + 8 {
        return Err(Error::InvalidState("NTLM message truncated".into()));
    }
    let len = u16::from_le_bytes(input[pos..pos + 2].try_into().unwrap());
    // skip max-len (u16 at pos+2)
    let off = u32::from_le_bytes(input[pos + 4..pos + 8].try_into().unwrap());
    Ok((len, off))
}

/// Parse a CHALLENGE_MESSAGE (Type 2).
pub(crate) fn parse_challenge(input: &[u8]) -> Result<Challenge, Error> {
    if input.len() < 48 {
        return Err(Error::InvalidState("NTLM challenge too short".into()));
    }
    if &input[0..8] != NTLMSSP_SIGNATURE {
        return Err(Error::InvalidState("NTLM challenge signature mismatch".into()));
    }
    let msg_type = u32::from_le_bytes(input[8..12].try_into().unwrap());
    if msg_type != MSG_TYPE_CHALLENGE {
        return Err(Error::InvalidState(format!(
            "Expected CHALLENGE_MESSAGE, got msg_type={msg_type}"
        )));
    }

    // TargetNameFields at offset 12 (len, maxlen, offset)
    let _target_name = read_field(input, 12)?;
    let negotiate_flags = u32::from_le_bytes(input[20..24].try_into().unwrap());
    let server_challenge: [u8; 8] = input[24..32].try_into().unwrap();
    // 8-byte reserved at 32..40
    let (ti_len, ti_off) = read_field(input, 40)?;
    let target_info = if ti_len == 0 {
        Vec::new()
    } else {
        let off = ti_off as usize;
        let end = off
            .checked_add(ti_len as usize)
            .ok_or_else(|| Error::InvalidState("target info offset overflow".into()))?;
        if input.len() < end {
            return Err(Error::InvalidState("target info out of bounds".into()));
        }
        input[off..end].to_vec()
    };

    Ok(Challenge {
        server_challenge,
        negotiate_flags,
        target_info,
    })
}

/// Convert UNIX SystemTime → Windows FILETIME (100-ns ticks since 1601-01-01).
fn windows_filetime() -> u64 {
    const EPOCH_DIFFERENCE_SECONDS: u64 = 11_644_473_600;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    (now.as_secs() + EPOCH_DIFFERENCE_SECONDS) * 10_000_000 + u64::from(now.subsec_nanos() / 100)
}

/// Build the AUTHENTICATE_MESSAGE (Type 3) and derive the exported session key.
pub(crate) fn build_authenticate(
    challenge: &Challenge,
    identity: &AuthIdentity,
    workstation: &str,
    target_spn: Option<&str>,
) -> Result<(Vec<u8>, [u8; 16]), Error> {
    let username = identity.username.account_name();
    let domain = identity.username.domain_name().unwrap_or("");
    let password = identity.password.as_ref();

    // ── NTOWFv2 = HMAC_MD5(MD4(unicode(password)), unicode(uppercase(user) + domain)) ──
    let password_md4 = md4(&utf16_le(password));
    let mut user_domain = utf16_le_upper(username);
    user_domain.extend_from_slice(&utf16_le(domain));
    let nt_ow_fv2 = hmac_md5(&password_md4, &user_domain);

    // ── Build AV_PAIR target info: copy server's, append MsvAvFlags=0x02
    //    (indicates MIC computed) and MsvAvTargetName when SPN is provided.
    let mut target_info = challenge.target_info.clone();
    // Strip trailing EOL pair (4 zero bytes) so we can append before resealing it.
    if target_info.ends_with(&[0, 0, 0, 0]) {
        target_info.truncate(target_info.len() - 4);
    }
    if let Some(spn) = target_spn {
        let spn_le = utf16_le(spn);
        target_info.extend_from_slice(&MSV_AV_TARGET_NAME.to_le_bytes());
        target_info.extend_from_slice(&(spn_le.len() as u16).to_le_bytes());
        target_info.extend_from_slice(&spn_le);
    }
    // Channel bindings = MD5(empty) per RFC 5929 when no TLS endpoint.
    let cb_hash = [0u8; 16];
    target_info.extend_from_slice(&MSV_AV_CHANNEL_BINDINGS.to_le_bytes());
    target_info.extend_from_slice(&16u16.to_le_bytes());
    target_info.extend_from_slice(&cb_hash);
    // MsvAvFlags (4 bytes value, flags=0)
    target_info.extend_from_slice(&MSV_AV_FLAGS.to_le_bytes());
    target_info.extend_from_slice(&4u16.to_le_bytes());
    target_info.extend_from_slice(&0u32.to_le_bytes());
    // EOL
    target_info.extend_from_slice(&MSV_AV_EOL.to_le_bytes());
    target_info.extend_from_slice(&0u16.to_le_bytes());

    // ── temp = Responserversion(1) || HiResponserversion(1) || Z(6) ||
    //          Time(8) || ClientChallenge(8) || Z(4) || ServerName(target_info) || Z(4) ──
    let timestamp = challenge_timestamp_or_now(&challenge.target_info);
    let mut client_nonce = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut client_nonce);

    let mut temp = Vec::with_capacity(28 + target_info.len() + 4);
    temp.push(0x01);
    temp.push(0x01);
    temp.extend_from_slice(&[0u8; 6]); // reserved
    temp.extend_from_slice(&timestamp.to_le_bytes());
    temp.extend_from_slice(&client_nonce);
    temp.extend_from_slice(&[0u8; 4]); // reserved
    temp.extend_from_slice(&target_info);
    temp.extend_from_slice(&[0u8; 4]); // reserved

    // NtProofStr = HMAC_MD5(NTOWFv2, ServerChallenge || temp)
    let nt_proof_str = hmac_md5_concat(&nt_ow_fv2, &challenge.server_challenge, &temp);

    // NtChallengeResponse = NtProofStr || temp
    let mut nt_response = Vec::with_capacity(16 + temp.len());
    nt_response.extend_from_slice(&nt_proof_str);
    nt_response.extend_from_slice(&temp);

    // LmChallengeResponse = HMAC_MD5(NTOWFv2, ServerChallenge || ClientChallenge) || ClientChallenge
    let mut lm_response = Vec::with_capacity(24);
    let lm_hmac = hmac_md5_concat(&nt_ow_fv2, &challenge.server_challenge, &client_nonce);
    lm_response.extend_from_slice(&lm_hmac);
    lm_response.extend_from_slice(&client_nonce);

    // SessionBaseKey = HMAC_MD5(NTOWFv2, NtProofStr); KeyExchangeKey = SessionBaseKey for NTLMv2.
    let session_base_key = hmac_md5(&nt_ow_fv2, &nt_proof_str);
    let key_exchange_key = session_base_key;

    // ExportedSessionKey: random 16 bytes, encrypted with KeyExchangeKey via RC4.
    // Server decrypts to get same SMB signing/sealing key.
    let mut exported_session_key = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut exported_session_key);
    let mut encrypted_random_session_key = exported_session_key;
    rc4(&key_exchange_key, &mut encrypted_random_session_key);

    // Negotiate flags echoed back; must include UNICODE + key-exch + 128 + extended sec.
    let response_flags = NTLMSSP_NEGOTIATE_UNICODE
        | NTLMSSP_NEGOTIATE_SIGN
        | NTLMSSP_NEGOTIATE_SEAL
        | NTLMSSP_NEGOTIATE_NTLM
        | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        | NTLMSSP_NEGOTIATE_TARGET_INFO
        | NTLMSSP_NEGOTIATE_VERSION
        | NTLMSSP_NEGOTIATE_128
        | NTLMSSP_NEGOTIATE_56
        | NTLMSSP_NEGOTIATE_KEY_EXCH;

    // ── Assemble the message ──
    // Layout: header (88 bytes including version + reserved MIC space) + payload
    // We don't emit a MIC (MsvAvFlags bit 0x02 above is left as 0).
    let domain_le = utf16_le(domain);
    let user_le = utf16_le(username);
    let ws_le = utf16_le(workstation);

    // Header size with version field present (no MIC).
    const HEADER_LEN: u32 = 8 + 4 + 8 * 6 + 4 + 8;
    // Field offsets in payload, in this order: LM, NT, Domain, User, Workstation, EncSessionKey.
    let lm_offset: u32 = HEADER_LEN;
    let nt_offset: u32 = lm_offset + lm_response.len() as u32;
    let dom_offset: u32 = nt_offset + nt_response.len() as u32;
    let user_offset: u32 = dom_offset + domain_le.len() as u32;
    let ws_offset: u32 = user_offset + user_le.len() as u32;
    let key_offset: u32 = ws_offset + ws_le.len() as u32;

    let mut buf: Vec<u8> = Vec::with_capacity(key_offset as usize + 16);
    buf.extend_from_slice(NTLMSSP_SIGNATURE);
    buf.extend_from_slice(&MSG_TYPE_AUTHENTICATE.to_le_bytes());
    push_field(&mut buf, lm_response.len() as u16, lm_offset);
    push_field(&mut buf, nt_response.len() as u16, nt_offset);
    push_field(&mut buf, domain_le.len() as u16, dom_offset);
    push_field(&mut buf, user_le.len() as u16, user_offset);
    push_field(&mut buf, ws_le.len() as u16, ws_offset);
    push_field(&mut buf, encrypted_random_session_key.len() as u16, key_offset);
    buf.extend_from_slice(&response_flags.to_le_bytes());
    // Version
    buf.extend_from_slice(&[10, 0, 0x61, 0x4a, 0, 0, 0, 0x0f]);
    debug_assert_eq!(buf.len() as u32, HEADER_LEN);

    buf.extend_from_slice(&lm_response);
    buf.extend_from_slice(&nt_response);
    buf.extend_from_slice(&domain_le);
    buf.extend_from_slice(&user_le);
    buf.extend_from_slice(&ws_le);
    buf.extend_from_slice(&encrypted_random_session_key);

    Ok((buf, exported_session_key))
}

fn push_field(buf: &mut Vec<u8>, len: u16, offset: u32) {
    buf.extend_from_slice(&len.to_le_bytes()); // Len
    buf.extend_from_slice(&len.to_le_bytes()); // MaxLen (= Len; no padding)
    buf.extend_from_slice(&offset.to_le_bytes());
}

/// Extract the server timestamp from the AV_PAIR list, falling back to "now".
fn challenge_timestamp_or_now(av_pairs: &[u8]) -> u64 {
    let mut p = 0usize;
    while p + 4 <= av_pairs.len() {
        let id = u16::from_le_bytes(av_pairs[p..p + 2].try_into().unwrap());
        let len = u16::from_le_bytes(av_pairs[p + 2..p + 4].try_into().unwrap()) as usize;
        if id == MSV_AV_EOL {
            break;
        }
        if id == MSV_AV_TIMESTAMP && len == 8 && p + 4 + 8 <= av_pairs.len() {
            return u64::from_le_bytes(av_pairs[p + 4..p + 12].try_into().unwrap());
        }
        p += 4 + len;
    }
    windows_filetime()
}

#[cfg(test)]
mod tests {
    //! Test vectors from [MS-NLMP] section 4.2.4 — "NTLM v2 Authentication".
    //! https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/

    use super::super::crypto::{hmac_md5, hmac_md5_concat, md4, utf16_le, utf16_le_upper};

    /// Common §4.2.4 inputs.
    const USER: &str = "User";
    const DOMAIN: &str = "Domain";
    const PASSWORD: &str = "Password";

    /// §4.2.4.1.1: Response Key Calculation
    /// Expected NTOWFv2(Password, "User", "Domain") =
    ///   0c 86 8a 40 3b fd 7a 93 a3 00 1e f2 2e f0 2e 3f
    #[test]
    fn ntowfv2_ms_nlmp_4_2_4_1_1() {
        let password_md4 = md4(&utf16_le(PASSWORD));
        let mut user_domain = utf16_le_upper(USER);
        user_domain.extend_from_slice(&utf16_le(DOMAIN));
        let ntowfv2 = hmac_md5(&password_md4, &user_domain);

        assert_eq!(
            ntowfv2,
            [
                0x0c, 0x86, 0x8a, 0x40, 0x3b, 0xfd, 0x7a, 0x93, 0xa3, 0x00, 0x1e, 0xf2, 0x2e, 0xf0, 0x2e, 0x3f
            ],
            "NTOWFv2 mismatch with [MS-NLMP] 4.2.4.1.1"
        );
    }

    /// §4.2.4.1.3 / §4.2.4.2.2: NtProofStr for the canonical sample blob.
    /// Inputs:
    ///   ServerChallenge   = 01 23 45 67 89 ab cd ef
    ///   ClientChallenge   = aa aa aa aa aa aa aa aa
    ///   Time              = 00 00 00 00 00 00 00 00
    ///   TargetInfo (AV_PAIRS):
    ///     02 00 0c 00 "Domain" (UTF-16LE)
    ///     01 00 0c 00 "Server" (UTF-16LE)
    ///     00 00 00 00              (EOL)
    /// Expected NtProofStr =
    ///   68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c
    #[test]
    fn nt_proof_str_ms_nlmp_4_2_4_2_2() {
        let password_md4 = md4(&utf16_le(PASSWORD));
        let mut user_domain = utf16_le_upper(USER);
        user_domain.extend_from_slice(&utf16_le(DOMAIN));
        let ntowfv2 = hmac_md5(&password_md4, &user_domain);

        let server_challenge: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let client_challenge: [u8; 8] = [0xaa; 8];
        let time: [u8; 8] = [0u8; 8];

        // TargetInfo from §4.2.4.1.3
        let mut target_info: Vec<u8> = Vec::new();
        target_info.extend_from_slice(&[0x02, 0x00, 0x0c, 0x00]);
        target_info.extend_from_slice(&utf16_le("Domain"));
        target_info.extend_from_slice(&[0x01, 0x00, 0x0c, 0x00]);
        target_info.extend_from_slice(&utf16_le("Server"));
        target_info.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // temp = 0x01,0x01, 6×0, Time, ClientChallenge, 4×0, TargetInfo, 4×0
        let mut temp = Vec::new();
        temp.extend_from_slice(&[0x01, 0x01, 0, 0, 0, 0, 0, 0]);
        temp.extend_from_slice(&time);
        temp.extend_from_slice(&client_challenge);
        temp.extend_from_slice(&[0, 0, 0, 0]);
        temp.extend_from_slice(&target_info);
        temp.extend_from_slice(&[0, 0, 0, 0]);

        let nt_proof_str = hmac_md5_concat(&ntowfv2, &server_challenge, &temp);

        assert_eq!(
            nt_proof_str,
            [
                0x68, 0xcd, 0x0a, 0xb8, 0x51, 0xe5, 0x1c, 0x96, 0xaa, 0xbc, 0x92, 0x7b, 0xeb, 0xef, 0x6a, 0x1c
            ],
            "NtProofStr mismatch with [MS-NLMP] 4.2.4.2.2"
        );

        // SessionBaseKey = HMAC_MD5(NTOWFv2, NtProofStr)
        // Expected per §4.2.4.2.2 = 8d e4 0c ca db c1 4a 82 f1 5c b0 ad 0d e9 5c a3
        let session_base_key = hmac_md5(&ntowfv2, &nt_proof_str);
        assert_eq!(
            session_base_key,
            [
                0x8d, 0xe4, 0x0c, 0xca, 0xdb, 0xc1, 0x4a, 0x82, 0xf1, 0x5c, 0xb0, 0xad, 0x0d, 0xe9, 0x5c, 0xa3
            ],
            "SessionBaseKey mismatch with [MS-NLMP] 4.2.4.2.2"
        );
    }

    /// §4.2.4.2.1: LMv2 response.
    /// LmChallengeResponse = HMAC_MD5(NTOWFv2, ServerChallenge || ClientChallenge) || ClientChallenge
    /// Expected first 16 bytes = 86 c3 50 97 ac 9c ec 10 25 54 76 4a 57 cc cc 19
    #[test]
    fn lmv2_response_ms_nlmp_4_2_4_2_1() {
        let password_md4 = md4(&utf16_le(PASSWORD));
        let mut user_domain = utf16_le_upper(USER);
        user_domain.extend_from_slice(&utf16_le(DOMAIN));
        let ntowfv2 = hmac_md5(&password_md4, &user_domain);

        let server_challenge: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let client_challenge: [u8; 8] = [0xaa; 8];

        let lm = hmac_md5_concat(&ntowfv2, &server_challenge, &client_challenge);

        assert_eq!(
            lm,
            [
                0x86, 0xc3, 0x50, 0x97, 0xac, 0x9c, 0xec, 0x10, 0x25, 0x54, 0x76, 0x4a, 0x57, 0xcc, 0xcc, 0x19
            ],
            "LMv2 hash mismatch with [MS-NLMP] 4.2.4.2.1"
        );
    }

    /// `build_negotiate` must produce a 40-byte Type 1 message with the
    /// "NTLMSSP\0" signature and msg_type=1 in little-endian.
    #[test]
    fn build_negotiate_header_shape() {
        let buf = super::build_negotiate("WS", None);
        assert_eq!(buf.len(), 40);
        assert_eq!(&buf[0..8], super::NTLMSSP_SIGNATURE);
        assert_eq!(u32::from_le_bytes(buf[8..12].try_into().unwrap()), 1);
    }

    /// `parse_challenge` must round-trip the server challenge, flags, and
    /// the TargetInfo blob from a synthetic Type 2 message.
    #[test]
    fn parse_challenge_round_trip() {
        let server_challenge: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let flags: u32 = 0x6282_8215;
        let target_info: Vec<u8> = vec![
            0x02, 0x00, 0x0c, 0x00, b'D', 0, b'o', 0, b'm', 0, b'a', 0, b'i', 0, b'n', 0, 0x00, 0x00, 0x00, 0x00,
        ];

        let header_size: u32 = 56;
        let ti_off = header_size;
        let ti_len = target_info.len() as u16;

        let mut buf = Vec::new();
        buf.extend_from_slice(super::NTLMSSP_SIGNATURE);
        buf.extend_from_slice(&super::MSG_TYPE_CHALLENGE.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&header_size.to_le_bytes());
        buf.extend_from_slice(&flags.to_le_bytes());
        buf.extend_from_slice(&server_challenge);
        buf.extend_from_slice(&[0u8; 8]);
        buf.extend_from_slice(&ti_len.to_le_bytes());
        buf.extend_from_slice(&ti_len.to_le_bytes());
        buf.extend_from_slice(&ti_off.to_le_bytes());
        buf.extend_from_slice(&[10, 0, 0x61, 0x4a, 0, 0, 0, 0x0f]);
        assert_eq!(buf.len() as u32, header_size);
        buf.extend_from_slice(&target_info);

        let parsed = super::parse_challenge(&buf).expect("parse_challenge");
        assert_eq!(parsed.server_challenge, server_challenge);
        assert_eq!(parsed.negotiate_flags, flags);
        assert_eq!(parsed.target_info, target_info);
    }

    /// A truncated buffer must surface as an `InvalidState` error rather than
    /// panicking via slice indexing.
    #[test]
    fn parse_challenge_rejects_truncated() {
        let res = super::parse_challenge(&[0u8; 8]);
        assert!(res.is_err());
    }

    /// A buffer with the wrong signature must be rejected.
    #[test]
    fn parse_challenge_rejects_bad_signature() {
        let mut buf = vec![0u8; 56];
        buf[0..8].copy_from_slice(b"BOGUS\0\0\0");
        let res = super::parse_challenge(&buf);
        assert!(res.is_err());
    }
}
