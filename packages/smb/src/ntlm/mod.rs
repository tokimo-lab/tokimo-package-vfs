//! Minimal NTLMv2 client implementation, replacing the previous `sspi` dependency.
//!
//! Only supports the "Direct NTLM" path used by smb-rs (`AuthMode::DirectNtlm`):
//! bare NTLMSSP `NEGOTIATE_MESSAGE` (Type 1) → `CHALLENGE_MESSAGE` (Type 2)
//! → `AUTHENTICATE_MESSAGE` (Type 3). No SPNEGO/Negotiate/Kerberos.
//!
//! Reference: \[MS-NLMP\] – NT LAN Manager (NTLM) Authentication Protocol.

mod crypto;
mod messages;

pub use messages::TargetName;

use std::fmt;

use crate::Error;

/// Wraps a sensitive value so that `Debug` doesn't leak it.
#[derive(Clone)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    pub fn as_ref(&self) -> &T {
        &self.0
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl<T> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

/// User principal: `account[@domain]` or `domain\account`.
#[derive(Debug, Clone)]
pub struct Username {
    account: String,
    domain: Option<String>,
}

impl Username {
    pub fn new(account: impl Into<String>, domain: Option<impl Into<String>>) -> Self {
        Self {
            account: account.into(),
            domain: domain.map(Into::into),
        }
    }

    /// Parse `user`, `user@DOMAIN`, or `DOMAIN\user`.
    pub fn parse(input: &str) -> Result<Self, Error> {
        if let Some((dom, acc)) = input.split_once('\\') {
            return Ok(Self::new(acc.to_string(), Some(dom.to_string())));
        }
        if let Some((acc, dom)) = input.split_once('@') {
            return Ok(Self::new(acc.to_string(), Some(dom.to_string())));
        }
        Ok(Self::new(input.to_string(), None::<String>))
    }

    pub fn account_name(&self) -> &str {
        &self.account
    }

    pub fn domain_name(&self) -> Option<&str> {
        self.domain.as_deref()
    }
}

impl fmt::Display for Username {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(d) = &self.domain {
            write!(f, "{d}\\{}", self.account)
        } else {
            f.write_str(&self.account)
        }
    }
}

/// Username + password credential.
#[derive(Debug, Clone)]
pub struct AuthIdentity {
    pub username: Username,
    pub password: Secret<String>,
}

/// State of the NTLM authentication state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NtlmState {
    /// Ready to emit a NEGOTIATE_MESSAGE (Type 1).
    Initial,
    /// Negotiate emitted, awaiting CHALLENGE_MESSAGE (Type 2).
    NegotiateSent,
    /// AUTHENTICATE_MESSAGE emitted, authentication complete.
    Done,
}

/// NTLMv2 client.
#[derive(Debug)]
pub struct Ntlm {
    state: NtlmState,
    identity: AuthIdentity,
    workstation: String,
    /// SPN string sent in `MsvAvTargetName` (e.g. `cifs/server`).
    target_spn: Option<String>,
    /// 16-byte exported session key (filled after Type 3).
    session_key: Option<[u8; 16]>,
}

impl Ntlm {
    pub fn new(identity: AuthIdentity, workstation: impl Into<String>, target_spn: Option<String>) -> Self {
        Self {
            state: NtlmState::Initial,
            identity,
            workstation: workstation.into(),
            target_spn,
            session_key: None,
        }
    }

    pub fn user_name(&self) -> &Username {
        &self.identity.username
    }

    pub fn is_complete(&self) -> bool {
        self.state == NtlmState::Done
    }

    /// Returns the 16-byte session key (`ExportedSessionKey` per \[MS-NLMP\] 3.4).
    pub fn session_key(&self) -> Result<[u8; 16], Error> {
        self.session_key
            .ok_or_else(|| Error::InvalidState("NTLM session key not yet established".into()))
    }

    /// Drive the authentication state machine.
    ///
    /// On the first call, `input` should be empty (returns Type 1).
    /// On the second call, `input` should be the server's Type 2 (returns Type 3).
    pub fn next(&mut self, input: &[u8]) -> Result<Vec<u8>, Error> {
        match self.state {
            NtlmState::Initial => {
                let msg = messages::build_negotiate(&self.workstation, self.identity.username.domain_name());
                self.state = NtlmState::NegotiateSent;
                Ok(msg)
            }
            NtlmState::NegotiateSent => {
                let challenge = messages::parse_challenge(input)?;
                let (auth_msg, session_key) = messages::build_authenticate(
                    &challenge,
                    &self.identity,
                    &self.workstation,
                    self.target_spn.as_deref(),
                )?;
                self.session_key = Some(session_key);
                self.state = NtlmState::Done;
                Ok(auth_msg)
            }
            NtlmState::Done => Err(Error::InvalidState("NTLM authentication already complete".into())),
        }
    }
}
