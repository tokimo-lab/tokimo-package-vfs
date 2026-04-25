use std::sync::Arc;

use crate::Error;
use crate::connection::connection_info::ConnectionInfo;
use crate::ntlm::{AuthIdentity, Ntlm, Username};
use maybe_async::*;

/// Drives NTLM session-setup token exchange for SMB.
///
/// Replaces the previous SSPI-based implementation. Only NTLMv2 (DirectNtlm)
/// is supported — SPNEGO/Negotiate/Kerberos paths were intentionally removed.
#[derive(Debug)]
pub struct Authenticator {
    user_name: Username,
    ntlm: Ntlm,
}

impl Authenticator {
    pub fn build(identity: AuthIdentity, conn_info: &Arc<ConnectionInfo>) -> crate::Result<Authenticator> {
        let user_name = identity.username.clone();
        let workstation = conn_info
            .config
            .client_name
            .clone()
            .unwrap_or_else(|| "smb-rs".to_string());
        let target_spn = format!("cifs/{}", conn_info.server_name);
        let ntlm = Ntlm::new(identity, workstation, Some(target_spn));
        Ok(Authenticator { user_name, ntlm })
    }

    pub fn user_name(&self) -> &Username {
        &self.user_name
    }

    pub fn is_authenticated(&self) -> crate::Result<bool> {
        Ok(self.ntlm.is_complete())
    }

    pub fn session_key(&self) -> crate::Result<[u8; 16]> {
        self.ntlm
            .session_key()
            .map_err(|e| Error::NtlmError(e.to_string()))
    }

    #[maybe_async]
    pub async fn next(&mut self, gss_token: &[u8]) -> crate::Result<Vec<u8>> {
        if self.ntlm.is_complete() {
            return Err(Error::InvalidState("Authentication already done.".into()));
        }
        self.ntlm
            .next(gss_token)
            .map_err(|e| match e {
                Error::NtlmError(_) | Error::InvalidState(_) => e,
                other => Error::NtlmError(other.to_string()),
            })
    }
}
