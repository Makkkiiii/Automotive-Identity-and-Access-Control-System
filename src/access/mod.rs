use crate::auth::AuthResult;
use crate::session::{SessionState, SessionValidationEngine};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessDecision {
    GrantAccess,
    RejectAccess(AccessDenialReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessDenialReason {
    InvalidCertificate,
    ExpiredCertificate,
    IdentityMismatch,
    UnknownNonce,
    ReusedNonce,
    FreshnessTimeout,
    InvalidSignature,
    InvalidTimestamp,
    SessionNotEstablished,
    SessionExpired,
    SessionEncryptionFailed,
    SessionIntegrityFailed,
    UnauthorizedIdentity,
    InternalError,
}

pub struct AccessDecisionEngine;

impl AccessDecisionEngine {
    pub fn from_auth_result(auth_result: AuthResult) -> AccessDecision {
        match auth_result {
            AuthResult::Success => AccessDecision::GrantAccess,
            AuthResult::InvalidCertificate => {
                AccessDecision::RejectAccess(AccessDenialReason::InvalidCertificate)
            }
            AuthResult::ExpiredCertificate => {
                AccessDecision::RejectAccess(AccessDenialReason::ExpiredCertificate)
            }
            AuthResult::IdentityMismatch => {
                AccessDecision::RejectAccess(AccessDenialReason::IdentityMismatch)
            }
            AuthResult::UnknownNonce => {
                AccessDecision::RejectAccess(AccessDenialReason::UnknownNonce)
            }
            AuthResult::ReusedNonce => {
                AccessDecision::RejectAccess(AccessDenialReason::ReusedNonce)
            }
            AuthResult::FreshnessTimeout => {
                AccessDecision::RejectAccess(AccessDenialReason::FreshnessTimeout)
            }
            AuthResult::InvalidSignature => {
                AccessDecision::RejectAccess(AccessDenialReason::InvalidSignature)
            }
            AuthResult::InvalidTimestamp => {
                AccessDecision::RejectAccess(AccessDenialReason::InvalidTimestamp)
            }
        }
    }

    pub fn from_session_result(session_result: Result<bool, String>) -> AccessDecision {
        match session_result {
            Ok(true) => AccessDecision::GrantAccess,
            Ok(false) => AccessDecision::RejectAccess(AccessDenialReason::SessionExpired),
            Err(_) => AccessDecision::RejectAccess(AccessDenialReason::InternalError),
        }
    }

    pub fn evaluate_access(
        auth_result: AuthResult,
        session_state: &SessionState,
    ) -> AccessDecision {
        let auth_decision = Self::from_auth_result(auth_result);
        if matches!(auth_decision, AccessDecision::RejectAccess(_)) {
            return auth_decision;
        }

        if !session_state.established {
            return AccessDecision::RejectAccess(AccessDenialReason::SessionNotEstablished);
        }

        match SessionValidationEngine::is_session_active(session_state) {
            Ok(true) => AccessDecision::GrantAccess,
            Ok(false) => AccessDecision::RejectAccess(AccessDenialReason::SessionExpired),
            Err(_) => AccessDecision::RejectAccess(AccessDenialReason::InternalError),
        }
    }

    pub fn decision_message(decision: &AccessDecision) -> String {
        match decision {
            AccessDecision::GrantAccess => "Access granted".to_string(),
            AccessDecision::RejectAccess(reason) => format!("Access denied: {:?}", reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn active_session() -> SessionState {
        let now = Utc::now();
        SessionState {
            session_id: "SESSION-001".to_string(),
            vehicle_id: "VEH-001".to_string(),
            subject_id: "FOB-001".to_string(),
            created_at: now.to_rfc3339(),
            expires_at: (now + chrono::Duration::seconds(60)).to_rfc3339(),
            established: true,
        }
    }

    fn expired_session() -> SessionState {
        let now = Utc::now();
        SessionState {
            session_id: "SESSION-EXPIRED".to_string(),
            vehicle_id: "VEH-001".to_string(),
            subject_id: "FOB-001".to_string(),
            created_at: (now - chrono::Duration::seconds(120)).to_rfc3339(),
            expires_at: (now - chrono::Duration::seconds(60)).to_rfc3339(),
            established: true,
        }
    }

    #[test]
    fn test_successful_authentication_grants_access() {
        let decision = AccessDecisionEngine::from_auth_result(AuthResult::Success);
        assert_eq!(decision, AccessDecision::GrantAccess);
    }

    #[test]
    fn test_invalid_certificate_rejects_access() {
        let decision = AccessDecisionEngine::from_auth_result(AuthResult::InvalidCertificate);
        assert_eq!(
            decision,
            AccessDecision::RejectAccess(AccessDenialReason::InvalidCertificate)
        );
    }

    #[test]
    fn test_expired_certificate_rejects_access() {
        let decision = AccessDecisionEngine::from_auth_result(AuthResult::ExpiredCertificate);
        assert_eq!(
            decision,
            AccessDecision::RejectAccess(AccessDenialReason::ExpiredCertificate)
        );
    }

    #[test]
    fn test_identity_mismatch_rejects_access() {
        let decision = AccessDecisionEngine::from_auth_result(AuthResult::IdentityMismatch);
        assert_eq!(
            decision,
            AccessDecision::RejectAccess(AccessDenialReason::IdentityMismatch)
        );
    }

    #[test]
    fn test_unknown_nonce_rejects_access() {
        let decision = AccessDecisionEngine::from_auth_result(AuthResult::UnknownNonce);
        assert_eq!(
            decision,
            AccessDecision::RejectAccess(AccessDenialReason::UnknownNonce)
        );
    }

    #[test]
    fn test_reused_nonce_rejects_access() {
        let decision = AccessDecisionEngine::from_auth_result(AuthResult::ReusedNonce);
        assert_eq!(
            decision,
            AccessDecision::RejectAccess(AccessDenialReason::ReusedNonce)
        );
    }

    #[test]
    fn test_freshness_timeout_rejects_access() {
        let decision = AccessDecisionEngine::from_auth_result(AuthResult::FreshnessTimeout);
        assert_eq!(
            decision,
            AccessDecision::RejectAccess(AccessDenialReason::FreshnessTimeout)
        );
    }

    #[test]
    fn test_invalid_signature_rejects_access() {
        let decision = AccessDecisionEngine::from_auth_result(AuthResult::InvalidSignature);
        assert_eq!(
            decision,
            AccessDecision::RejectAccess(AccessDenialReason::InvalidSignature)
        );
    }

    #[test]
    fn test_active_session_allows_access() {
        let decision =
            AccessDecisionEngine::evaluate_access(AuthResult::Success, &active_session());
        assert_eq!(decision, AccessDecision::GrantAccess);
    }

    #[test]
    fn test_expired_session_rejects_access() {
        let decision =
            AccessDecisionEngine::evaluate_access(AuthResult::Success, &expired_session());
        assert_eq!(
            decision,
            AccessDecision::RejectAccess(AccessDenialReason::SessionExpired)
        );
    }

    #[test]
    fn test_unestablished_session_rejects_access() {
        let mut session = active_session();
        session.established = false;
        let decision = AccessDecisionEngine::evaluate_access(AuthResult::Success, &session);
        assert_eq!(
            decision,
            AccessDecision::RejectAccess(AccessDenialReason::SessionNotEstablished)
        );
    }

    #[test]
    fn test_decision_messages_are_clear_and_stable() {
        let grant = AccessDecisionEngine::decision_message(&AccessDecision::GrantAccess);
        let deny = AccessDecisionEngine::decision_message(&AccessDecision::RejectAccess(
            AccessDenialReason::InvalidSignature,
        ));

        assert_eq!(grant, "Access granted");
        assert_eq!(deny, "Access denied: InvalidSignature");
    }
}
