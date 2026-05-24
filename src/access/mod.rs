/// Access Decision Engine Module
/// Responsibilities:
/// - Make access grant/reject decisions
/// - Log access outcomes

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum AccessDecision {
    GrantAccess,
    RejectAccess(AccessDenialReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum AccessDenialReason {
    InvalidSignature,
    CertificateValidationFailed,
    NonceReuse,
    FreshnessTimeout,
    IntegrityCheckFailed,
    UnknownIdentity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessLog {
    pub timestamp: String,
    pub vehicle_id: String,
    pub fob_id: String,
    pub decision: AccessDecision,
}

pub struct AccessDecisionEngine;

impl AccessDecisionEngine {
    pub fn make_decision(
        signature_valid: bool,
        certificate_valid: bool,
        nonce_fresh: bool,
        integrity_ok: bool,
    ) -> AccessDecision {
        if signature_valid && certificate_valid && nonce_fresh && integrity_ok {
            AccessDecision::GrantAccess
        } else {
            AccessDecision::RejectAccess(AccessDenialReason::InvalidSignature)
        }
    }

    pub fn log_access(log: &AccessLog) -> Result<(), String> {
        println!("[ACCESS LOG] {:?}", log);
        Ok(())
    }
}
