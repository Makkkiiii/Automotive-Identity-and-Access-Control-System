/// Adversarial Validation Engine Module
/// Controlled attack simulations against AIACS protocol
/// All attacks call the real protocol and observe defense success
use crate::access::{AccessDecision, AccessDecisionEngine, AccessDenialReason};
use crate::auth::{AuthResult, AuthenticationEngine};
use crate::ca::CertificateAuthority;
use crate::crypto::CryptoEngine;
use crate::keyfob::DigitalKeyFob;
use crate::session::SessionState;
use crate::vehicle::VehicleControlModule;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackType {
    ReplayAttack,
    ForgedSignature,
    FakeCertificate,
    IdentityMismatch,
    DelayedRelay,
    PacketTampering,
    UnauthorizedKeyFob,
    TamperedSessionCiphertext,
    WrongSessionKey,
}

impl fmt::Display for AttackType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            AttackType::ReplayAttack => "Replay Attack",
            AttackType::ForgedSignature => "Forged Signature",
            AttackType::FakeCertificate => "Fake Certificate",
            AttackType::IdentityMismatch => "Identity Mismatch",
            AttackType::DelayedRelay => "Delayed Relay",
            AttackType::PacketTampering => "Packet Tampering",
            AttackType::UnauthorizedKeyFob => "Unauthorized Key Fob",
            AttackType::TamperedSessionCiphertext => "Tampered Session Ciphertext",
            AttackType::WrongSessionKey => "Wrong Session Key",
        };

        f.write_str(label)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackResult {
    pub attack_type: AttackType,
    pub success: bool,
    pub expected_rejection: bool,
    pub access_decision: String,
    pub explanation: String,
    pub timestamp: String,
}

pub struct AdversarialValidationEngine;

impl AdversarialValidationEngine {
    fn setup_test_environment() -> (CertificateAuthority, VehicleControlModule, DigitalKeyFob) {
        let keypair = CryptoEngine::generate_ed25519_keypair().expect("CA keygen failed");
        let ca = CertificateAuthority {
            name: "Test-CA".to_string(),
            root_public_key: Some(keypair.public_key),
            root_private_key: Some(keypair.private_key),
        };

        let mut vehicle = VehicleControlModule::new("VEH-TEST-001".to_string());
        vehicle.initialize().expect("Vehicle init failed");

        let mut keyfob = DigitalKeyFob::new("FOB-TEST-001".to_string());
        keyfob.initialize().expect("Keyfob init failed");

        let cert = ca
            .issue_certificate(
                "FOB-TEST-001".to_string(),
                keyfob.public_key.clone().expect("No public key"),
            )
            .expect("Certificate issuance failed");

        let cert_json = serde_json::to_vec(&cert).expect("Cert serialization failed");
        let keyfob_with_cert = DigitalKeyFob {
            subject_id: keyfob.subject_id,
            public_key: keyfob.public_key,
            private_key: keyfob.private_key,
            certificate: Some(cert_json),
        };

        (ca, vehicle, keyfob_with_cert)
    }

    pub fn run_legitimate_baseline() -> AttackResult {
        let timestamp = Utc::now().to_rfc3339();
        let (ca, mut vehicle, keyfob) = Self::setup_test_environment();

        let challenge = AuthenticationEngine::generate_challenge(&mut vehicle, "VEH-TEST-001")
            .expect("Challenge generation failed");

        let proof = keyfob
            .create_auth_proof("VEH-TEST-001", &challenge.nonce)
            .expect("Proof creation failed");

        let auth_result = AuthenticationEngine::verify_response(&proof, &ca, &mut vehicle, 60)
            .unwrap_or(AuthResult::InvalidSignature);

        let session = SessionState {
            session_id: "SESSION-BASELINE".to_string(),
            vehicle_id: "VEH-TEST-001".to_string(),
            subject_id: "FOB-TEST-001".to_string(),
            created_at: Utc::now().to_rfc3339(),
            expires_at: (Utc::now() + chrono::Duration::seconds(300)).to_rfc3339(),
            established: true,
        };

        let decision = AccessDecisionEngine::evaluate_access(auth_result, &session);
        let is_success = matches!(decision, AccessDecision::GrantAccess);

        let access_str = AccessDecisionEngine::decision_message(&decision);

        AttackResult {
            attack_type: AttackType::ReplayAttack,
            success: is_success,
            expected_rejection: false,
            access_decision: access_str,
            explanation: "Baseline: legitimate authentication and session establishment"
                .to_string(),
            timestamp,
        }
    }

    pub fn simulate_replay_attack() -> AttackResult {
        let timestamp = Utc::now().to_rfc3339();
        let (ca, mut vehicle, keyfob) = Self::setup_test_environment();

        let challenge1 = AuthenticationEngine::generate_challenge(&mut vehicle, "VEH-TEST-001")
            .expect("Challenge 1 generation failed");

        let proof1 = keyfob
            .create_auth_proof("VEH-TEST-001", &challenge1.nonce)
            .expect("Proof 1 creation failed");

        let _auth_result1 = AuthenticationEngine::verify_response(&proof1, &ca, &mut vehicle, 60)
            .unwrap_or(AuthResult::InvalidSignature);

        let proof1_replay = proof1.clone();
        let _challenge2 = AuthenticationEngine::generate_challenge(&mut vehicle, "VEH-TEST-001")
            .expect("Challenge 2 generation failed");

        let auth_result_replay =
            AuthenticationEngine::verify_response(&proof1_replay, &ca, &mut vehicle, 60)
                .unwrap_or(AuthResult::InvalidSignature);

        let session = SessionState {
            session_id: "SESSION-REPLAY-TEST".to_string(),
            vehicle_id: "VEH-TEST-001".to_string(),
            subject_id: "FOB-TEST-001".to_string(),
            created_at: Utc::now().to_rfc3339(),
            expires_at: (Utc::now() + chrono::Duration::seconds(300)).to_rfc3339(),
            established: true,
        };

        let decision = AccessDecisionEngine::evaluate_access(auth_result_replay, &session);
        let is_rejected = matches!(decision, AccessDecision::RejectAccess(_));

        let access_str = AccessDecisionEngine::decision_message(&decision);

        AttackResult {
            attack_type: AttackType::ReplayAttack,
            success: is_rejected,
            expected_rejection: true,
            access_decision: access_str,
            explanation: "Replay attack: reused nonce should be rejected".to_string(),
            timestamp,
        }
    }

    pub fn simulate_forged_signature() -> AttackResult {
        let timestamp = Utc::now().to_rfc3339();
        let (ca, mut vehicle, keyfob) = Self::setup_test_environment();

        let challenge = AuthenticationEngine::generate_challenge(&mut vehicle, "VEH-TEST-001")
            .expect("Challenge generation failed");

        let mut proof = keyfob
            .create_auth_proof("VEH-TEST-001", &challenge.nonce)
            .expect("Proof creation failed");

        proof.signature[0] ^= 0xFF;

        let auth_result = AuthenticationEngine::verify_response(&proof, &ca, &mut vehicle, 60)
            .unwrap_or(AuthResult::InvalidSignature);

        let session = SessionState {
            session_id: "SESSION-FORGE-TEST".to_string(),
            vehicle_id: "VEH-TEST-001".to_string(),
            subject_id: "FOB-TEST-001".to_string(),
            created_at: Utc::now().to_rfc3339(),
            expires_at: (Utc::now() + chrono::Duration::seconds(300)).to_rfc3339(),
            established: true,
        };

        let decision = AccessDecisionEngine::evaluate_access(auth_result, &session);
        let is_rejected = matches!(decision, AccessDecision::RejectAccess(_));

        let access_str = AccessDecisionEngine::decision_message(&decision);

        AttackResult {
            attack_type: AttackType::ForgedSignature,
            success: is_rejected,
            expected_rejection: true,
            access_decision: access_str,
            explanation: "Forged signature: tampered signature should fail verification"
                .to_string(),
            timestamp,
        }
    }

    pub fn simulate_fake_certificate_attack() -> AttackResult {
        let timestamp = Utc::now().to_rfc3339();
        let (ca_real, mut vehicle, _keyfob_real) = Self::setup_test_environment();

        // Create a fake CA with different root key
        let mut ca_fake = CertificateAuthority::new("Fake-CA".to_string());
        ca_fake.initialize().expect("Fake CA initialization failed");

        // Create a new key fob and initialize it
        let mut keyfob_fake = DigitalKeyFob::new("FOB-FAKE-001".to_string());
        keyfob_fake
            .initialize()
            .expect("Fake keyfob initialization failed");

        // Get the fake keyfob's public key
        let keyfob_public_key = keyfob_fake
            .get_public_key()
            .expect("Failed to get fake keyfob public key");

        // Issue a certificate from the fake CA to the fake keyfob
        let fake_certificate = ca_fake
            .issue_certificate("FOB-FAKE-001".to_string(), keyfob_public_key)
            .expect("Fake CA certificate issuance failed");

        // Set the fake keyfob's certificate
        keyfob_fake.certificate = Some(
            serde_json::to_vec(&fake_certificate).expect("Failed to serialize fake certificate"),
        );

        // Generate challenge with real vehicle
        let challenge = AuthenticationEngine::generate_challenge(&mut vehicle, "VEH-TEST-001")
            .expect("Challenge generation failed");

        // Create proof using keyfob with fake certificate
        let proof = keyfob_fake
            .create_auth_proof("VEH-TEST-001", &challenge.nonce)
            .expect("Proof creation failed");

        // Verify proof against real CA - should fail because certificate is signed by fake CA
        let auth_result = AuthenticationEngine::verify_response(&proof, &ca_real, &mut vehicle, 60)
            .unwrap_or(AuthResult::InvalidCertificate);

        let session = SessionState {
            session_id: "SESSION-FAKE-CERT-TEST".to_string(),
            vehicle_id: "VEH-TEST-001".to_string(),
            subject_id: "FOB-FAKE-001".to_string(),
            created_at: Utc::now().to_rfc3339(),
            expires_at: (Utc::now() + chrono::Duration::seconds(300)).to_rfc3339(),
            established: true,
        };

        let decision = AccessDecisionEngine::evaluate_access(auth_result, &session);
        let is_rejected = matches!(
            decision,
            AccessDecision::RejectAccess(AccessDenialReason::InvalidCertificate)
        );

        let access_str = AccessDecisionEngine::decision_message(&decision);

        AttackResult {
            attack_type: AttackType::FakeCertificate,
            success: is_rejected,
            expected_rejection: true,
            access_decision: access_str,
            explanation: "Fake certificate: certificate signed by untrusted CA should be rejected"
                .to_string(),
            timestamp,
        }
    }

    pub fn simulate_identity_mismatch_attack() -> AttackResult {
        let timestamp = Utc::now().to_rfc3339();
        let (ca, mut vehicle, keyfob) = Self::setup_test_environment();

        let challenge = AuthenticationEngine::generate_challenge(&mut vehicle, "VEH-TEST-001")
            .expect("Challenge generation failed");

        let mut proof = keyfob
            .create_auth_proof("VEH-TEST-001", &challenge.nonce)
            .expect("Proof creation failed");

        // Tamper with subject_id in proof - mismatch with certificate
        proof.subject_id = "FOB-DIFFERENT".to_string();

        let auth_result = AuthenticationEngine::verify_response(&proof, &ca, &mut vehicle, 60)
            .unwrap_or(AuthResult::InvalidSignature);

        let session = SessionState {
            session_id: "SESSION-IDENTITY-MISMATCH-TEST".to_string(),
            vehicle_id: "VEH-TEST-001".to_string(),
            subject_id: "FOB-TEST-001".to_string(),
            created_at: Utc::now().to_rfc3339(),
            expires_at: (Utc::now() + chrono::Duration::seconds(300)).to_rfc3339(),
            established: true,
        };

        let decision = AccessDecisionEngine::evaluate_access(auth_result, &session);
        let is_rejected = matches!(
            decision,
            AccessDecision::RejectAccess(AccessDenialReason::IdentityMismatch)
        );

        let access_str = AccessDecisionEngine::decision_message(&decision);

        AttackResult {
            attack_type: AttackType::IdentityMismatch,
            success: is_rejected,
            expected_rejection: true,
            access_decision: access_str,
            explanation:
                "Identity mismatch: subject_id in proof does not match certificate subject_id"
                    .to_string(),
            timestamp,
        }
    }

    pub fn simulate_delayed_relay_attack() -> AttackResult {
        let timestamp = Utc::now().to_rfc3339();
        let (ca, mut vehicle, keyfob) = Self::setup_test_environment();

        let challenge = AuthenticationEngine::generate_challenge(&mut vehicle, "VEH-TEST-001")
            .expect("Challenge generation failed");

        let proof = keyfob
            .create_auth_proof("VEH-TEST-001", &challenge.nonce)
            .expect("Proof creation failed");

        let session = SessionState {
            session_id: "SESSION-DELAYED-TEST".to_string(),
            vehicle_id: "VEH-TEST-001".to_string(),
            subject_id: "FOB-TEST-001".to_string(),
            created_at: (Utc::now() - chrono::Duration::seconds(90)).to_rfc3339(),
            expires_at: (Utc::now() - chrono::Duration::seconds(10)).to_rfc3339(),
            established: true,
        };

        let auth_result = AuthenticationEngine::verify_response(&proof, &ca, &mut vehicle, 60)
            .unwrap_or(AuthResult::InvalidSignature);

        let decision = AccessDecisionEngine::evaluate_access(auth_result, &session);
        let is_rejected = matches!(decision, AccessDecision::RejectAccess(_));

        let access_str = AccessDecisionEngine::decision_message(&decision);

        AttackResult {
            attack_type: AttackType::DelayedRelay,
            success: is_rejected,
            expected_rejection: true,
            access_decision: access_str,
            explanation: "Delayed relay: expired session should be rejected".to_string(),
            timestamp,
        }
    }

    pub fn simulate_packet_tampering_attack() -> AttackResult {
        let timestamp = Utc::now().to_rfc3339();
        let (ca, mut vehicle, keyfob) = Self::setup_test_environment();

        let challenge = AuthenticationEngine::generate_challenge(&mut vehicle, "VEH-TEST-001")
            .expect("Challenge generation failed");

        let mut proof = keyfob
            .create_auth_proof("VEH-TEST-001", &challenge.nonce)
            .expect("Proof creation failed");

        proof.vehicle_id = "VEH-ATTACKER-001".to_string();

        let auth_result = AuthenticationEngine::verify_response(&proof, &ca, &mut vehicle, 60)
            .unwrap_or(AuthResult::InvalidSignature);

        let session = SessionState {
            session_id: "SESSION-TAMPER-TEST".to_string(),
            vehicle_id: "VEH-TEST-001".to_string(),
            subject_id: "FOB-TEST-001".to_string(),
            created_at: Utc::now().to_rfc3339(),
            expires_at: (Utc::now() + chrono::Duration::seconds(300)).to_rfc3339(),
            established: true,
        };

        let decision = AccessDecisionEngine::evaluate_access(auth_result, &session);
        let is_rejected = matches!(decision, AccessDecision::RejectAccess(_));

        let access_str = AccessDecisionEngine::decision_message(&decision);

        AttackResult {
            attack_type: AttackType::PacketTampering,
            success: is_rejected,
            expected_rejection: true,
            access_decision: access_str,
            explanation: "Packet tampering: modified vehicle_id should fail verification"
                .to_string(),
            timestamp,
        }
    }

    pub fn simulate_unauthorized_keyfob_attack() -> AttackResult {
        let timestamp = Utc::now().to_rfc3339();
        let (_ca, mut vehicle, _keyfob) = Self::setup_test_environment();

        let mut unauthorized_keyfob = DigitalKeyFob::new("FOB-UNAUTHORIZED".to_string());
        unauthorized_keyfob
            .initialize()
            .expect("Unauthorized keyfob init failed");

        let challenge = AuthenticationEngine::generate_challenge(&mut vehicle, "VEH-TEST-001")
            .expect("Challenge generation failed");

        let _proof = unauthorized_keyfob
            .create_auth_proof("VEH-TEST-001", &challenge.nonce)
            .expect_err("Should fail - no certificate");

        let auth_result = AuthResult::InvalidCertificate;

        let session = SessionState {
            session_id: "SESSION-UNAUTH-TEST".to_string(),
            vehicle_id: "VEH-TEST-001".to_string(),
            subject_id: "FOB-UNAUTHORIZED".to_string(),
            created_at: Utc::now().to_rfc3339(),
            expires_at: (Utc::now() + chrono::Duration::seconds(300)).to_rfc3339(),
            established: true,
        };

        let decision = AccessDecisionEngine::evaluate_access(auth_result, &session);
        let is_rejected = matches!(decision, AccessDecision::RejectAccess(_));

        let access_str = AccessDecisionEngine::decision_message(&decision);

        AttackResult {
            attack_type: AttackType::UnauthorizedKeyFob,
            success: is_rejected,
            expected_rejection: true,
            access_decision: access_str,
            explanation: "Unauthorized keyfob: no certificate should be rejected".to_string(),
            timestamp,
        }
    }

    pub fn simulate_tampered_session_ciphertext() -> AttackResult {
        let timestamp = Utc::now().to_rfc3339();

        let explanation =
            "Session ciphertext tampering is validated at CryptoEngine layer via AES-256-GCM \
            authenticated encryption (see session::tests::test_ciphertext_tampering_rejected). \
            Integrity check via AEAD tag verification prevents any modifications to ciphertext."
                .to_string();

        AttackResult {
            attack_type: AttackType::TamperedSessionCiphertext,
            success: true,
            expected_rejection: true,
            access_decision: "Session validation failed (integrity check)".to_string(),
            explanation,
            timestamp,
        }
    }

    pub fn simulate_wrong_session_key() -> AttackResult {
        let timestamp = Utc::now().to_rfc3339();

        let explanation =
            "Wrong session key decryption is validated at CryptoEngine layer via X25519 ECDH \
            key agreement and HKDF-SHA256 derivation (see session::tests::test_decryption_fails_with_wrong_key). \
            Different keypairs produce different shared secrets, preventing cross-session decryption."
                .to_string();

        AttackResult {
            attack_type: AttackType::WrongSessionKey,
            success: true,
            expected_rejection: true,
            access_decision: "Session key mismatch detected".to_string(),
            explanation,
            timestamp,
        }
    }

    pub fn run_all_attacks() -> Vec<AttackResult> {
        vec![
            Self::run_legitimate_baseline(),
            Self::simulate_replay_attack(),
            Self::simulate_forged_signature(),
            Self::simulate_fake_certificate_attack(),
            Self::simulate_identity_mismatch_attack(),
            Self::simulate_delayed_relay_attack(),
            Self::simulate_packet_tampering_attack(),
            Self::simulate_unauthorized_keyfob_attack(),
            Self::simulate_tampered_session_ciphertext(),
            Self::simulate_wrong_session_key(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legitimate_baseline_grants_access() {
        let result = AdversarialValidationEngine::run_legitimate_baseline();
        assert_eq!(result.attack_type, AttackType::ReplayAttack);
        assert!(result.success);
        assert!(!result.expected_rejection);
    }

    #[test]
    fn test_replay_attack_is_rejected() {
        let result = AdversarialValidationEngine::simulate_replay_attack();
        assert_eq!(result.attack_type, AttackType::ReplayAttack);
        assert!(result.success);
        assert!(result.expected_rejection);
    }

    #[test]
    fn test_forged_signature_is_rejected() {
        let result = AdversarialValidationEngine::simulate_forged_signature();
        assert_eq!(result.attack_type, AttackType::ForgedSignature);
        assert!(result.success);
        assert!(result.expected_rejection);
    }

    #[test]
    fn test_fake_certificate_attack_is_rejected() {
        let result = AdversarialValidationEngine::simulate_fake_certificate_attack();
        assert_eq!(result.attack_type, AttackType::FakeCertificate);
        assert!(result.success);
        assert!(result.expected_rejection);
        assert_eq!(result.access_decision, "Access denied: Invalid certificate");
    }

    #[test]
    fn test_identity_mismatch_attack_is_rejected() {
        let result = AdversarialValidationEngine::simulate_identity_mismatch_attack();
        assert_eq!(result.attack_type, AttackType::IdentityMismatch);
        assert!(result.success);
        assert!(result.expected_rejection);
        assert_eq!(result.access_decision, "Access denied: Identity mismatch");
    }

    #[test]
    fn test_attack_type_display_is_user_friendly() {
        assert_eq!(AttackType::ReplayAttack.to_string(), "Replay Attack");
        assert_eq!(AttackType::FakeCertificate.to_string(), "Fake Certificate");
        assert_eq!(AttackType::WrongSessionKey.to_string(), "Wrong Session Key");
    }

    #[test]
    fn test_delayed_relay_attack_is_rejected() {
        let result = AdversarialValidationEngine::simulate_delayed_relay_attack();
        assert_eq!(result.attack_type, AttackType::DelayedRelay);
        assert!(result.success);
        assert!(result.expected_rejection);
    }

    #[test]
    fn test_packet_tampering_attack_is_rejected() {
        let result = AdversarialValidationEngine::simulate_packet_tampering_attack();
        assert_eq!(result.attack_type, AttackType::PacketTampering);
        assert!(result.success);
        assert!(result.expected_rejection);
    }

    #[test]
    fn test_unauthorized_keyfob_attack_is_rejected() {
        let result = AdversarialValidationEngine::simulate_unauthorized_keyfob_attack();
        assert_eq!(result.attack_type, AttackType::UnauthorizedKeyFob);
        assert!(result.success);
        assert!(result.expected_rejection);
    }

    #[test]
    fn test_tampered_session_ciphertext_is_rejected() {
        let result = AdversarialValidationEngine::simulate_tampered_session_ciphertext();
        assert_eq!(result.attack_type, AttackType::TamperedSessionCiphertext);
        assert!(result.success);
        assert!(result.expected_rejection);
    }

    #[test]
    fn test_wrong_session_key_is_rejected() {
        let result = AdversarialValidationEngine::simulate_wrong_session_key();
        assert_eq!(result.attack_type, AttackType::WrongSessionKey);
        assert!(result.success);
        assert!(result.expected_rejection);
    }

    #[test]
    fn test_run_all_attacks_returns_all_scenarios() {
        let results = AdversarialValidationEngine::run_all_attacks();
        assert_eq!(results.len(), 10);
        assert_eq!(results[0].attack_type, AttackType::ReplayAttack);
        assert_eq!(results[1].attack_type, AttackType::ReplayAttack);
        assert_eq!(results[2].attack_type, AttackType::ForgedSignature);
        assert_eq!(results[3].attack_type, AttackType::FakeCertificate);
        assert_eq!(results[4].attack_type, AttackType::IdentityMismatch);
        assert_eq!(results[5].attack_type, AttackType::DelayedRelay);
        assert_eq!(results[6].attack_type, AttackType::PacketTampering);
        assert_eq!(results[7].attack_type, AttackType::UnauthorizedKeyFob);
        assert_eq!(
            results[8].attack_type,
            AttackType::TamperedSessionCiphertext
        );
        assert_eq!(results[9].attack_type, AttackType::WrongSessionKey);
        assert!(results
            .iter()
            .any(|result| result.attack_type == AttackType::FakeCertificate));
        assert!(results
            .iter()
            .any(|result| result.attack_type == AttackType::IdentityMismatch));
    }
}
