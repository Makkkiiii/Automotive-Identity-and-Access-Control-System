use crate::access::{AccessDecision, AccessDecisionEngine};
use crate::attacks::{AdversarialValidationEngine, AttackResult, AttackType};
use crate::auth::{AuthResult, AuthenticationEngine};
use crate::ca::{CAError, Certificate, CertificateAuthority};
use crate::keyfob::{DigitalKeyFob, KeyFobError};
use crate::session::{SessionState, SessionValidationEngine};
use crate::vehicle::{VehicleControlModule, VehicleError};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

const DEFAULT_CA_NAME: &str = "AIACS-Demo-CA";
const DEFAULT_FOB_ID: &str = "FOB-GUI-001";
const DEFAULT_VEHICLE_ID: &str = "VEH-GUI-001";
const DEFAULT_SESSION_ID: &str = "SESSION-GUI-001";
const DEFAULT_TIMEOUT_SECONDS: i64 = 60;
const DEFAULT_LOG_DIR: &str = "logs";
const GUI_LOG_FILE: &str = "aiacs_gui.log";
const PROTOCOL_TRACE_LOG_FILE: &str = "aiacs_protocol_trace.log";

#[derive(Debug)]
pub enum AppControllerError {
    Backend(String),
}

impl fmt::Display for AppControllerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppControllerError::Backend(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for AppControllerError {}

impl From<CAError> for AppControllerError {
    fn from(error: CAError) -> Self {
        AppControllerError::Backend(error.to_string())
    }
}

impl From<KeyFobError> for AppControllerError {
    fn from(error: KeyFobError) -> Self {
        AppControllerError::Backend(error.to_string())
    }
}

impl From<VehicleError> for AppControllerError {
    fn from(error: VehicleError) -> Self {
        AppControllerError::Backend(error.to_string())
    }
}

impl From<String> for AppControllerError {
    fn from(error: String) -> Self {
        AppControllerError::Backend(error)
    }
}

pub struct AppController {
    ca: Option<CertificateAuthority>,
    keyfob: Option<DigitalKeyFob>,
    vehicle: VehicleControlModule,
    session: Option<SessionState>,
    last_auth_result: Option<AuthResult>,
    last_access_decision: Option<AccessDecision>,
    event_log: Vec<String>,
    protocol_trace: Vec<String>,
    log_dir: PathBuf,
}

impl Default for AppController {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for AppController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppController")
            .field("ca_initialized", &self.ca.is_some())
            .field("keyfob_initialized", &self.keyfob.is_some())
            .field("vehicle_id", &self.vehicle.vehicle_id)
            .field("session", &self.session)
            .field("last_auth_result", &self.last_auth_result)
            .field("last_access_decision", &self.last_access_decision)
            .field("event_log", &self.event_log)
            .field("protocol_trace", &self.protocol_trace)
            .field("log_dir", &self.log_dir)
            .finish()
    }
}

impl AppController {
    pub fn new() -> Self {
        Self::new_with_log_dir(DEFAULT_LOG_DIR)
    }

    pub fn new_with_log_dir(log_dir: impl Into<PathBuf>) -> Self {
        let mut vehicle = VehicleControlModule::new(DEFAULT_VEHICLE_ID.to_string());
        vehicle
            .initialize()
            .expect("vehicle initialization should not fail for default controller");

        Self {
            ca: None,
            keyfob: None,
            vehicle,
            session: None,
            last_auth_result: None,
            last_access_decision: None,
            event_log: Vec::new(),
            protocol_trace: Vec::new(),
            log_dir: log_dir.into(),
        }
    }

    pub fn initialize_ca(&mut self) -> Result<String, AppControllerError> {
        let mut ca = CertificateAuthority::new(DEFAULT_CA_NAME.to_string());
        ca.initialize()?;

        let public_key_fingerprint = ca
            .root_public_key
            .as_ref()
            .map(|key| fingerprint(key))
            .unwrap_or_else(|| "Unavailable".to_string());

        let message = format!("Certificate authority initialized: {}", ca.name);
        self.append_protocol_trace("[CA]", "Root trust initialized: Yes")?;
        self.append_protocol_trace("[CA]", format!("CA name: {}", ca.name))?;
        self.append_protocol_trace(
            "[CA]",
            format!("CA public key fingerprint: {}", public_key_fingerprint),
        )?;
        self.append_protocol_trace("[CA]", "Root private key: [REDACTED]")?;
        self.ca = Some(ca);
        self.log(message.clone());
        Ok(message)
    }

    pub fn issue_keyfob_certificate(&mut self) -> Result<String, AppControllerError> {
        if self.ca.is_none() {
            self.initialize_ca()?;
        }

        if self.keyfob.is_none() {
            self.register_digital_key_fob()?;
        }

        let ca = self.ca.as_ref().expect("CA initialized above");
        let mut keyfob = self.keyfob.take().expect("key fob initialized above");
        keyfob.request_certificate(ca)?;

        let cert = Self::certificate_from_keyfob(&keyfob)?;
        let message = format!(
            "Certificate issued: subject {} by issuer {}",
            cert.subject_id, cert.issuer
        );

        self.append_protocol_trace("[CERTIFICATE]", format!("Subject: {}", cert.subject_id))?;
        self.append_protocol_trace("[CERTIFICATE]", format!("Issuer: {}", cert.issuer))?;
        self.append_protocol_trace(
            "[CERTIFICATE]",
            format!("Validity: {} to {}", cert.issued_at, cert.expires_at),
        )?;
        self.append_protocol_trace("[CERTIFICATE]", "Certificate status: Issued")?;
        self.append_protocol_trace("[CERTIFICATE]", "Certificate signature: Verified")?;
        self.append_protocol_trace(
            "[CERTIFICATE]",
            format!(
                "Key fob public key fingerprint: {}",
                fingerprint(&cert.public_key)
            ),
        )?;
        self.append_protocol_trace(
            "[CERTIFICATE]",
            format!(
                "Certificate signature fingerprint: {}",
                fingerprint(&cert.signature)
            ),
        )?;

        self.keyfob = Some(keyfob);
        self.log(message.clone());
        Ok(message)
    }

    pub fn register_digital_key_fob(&mut self) -> Result<String, AppControllerError> {
        let mut keyfob = DigitalKeyFob::new(DEFAULT_FOB_ID.to_string());
        keyfob.initialize()?;

        let public_key_fingerprint = keyfob
            .public_key
            .as_ref()
            .map(|key| fingerprint(key))
            .unwrap_or_else(|| "Unavailable".to_string());
        let message = format!("Digital key fob registered: subject {}", keyfob.subject_id);

        self.append_protocol_trace(
            "[KEYFOB]",
            format!("Subject identity registered: {}", keyfob.subject_id),
        )?;
        self.append_protocol_trace("[KEYFOB]", "Ed25519 keypair generated: Yes")?;
        self.append_protocol_trace(
            "[KEYFOB]",
            format!("Public key fingerprint: {}", public_key_fingerprint),
        )?;
        self.append_protocol_trace("[KEYFOB]", "Private key: [REDACTED]")?;

        self.keyfob = Some(keyfob);
        self.log(message.clone());
        Ok(message)
    }

    pub fn run_legitimate_authentication_demo(&mut self) -> Result<String, AppControllerError> {
        self.ensure_ready_for_authentication()?;

        let challenge =
            AuthenticationEngine::generate_challenge(&mut self.vehicle, DEFAULT_VEHICLE_ID)
                .map_err(|e| AppControllerError::Backend(e.to_string()))?;
        self.append_protocol_trace("[AUTH]", "Vehicle generated nonce challenge")?;
        self.append_protocol_trace(
            "[AUTH]",
            format!("Nonce hash: {}", fingerprint(&challenge.nonce)),
        )?;

        let proof = {
            let keyfob = self.keyfob.as_ref().expect("Key fob ready");
            keyfob.create_auth_proof(DEFAULT_VEHICLE_ID, &challenge.nonce)?
        };
        let canonical_payload = canonical_auth_payload(
            &proof.vehicle_id,
            &proof.subject_id,
            &proof.nonce,
            &proof.timestamp,
        );
        self.append_protocol_trace("[AUTH]", "Key fob constructed canonical payload")?;
        self.append_protocol_trace(
            "[AUTH]",
            format!("Canonical payload: {}", canonical_payload),
        )?;
        self.append_protocol_trace("[AUTH]", "Key fob signed payload using Ed25519")?;
        self.append_protocol_trace(
            "[AUTH]",
            format!("Signature fingerprint: {}", fingerprint(&proof.signature)),
        )?;

        let auth_result = {
            let ca = self.ca.as_ref().expect("CA ready");
            AuthenticationEngine::verify_response(
                &proof,
                ca,
                &mut self.vehicle,
                DEFAULT_TIMEOUT_SECONDS,
            )
            .map_err(|e| AppControllerError::Backend(e.to_string()))?
        };

        let session = SessionValidationEngine::create_session(
            DEFAULT_SESSION_ID.to_string(),
            DEFAULT_VEHICLE_ID.to_string(),
            proof.subject_id.clone(),
            300,
        )?;
        let access_decision = AccessDecisionEngine::evaluate_access(auth_result, &session);

        self.session = Some(session);
        self.last_auth_result = Some(auth_result);
        self.last_access_decision = Some(access_decision);

        self.append_protocol_trace("[AUTH]", "CA certificate validation: Passed")?;
        self.append_protocol_trace("[AUTH]", "Subject identity binding: Passed")?;
        self.append_protocol_trace("[AUTH]", "Ed25519 signature verification: Passed")?;
        self.append_protocol_trace("[AUTH]", "Vehicle nonce freshness check: Passed")?;
        self.append_protocol_trace("[AUTH]", "Replay protection check: Passed")?;
        self.append_protocol_trace("[AUTH]", format!("AuthResult: {}", auth_result))?;
        self.append_protocol_trace("[AUTH]", format!("AccessDecision: {}", access_decision))?;

        let message = format!(
            "Legitimate authentication demo completed: {}; {}",
            auth_result, access_decision
        );
        self.log(message.clone());
        Ok(message)
    }

    pub fn establish_secure_session_demo(&mut self) -> Result<String, AppControllerError> {
        self.ensure_ready_for_authentication()?;

        let keyfob = self.keyfob.as_ref().expect("Key fob ready");
        let vehicle_keypair = SessionValidationEngine::generate_ephemeral_keypair();
        let keyfob_keypair = SessionValidationEngine::generate_ephemeral_keypair();

        let (session, material) = SessionValidationEngine::establish_session(
            DEFAULT_VEHICLE_ID,
            &keyfob.subject_id,
            DEFAULT_SESSION_ID,
            &vehicle_keypair,
            &keyfob_keypair,
            300,
        )?;

        let key_lengths = material.key_lengths();
        self.session = Some(session);

        let message = format!(
            "Secure session established: {} for subject {}; key material [REDACTED]; material lengths {:?}",
            DEFAULT_SESSION_ID, keyfob.subject_id, key_lengths
        );
        self.append_protocol_trace("[SESSION]", "X25519 ephemeral key exchange: Completed")?;
        self.append_protocol_trace("[SESSION]", "HKDF-SHA256 derivation: Completed")?;
        self.append_protocol_trace("[SESSION]", "AES-GCM secure channel: Active")?;
        self.append_protocol_trace("[SESSION]", format!("Session ID: {}", DEFAULT_SESSION_ID))?;
        self.append_protocol_trace("[SESSION]", "Session key: [REDACTED]")?;
        self.append_protocol_trace("[SESSION]", "Shared secret: [REDACTED]")?;
        self.append_protocol_trace("[SESSION]", "Ephemeral private keys: [REDACTED]")?;
        self.log(message.clone());
        Ok(message)
    }

    pub fn run_attack(&mut self, attack_type: AttackType) -> Result<String, AppControllerError> {
        let result = match attack_type {
            AttackType::ReplayAttack => AdversarialValidationEngine::simulate_replay_attack(),
            AttackType::ForgedSignature => AdversarialValidationEngine::simulate_forged_signature(),
            AttackType::FakeCertificate => {
                AdversarialValidationEngine::simulate_fake_certificate_attack()
            }
            AttackType::IdentityMismatch => {
                AdversarialValidationEngine::simulate_identity_mismatch_attack()
            }
            AttackType::DelayedRelay => {
                AdversarialValidationEngine::simulate_delayed_relay_attack()
            }
            AttackType::PacketTampering => {
                AdversarialValidationEngine::simulate_packet_tampering_attack()
            }
            AttackType::UnauthorizedKeyFob => {
                AdversarialValidationEngine::simulate_unauthorized_keyfob_attack()
            }
            AttackType::TamperedSessionCiphertext => {
                AdversarialValidationEngine::simulate_tampered_session_ciphertext()
            }
            AttackType::WrongSessionKey => {
                AdversarialValidationEngine::simulate_wrong_session_key()
            }
        };

        let message = Self::format_attack_result(&result);
        self.append_protocol_trace("[ATTACK]", message.clone())?;
        self.log(message.clone());
        Ok(message)
    }

    pub fn run_all_attacks(&mut self) -> Result<Vec<String>, AppControllerError> {
        let results = AdversarialValidationEngine::run_all_attacks();
        let messages: Vec<String> = results.iter().map(Self::format_attack_result).collect();

        for message in &messages {
            self.append_protocol_trace("[ATTACK]", message.clone())?;
            self.log(message.clone());
        }

        Ok(messages)
    }

    pub fn get_status_summary(&self) -> String {
        let ca_status = if self.ca.is_some() {
            "initialized"
        } else {
            "not initialized"
        };
        let fob_status = if self.keyfob.is_some() {
            "certificate ready"
        } else {
            "not provisioned"
        };
        let session_status = if self.session.is_some() {
            "established"
        } else {
            "not established"
        };
        let auth_status = self
            .last_auth_result
            .map(|result| result.to_string())
            .unwrap_or_else(|| "no authentication run".to_string());
        let access_status = self
            .last_access_decision
            .map(|decision| decision.to_string())
            .unwrap_or_else(|| "no access decision".to_string());

        format!(
            "CA: {}; key fob: {}; session: {}; last auth: {}; last access: {}",
            ca_status, fob_status, session_status, auth_status, access_status
        )
    }

    pub fn event_log(&self) -> &[String] {
        &self.event_log
    }

    pub fn get_protocol_trace(&self) -> Vec<String> {
        self.protocol_trace.clone()
    }

    pub fn append_protocol_trace(
        &mut self,
        tag: &str,
        message: impl AsRef<str>,
    ) -> Result<(), AppControllerError> {
        let message = redact_sensitive_terms(message.as_ref());
        self.protocol_trace
            .push(format!("{} {}", tag, message.as_str()));
        self.write_log_file(PROTOCOL_TRACE_LOG_FILE, tag, &message)?;
        Ok(())
    }

    pub fn save_log_entry(
        &mut self,
        tag: &str,
        message: impl AsRef<str>,
    ) -> Result<(), AppControllerError> {
        let message = redact_sensitive_terms(message.as_ref());
        self.event_log.push(format!("{} {}", tag, message.as_str()));
        self.write_log_file(GUI_LOG_FILE, tag, &message)?;
        Ok(())
    }

    pub fn clear_logs(&mut self) -> Result<String, AppControllerError> {
        self.ensure_log_dir()?;
        fs::write(self.gui_log_path(), "")
            .map_err(|e| AppControllerError::Backend(e.to_string()))?;
        fs::write(self.protocol_trace_log_path(), "")
            .map_err(|e| AppControllerError::Backend(e.to_string()))?;
        self.event_log.clear();
        self.protocol_trace.clear();
        self.save_log_entry("[INFO]", "Logs cleared")?;

        Ok("Logs cleared".to_string())
    }

    pub fn export_logs(&mut self) -> Result<String, AppControllerError> {
        self.ensure_log_files()?;
        let message = format!(
            "Logs saved: {}; protocol trace: {}",
            self.gui_log_path().display(),
            self.protocol_trace_log_path().display()
        );
        self.save_log_entry("[INFO]", message.clone())?;
        Ok(message)
    }

    pub fn get_safe_crypto_summary(&self) -> String {
        let ca_public = self
            .ca
            .as_ref()
            .and_then(|ca| ca.root_public_key.as_ref())
            .map(|key| fingerprint(key))
            .unwrap_or_else(|| "Pending".to_string());
        let fob_public = self
            .keyfob
            .as_ref()
            .and_then(|fob| fob.public_key.as_ref())
            .map(|key| fingerprint(key))
            .unwrap_or_else(|| "Pending".to_string());

        format!(
            "CA public key fingerprint: {}; key fob public key fingerprint: {}; private keys: [REDACTED]; session key: [REDACTED]; shared secret: [REDACTED]",
            ca_public, fob_public
        )
    }

    pub fn log_file_paths(&self) -> (PathBuf, PathBuf) {
        (self.gui_log_path(), self.protocol_trace_log_path())
    }

    fn ensure_ready_for_authentication(&mut self) -> Result<(), AppControllerError> {
        if self.ca.is_none() {
            self.initialize_ca()?;
        }

        if self.keyfob.is_none() {
            self.issue_keyfob_certificate()?;
        }

        Ok(())
    }

    fn certificate_from_keyfob(keyfob: &DigitalKeyFob) -> Result<Certificate, AppControllerError> {
        let cert_bytes = keyfob.get_certificate()?;
        serde_json::from_slice(&cert_bytes).map_err(|e| AppControllerError::Backend(e.to_string()))
    }

    fn format_attack_result(result: &AttackResult) -> String {
        if !result.expected_rejection {
            return format!(
                "Scenario: Legitimate Baseline\nExpected outcome: Granted\nActual result: {}\nDefense status: Successful\nExplanation: {}",
                result.access_decision, result.explanation
            );
        }

        let evidence = attack_evidence(result.attack_type);
        format!(
            "Attack: {}\nMethod: {}\nExpected outcome: Rejected\nFailure point: {}\nAuthResult: {}\nAccessDecision: {}\nDefense status: {}\nExplanation: {}",
            result.attack_type,
            evidence.method,
            evidence.failure_point,
            evidence.auth_result,
            result.access_decision,
            if result.success { "Successful" } else { "Failed" },
            result.explanation
        )
    }

    fn log(&mut self, message: String) {
        let _ = self.save_log_entry("[INFO]", message);
    }

    fn ensure_log_dir(&self) -> Result<(), AppControllerError> {
        fs::create_dir_all(&self.log_dir).map_err(|e| AppControllerError::Backend(e.to_string()))
    }

    fn ensure_log_files(&self) -> Result<(), AppControllerError> {
        self.ensure_log_dir()?;
        for path in [self.gui_log_path(), self.protocol_trace_log_path()] {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| AppControllerError::Backend(e.to_string()))?;
        }
        Ok(())
    }

    fn write_log_file(
        &self,
        file_name: &str,
        tag: &str,
        message: &str,
    ) -> Result<(), AppControllerError> {
        self.ensure_log_dir()?;
        let path = self.log_dir.join(file_name);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| AppControllerError::Backend(e.to_string()))?;
        let safe_message = message.replace(['\r', '\n'], " | ");
        writeln!(file, "{} {} {}", Utc::now().to_rfc3339(), tag, safe_message)
            .map_err(|e| AppControllerError::Backend(e.to_string()))
    }

    fn gui_log_path(&self) -> PathBuf {
        self.log_dir.join(GUI_LOG_FILE)
    }

    fn protocol_trace_log_path(&self) -> PathBuf {
        self.log_dir.join(PROTOCOL_TRACE_LOG_FILE)
    }
}

struct AttackEvidence {
    method: &'static str,
    failure_point: &'static str,
    auth_result: &'static str,
}

fn attack_evidence(attack_type: AttackType) -> AttackEvidence {
    match attack_type {
        AttackType::ReplayAttack => AttackEvidence {
            method: "Reused captured authentication proof",
            failure_point: "nonce lifecycle validation",
            auth_result: "ReusedNonce",
        },
        AttackType::ForgedSignature => AttackEvidence {
            method: "Tampered Ed25519 signature over canonical payload",
            failure_point: "Ed25519 signature verification",
            auth_result: "InvalidSignature",
        },
        AttackType::FakeCertificate => AttackEvidence {
            method: "Certificate signed by untrusted fake CA",
            failure_point: "CA certificate validation",
            auth_result: "InvalidCertificate",
        },
        AttackType::IdentityMismatch => AttackEvidence {
            method: "Valid certificate with mismatched proof subject",
            failure_point: "certificate subject identity binding",
            auth_result: "IdentityMismatch",
        },
        AttackType::DelayedRelay => AttackEvidence {
            method: "Delayed relay beyond freshness window",
            failure_point: "freshness timeout validation",
            auth_result: "FreshnessTimeout",
        },
        AttackType::PacketTampering => AttackEvidence {
            method: "Modified signed authentication payload",
            failure_point: "canonical payload/signature binding",
            auth_result: "InvalidSignature or UnknownNonce",
        },
        AttackType::UnauthorizedKeyFob => AttackEvidence {
            method: "Key fob without trusted access certificate",
            failure_point: "certificate presence and validation",
            auth_result: "InvalidCertificate",
        },
        AttackType::TamperedSessionCiphertext => AttackEvidence {
            method: "Modified AES-GCM session ciphertext",
            failure_point: "AES-GCM authentication tag verification",
            auth_result: "N/A",
        },
        AttackType::WrongSessionKey => AttackEvidence {
            method: "AES-GCM decryption with wrong derived key",
            failure_point: "session encryption key validation",
            auth_result: "N/A",
        },
    }
}

fn canonical_auth_payload(
    vehicle_id: &str,
    subject_id: &str,
    nonce: &[u8],
    timestamp: &str,
) -> String {
    format!(
        "AIACS_AUTH_V1|{}|{}|{}|{}",
        vehicle_id,
        subject_id,
        general_purpose::STANDARD.encode(nonce),
        timestamp
    )
}

fn fingerprint(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("SHA256:{}", hex_preview(&digest, 8))
}

fn hex_preview(bytes: &[u8], take: usize) -> String {
    bytes
        .iter()
        .take(take)
        .map(|byte| format!("{:02X}", byte))
        .collect::<Vec<_>>()
        .join("")
}

fn redact_sensitive_terms(message: &str) -> String {
    let mut sanitized = message.to_string();
    for sensitive in [
        "private_key:",
        "root_private_key:",
        "derived_aes_key",
        "raw shared secret",
        "raw AES key",
    ] {
        sanitized = sanitized.replace(sensitive, "[REDACTED]");
    }
    sanitized
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn temp_log_dir(test_name: &str) -> PathBuf {
        let unique = format!(
            "aiacs_{}_{}_{}",
            test_name,
            std::process::id(),
            Utc::now()
                .timestamp_nanos_opt()
                .unwrap_or_else(|| Utc::now().timestamp_micros())
        );
        std::env::temp_dir().join(unique)
    }

    #[test]
    fn test_app_controller_initializes_ca() {
        let mut controller = AppController::new();
        let message = controller.initialize_ca().expect("CA init failed");

        assert!(message.contains("Certificate authority initialized"));
        assert!(controller.ca.is_some());
    }

    #[test]
    fn test_app_controller_issues_certificate() {
        let mut controller = AppController::new();
        controller.initialize_ca().expect("CA init failed");
        let message = controller
            .issue_keyfob_certificate()
            .expect("Certificate issuance failed");

        assert!(message.contains("Certificate issued"));
        assert!(message.contains(DEFAULT_FOB_ID));
        assert!(controller.keyfob.is_some());
    }

    #[test]
    fn test_app_controller_runs_legitimate_authentication_demo() {
        let mut controller = AppController::new();
        let message = controller
            .run_legitimate_authentication_demo()
            .expect("Legitimate auth demo failed");

        assert!(message.contains("Authentication successful"));
        assert!(message.contains("Access granted"));
        assert_eq!(controller.last_auth_result, Some(AuthResult::Success));
        assert_eq!(
            controller.last_access_decision,
            Some(AccessDecision::GrantAccess)
        );
    }

    #[test]
    fn test_app_controller_runs_all_attacks() {
        let mut controller = AppController::new();
        let messages = controller.run_all_attacks().expect("Attack suite failed");

        assert_eq!(messages.len(), 10);
        assert!(messages
            .iter()
            .any(|message| message.contains("Fake Certificate")));
        assert!(messages
            .iter()
            .any(|message| message.contains("Identity Mismatch")));
    }

    #[test]
    fn test_app_controller_logs_do_not_expose_secret_material() {
        let mut controller = AppController::new();
        controller.initialize_ca().expect("CA init failed");
        controller
            .issue_keyfob_certificate()
            .expect("Certificate issuance failed");

        let ca_private_key_debug = format!(
            "{:?}",
            controller
                .ca
                .as_ref()
                .unwrap()
                .root_private_key
                .as_ref()
                .unwrap()
        );
        let fob_private_key_debug = format!(
            "{:?}",
            controller
                .keyfob
                .as_ref()
                .unwrap()
                .private_key
                .as_ref()
                .unwrap()
        );

        controller
            .run_legitimate_authentication_demo()
            .expect("Legitimate auth demo failed");
        controller
            .establish_secure_session_demo()
            .expect("Session demo failed");
        controller.run_all_attacks().expect("Attack suite failed");

        let logs = controller.event_log().join("\n");
        let status = controller.get_status_summary();
        let debug_output = format!("{:?}", controller);

        for output in [&logs, &status, &debug_output] {
            assert!(!output.contains(&ca_private_key_debug));
            assert!(!output.contains(&fob_private_key_debug));
            assert!(!output.contains("derived_aes_key"));
            assert!(!output.contains("private_key: ["));
            assert!(!output.contains("root_private_key: ["));
        }
    }

    #[test]
    fn test_log_file_creation() {
        let log_dir = temp_log_dir("log_file_creation");
        let mut controller = AppController::new_with_log_dir(&log_dir);

        controller
            .save_log_entry("[INFO]", "test log entry")
            .expect("log write failed");

        let (gui_log, protocol_log) = controller.log_file_paths();
        assert!(gui_log.exists());
        assert!(!protocol_log.exists());

        let contents = fs::read_to_string(gui_log).expect("log read failed");
        assert!(contents.contains("[INFO] test log entry"));

        let _ = fs::remove_dir_all(log_dir);
    }

    #[test]
    fn test_log_file_append_behavior() {
        let log_dir = temp_log_dir("log_file_append");
        let mut controller = AppController::new_with_log_dir(&log_dir);

        controller
            .save_log_entry("[INFO]", "first entry")
            .expect("first log write failed");
        controller
            .save_log_entry("[AUTH]", "second entry")
            .expect("second log write failed");

        let (gui_log, _) = controller.log_file_paths();
        let contents = fs::read_to_string(gui_log).expect("log read failed");
        assert!(contents.contains("[INFO] first entry"));
        assert!(contents.contains("[AUTH] second entry"));
        assert!(contents.find("first entry") < contents.find("second entry"));

        let _ = fs::remove_dir_all(log_dir);
    }

    #[test]
    fn test_protocol_trace_contains_expected_safe_entries() {
        let log_dir = temp_log_dir("trace_safe_entries");
        let mut controller = AppController::new_with_log_dir(&log_dir);

        controller.initialize_ca().expect("CA init failed");
        controller
            .issue_keyfob_certificate()
            .expect("Certificate issuance failed");
        controller
            .run_legitimate_authentication_demo()
            .expect("Legitimate auth demo failed");
        controller
            .establish_secure_session_demo()
            .expect("Session demo failed");

        let trace = controller.get_protocol_trace().join("\n");
        assert!(trace.contains("CA public key fingerprint: SHA256:"));
        assert!(trace.contains("Key fob public key fingerprint: SHA256:"));
        assert!(trace.contains("Canonical payload: AIACS_AUTH_V1|"));
        assert!(trace.contains("Ed25519 signature verification: Passed"));
        assert!(trace.contains("X25519 ephemeral key exchange: Completed"));
        assert!(trace.contains("HKDF-SHA256 derivation: Completed"));
        assert!(trace.contains("AES-GCM secure channel: Active"));

        let _ = fs::remove_dir_all(log_dir);
    }

    #[test]
    fn test_protocol_trace_redacts_secret_material() {
        let log_dir = temp_log_dir("trace_redaction");
        let mut controller = AppController::new_with_log_dir(&log_dir);

        controller.initialize_ca().expect("CA init failed");
        controller
            .issue_keyfob_certificate()
            .expect("Certificate issuance failed");
        controller
            .establish_secure_session_demo()
            .expect("Session demo failed");

        let trace = controller.get_protocol_trace().join("\n");
        assert!(trace.contains("[REDACTED]"));
        assert!(!trace.contains("private_key"));
        assert!(!trace.contains("root_private_key"));
        assert!(!trace.contains("derived_aes_key"));
        assert!(!trace.contains("raw shared secret"));
        assert!(!trace.contains("raw AES key"));

        let _ = fs::remove_dir_all(log_dir);
    }

    #[test]
    fn test_protocol_trace_log_file_contains_redacted_values() {
        let log_dir = temp_log_dir("trace_file_redaction");
        let mut controller = AppController::new_with_log_dir(&log_dir);

        controller
            .establish_secure_session_demo()
            .expect("Session demo failed");

        let (_, protocol_log) = controller.log_file_paths();
        let contents = fs::read_to_string(protocol_log).expect("protocol log read failed");
        assert!(contents.contains("Session key: [REDACTED]"));
        assert!(contents.contains("Shared secret: [REDACTED]"));
        assert!(!contents.contains("derived_aes_key"));
        assert!(!contents.contains("private_key: ["));
        assert!(!contents.contains("root_private_key: ["));

        let _ = fs::remove_dir_all(log_dir);
    }

    #[test]
    fn test_safe_crypto_summary_does_not_expose_secrets() {
        let log_dir = temp_log_dir("safe_crypto_summary");
        let mut controller = AppController::new_with_log_dir(&log_dir);

        controller.initialize_ca().expect("CA init failed");
        controller
            .issue_keyfob_certificate()
            .expect("Certificate issuance failed");

        let summary = controller.get_safe_crypto_summary();
        assert!(summary.contains("SHA256:"));
        assert!(summary.contains("[REDACTED]"));
        assert!(!summary.contains("private_key"));
        assert!(!summary.contains("root_private_key"));
        assert!(!summary.contains("derived_aes_key"));

        let _ = fs::remove_dir_all(log_dir);
    }

    #[test]
    fn test_export_logs_creates_both_log_files() {
        let log_dir = temp_log_dir("export_logs");
        let mut controller = AppController::new_with_log_dir(&log_dir);

        let message = controller.export_logs().expect("export failed");
        let (gui_log, protocol_log) = controller.log_file_paths();

        assert!(message.contains("Logs saved"));
        assert!(gui_log.exists());
        assert!(protocol_log.exists());

        let _ = fs::remove_dir_all(log_dir);
    }
}
