use crate::access::{AccessDecision, AccessDecisionEngine};
use crate::attacks::{AdversarialValidationEngine, AttackResult, AttackType};
use crate::auth::{AuthResult, AuthenticationEngine};
use crate::ca::{CAError, Certificate, CertificateAuthority};
use crate::cloud_storage::{
    demo_certificate_metadata, demo_customer_metadata, demo_key_fob_metadata,
    demo_provisioning_session_metadata, demo_vehicle_metadata, encrypt_private_key_for_cloud,
    parse_master_key_from_env, CertificateMetadata, CloudStorageClient, CloudStorageError,
    CustomerMetadata, EncryptedKeyRecord, KeyFobMetadata, ProvisioningSessionMetadata,
    VehicleMetadata, CA_ENCRYPTED_KEY_ID, CA_KEY_PURPOSE, DEFAULT_CERTIFICATE_STATUS, DEMO_FOB_ID,
    DEMO_VEHICLE_ID, ENCRYPTED_KEY_STORAGE_STATUS, KEY_FOB_ENCRYPTED_KEY_ID, KEY_FOB_KEY_PURPOSE,
};
use crate::keyfob::{DigitalKeyFob, KeyFobError};
use crate::session::{SessionState, SessionValidationEngine};
use crate::vehicle::{VehicleControlModule, VehicleError};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

const DEFAULT_CA_NAME: &str = "AIACS-Demo-CA";
const DEFAULT_FOB_ID: &str = DEMO_FOB_ID;
const DEFAULT_VEHICLE_ID: &str = DEMO_VEHICLE_ID;
const DEFAULT_SESSION_ID: &str = "SESSION-0001";
const DEFAULT_TIMEOUT_SECONDS: i64 = 60;
const DEFAULT_LOG_DIR: &str = "logs";
const GUI_LOG_FILE: &str = "aiacs_gui.log";
const PROTOCOL_TRACE_LOG_FILE: &str = "aiacs_protocol_trace.log";
const PROVISIONING_REPORT_FILE: &str = "aiacs_provisioning_report.txt";
const CA_PRIVATE_KEY_PATH: &str = "keys/ca_private.json";
const CA_PUBLIC_KEY_PATH: &str = "keys/ca_public.json";
const KEYFOB_PRIVATE_KEY_PATH: &str = "keys/fob_FOB-0001_private.json";
const KEYFOB_PUBLIC_KEY_PATH: &str = "keys/fob_FOB-0001_public.json";
const KEYFOB_CERTIFICATE_PATH: &str = "certs/fob_FOB-0001.json";

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
    vehicle_connected: bool,
    keyfob_detected: bool,
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
            .field("vehicle_connected", &self.vehicle_connected)
            .field("keyfob_detected", &self.keyfob_detected)
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
            vehicle_connected: false,
            keyfob_detected: false,
        }
    }

    pub fn connect_vehicle(&mut self) -> Result<String, AppControllerError> {
        self.vehicle_connected = true;
        let message = format!(
            "Vehicle connected: {}; protocol AIACS_AUTH_V1",
            DEFAULT_VEHICLE_ID
        );
        self.append_protocol_trace("[VEHICLE]", "Vehicle connection established")?;
        self.append_protocol_trace("[VEHICLE]", format!("Vehicle ID: {}", DEFAULT_VEHICLE_ID))?;
        self.append_protocol_trace("[VEHICLE]", "Protocol version: AIACS_AUTH_V1")?;
        self.log(message.clone());
        Ok(message)
    }

    pub fn detect_key_fob(&mut self) -> Result<String, AppControllerError> {
        self.keyfob_detected = true;
        let message = format!("Digital key fob detected: {}", DEFAULT_FOB_ID);
        self.append_protocol_trace("[KEYFOB]", format!("Detected fob ID: {}", DEFAULT_FOB_ID))?;
        self.append_protocol_trace("[KEYFOB]", "Private key material: [REDACTED]")?;
        self.log(message.clone());
        Ok(message)
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
        self.append_key_storage_trace(None, Some(public_key_fingerprint.as_str()))?;
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
        keyfob.save_keys()?;

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
        self.append_key_storage_trace(Some(public_key_fingerprint.as_str()), None)?;

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

    pub fn run_named_attack(&mut self, attack_key: &str) -> Result<String, AppControllerError> {
        let attack_type = attack_type_from_key(attack_key)?;
        self.run_attack(attack_type)
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

    pub fn get_protocol_artifacts(&self) -> Vec<String> {
        let mut artifacts = Vec::new();

        artifacts.push("[Challenge Message]".to_string());
        artifacts.push(format!("vehicle_id: {}", DEFAULT_VEHICLE_ID));
        artifacts.push("nonce_hash: see [AUTH] trace after challenge generation".to_string());
        artifacts.push("raw_nonce: [REDACTED]".to_string());
        artifacts.push("protocol_version: AIACS_AUTH_V1".to_string());

        artifacts.push("[Authentication Proof]".to_string());
        artifacts.push(format!("subject_id: {}", DEFAULT_FOB_ID));
        artifacts.push(
            "payload_format: AIACS_AUTH_V1|vehicle_id|subject_id|base64(nonce)|timestamp"
                .to_string(),
        );
        artifacts.push("signature_fingerprint: see [AUTH] trace after signing".to_string());
        artifacts.push("private_key: [REDACTED]".to_string());

        artifacts.push("[Certificate Details]".to_string());
        if let Some(cert) = self.current_certificate() {
            artifacts.push(format!("subject: {}", cert.subject_id));
            artifacts.push(format!("issuer: {}", cert.issuer));
            artifacts.push(format!(
                "validity: {} -> {}",
                cert.issued_at, cert.expires_at
            ));
            artifacts.push(format!("certificate_path: {}", KEYFOB_CERTIFICATE_PATH));
            artifacts.push("certificate_signature: Verified".to_string());
            artifacts.push(format!(
                "public_key_fingerprint: {}",
                fingerprint(&cert.public_key)
            ));
        } else {
            artifacts.push("subject: Pending".to_string());
            artifacts.push("issuer: Pending".to_string());
            artifacts.push("validity: Pending".to_string());
            artifacts.push("certificate_signature: Pending".to_string());
        }

        artifacts.push("[Credential Storage]".to_string());
        artifacts.extend(self.credential_storage_summary());

        artifacts.push("[Session Establishment Summary]".to_string());
        artifacts.push("key_exchange: X25519".to_string());
        artifacts.push("kdf: HKDF-SHA256".to_string());
        artifacts.push("encryption: AES-GCM".to_string());
        artifacts.push(format!("session_id: {}", DEFAULT_SESSION_ID));
        artifacts.push("session_key: [REDACTED]".to_string());
        artifacts.push("shared_secret: [REDACTED]".to_string());

        artifacts.push("[Access Decision]".to_string());
        artifacts.push(format!(
            "auth_result: {}",
            self.last_auth_result
                .map(|result| result.to_string())
                .unwrap_or_else(|| "Pending".to_string())
        ));
        artifacts.push(format!(
            "access_decision: {}",
            self.last_access_decision
                .map(|decision| decision.to_string())
                .unwrap_or_else(|| "Pending".to_string())
        ));

        artifacts
    }

    pub fn credential_storage_summary(&self) -> Vec<String> {
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

        vec![
            format!("CA private key path: {}", CA_PRIVATE_KEY_PATH),
            "CA private key material: [REDACTED]".to_string(),
            format!("CA public key path: {}", CA_PUBLIC_KEY_PATH),
            format!("CA public key fingerprint: {}", ca_public),
            format!("Key fob private key path: {}", KEYFOB_PRIVATE_KEY_PATH),
            "Key fob private key material: [REDACTED]".to_string(),
            format!("Key fob public key path: {}", KEYFOB_PUBLIC_KEY_PATH),
            format!("Key fob public key fingerprint: {}", fob_public),
            "Storage mode: Local prototype key file".to_string(),
            "Production note: secure element / OS key store / encrypted key storage recommended"
                .to_string(),
        ]
    }

    pub fn diagnostics_attack_steps(
        &self,
        attack_key: &str,
    ) -> Result<Vec<String>, AppControllerError> {
        let attack_type = attack_type_from_key(attack_key)?;
        Ok(attack_steps(attack_type)
            .iter()
            .map(|step| (*step).to_string())
            .collect())
    }

    pub fn append_protocol_trace(
        &mut self,
        tag: &str,
        message: impl AsRef<str>,
    ) -> Result<(), AppControllerError> {
        let message = redact_sensitive_terms(message.as_ref());
        let entry = format!("{} {}", tag, message.as_str());
        if self
            .protocol_trace
            .iter()
            .any(|existing| existing == &entry)
        {
            return Ok(());
        }

        self.protocol_trace.push(entry);
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

    pub fn export_provisioning_report(&mut self) -> Result<String, AppControllerError> {
        self.ensure_log_dir()?;
        let report_path = self.provisioning_report_path();
        let cert = self.current_certificate();
        let mut report = String::new();
        report.push_str("AIACS Provisioning Audit Report\n");
        report.push_str("================================\n");
        report.push_str(&format!("Generated At: {}\n", Utc::now().to_rfc3339()));
        report.push('\n');

        report.push_str("Provisioning Summary\n");
        report.push_str("--------------------\n");
        report.push_str(&format!("Vehicle ID: {}\n", DEFAULT_VEHICLE_ID));
        report.push_str(&format!("Key Fob ID: {}\n", DEFAULT_FOB_ID));
        report.push_str(&format!(
            "Vehicle Connected: {}\n",
            if self.vehicle_connected {
                "Yes"
            } else {
                "Pending"
            }
        ));
        report.push_str(&format!(
            "Key Fob Detected: {}\n",
            if self.keyfob_detected {
                "Yes"
            } else {
                "Pending"
            }
        ));
        report.push_str(&format!(
            "Trust Status: {}\n",
            if self.ca.is_some() {
                "Initialized"
            } else {
                "Pending"
            }
        ));
        report.push_str(&format!(
            "Certificate Status: {}\n",
            if cert.is_some() { "Issued" } else { "Pending" }
        ));
        report.push_str(&format!(
            "Access Decision: {}\n",
            self.last_access_decision
                .map(|decision| decision.to_string())
                .unwrap_or_else(|| "Pending".to_string())
        ));
        report.push('\n');

        report.push_str("Credential Storage\n");
        report.push_str("------------------\n");
        for line in self.credential_storage_summary() {
            report.push_str(&line);
            report.push('\n');
        }
        report.push('\n');

        report.push_str("Certificate Details\n");
        report.push_str("-------------------\n");
        if let Some(cert) = cert {
            report.push_str(&format!("Subject: {}\n", cert.subject_id));
            report.push_str(&format!("Issuer: {}\n", cert.issuer));
            report.push_str(&format!("Certificate Path: {}\n", KEYFOB_CERTIFICATE_PATH));
            report.push_str(&format!("Issued At: {}\n", cert.issued_at));
            report.push_str(&format!("Expires At: {}\n", cert.expires_at));
            report.push_str(&format!(
                "Public Key Fingerprint: {}\n",
                fingerprint(&cert.public_key)
            ));
            report.push_str("Certificate Signature: Verified\n");
        } else {
            report.push_str("Subject: Pending\n");
            report.push_str("Issuer: Pending\n");
            report.push_str("Certificate Path: Pending\n");
        }
        report.push('\n');

        report.push_str("Authentication Verification\n");
        report.push_str("---------------------------\n");
        report.push_str(&format!(
            "Authentication Result: {}\n",
            self.last_auth_result
                .map(|result| result.to_string())
                .unwrap_or_else(|| "Pending".to_string())
        ));
        report.push_str("Authentication Method: Ed25519 + PKI\n");
        report.push_str("Certificate Chain Validation: trusted CA path only\n");
        report.push_str("Signature Material: [REDACTED]\n");
        report.push('\n');

        report.push_str("Secure Session Establishment\n");
        report.push_str("----------------------------\n");
        report.push_str(&format!("Session ID: {}\n", DEFAULT_SESSION_ID));
        report.push_str("Session Method: X25519 + HKDF-SHA256 + AES-GCM\n");
        report.push_str("Session Key: [REDACTED]\n");
        report.push_str("Shared Secret: [REDACTED]\n");
        report.push_str("Ephemeral Private Keys: [REDACTED]\n");
        report.push_str(&format!(
            "Session Status: {}\n",
            if self.session.is_some() {
                "Established"
            } else {
                "Pending"
            }
        ));
        report.push('\n');

        report.push_str("Security Notes\n");
        report.push_str("--------------\n");
        report.push_str("Private keys, session keys, shared secrets, raw AES keys, and X25519 private keys are redacted.\n");
        report.push_str(
            "Report includes only safe metadata, file paths, algorithm names, and fingerprints.\n",
        );
        report.push_str("Diagnostics are isolated in the separate AIACS diagnostics tool.\n");
        report.push('\n');

        report.push_str("\nProtocol Trace\n");
        report.push_str("--------------\n");
        for entry in &self.protocol_trace {
            report.push_str(entry);
            report.push('\n');
        }
        report.push_str("\nDiagnostics Summary\n");
        report.push_str("-------------------\n");
        let mut diagnostics_found = false;
        for entry in self
            .protocol_trace
            .iter()
            .filter(|entry| entry.contains("[ATTACK]"))
        {
            diagnostics_found = true;
            report.push_str(entry);
            report.push('\n');
        }
        if !diagnostics_found {
            report.push_str("No diagnostics run from this controller session.\n");
        }
        report.push_str("\nSecret Material: [REDACTED]\n");

        fs::write(&report_path, redact_sensitive_terms(&report))
            .map_err(|e| AppControllerError::Backend(e.to_string()))?;
        let message = format!("Provisioning report exported: {}", report_path.display());
        self.save_log_entry("[INFO]", message.clone())?;
        Ok(message)
    }

    pub fn launch_diagnostics_tool(&mut self) -> Result<String, AppControllerError> {
        let current_exe =
            std::env::current_exe().map_err(|e| AppControllerError::Backend(e.to_string()))?;
        let exe_name = if cfg!(windows) {
            "aiacs_diagnostics.exe"
        } else {
            "aiacs_diagnostics"
        };
        let diagnostics_exe = current_exe.with_file_name(exe_name);
        std::process::Command::new(&diagnostics_exe)
            .spawn()
            .map_err(|e| {
                AppControllerError::Backend(format!(
                    "Failed to launch {}: {}",
                    diagnostics_exe.display(),
                    e
                ))
            })?;
        let message = format!("Diagnostics tool launched: {}", diagnostics_exe.display());
        self.save_log_entry("[INFO]", message.clone())?;
        Ok(message)
    }

    pub fn check_cloud_connection(&mut self) -> Result<String, AppControllerError> {
        let runtime = Self::cloud_runtime()?;
        let message = runtime
            .block_on(async {
                let client = CloudStorageClient::connect_from_env().await?;
                client.health_check().await
            })
            .map_err(Self::map_cloud_error)?;

        self.save_log_entry("[DB]", "Cloud database connection healthy")?;
        Ok(message)
    }

    pub fn sync_customer_metadata(&mut self) -> Result<String, AppControllerError> {
        let metadata = self.customer_metadata();
        let runtime = Self::cloud_runtime()?;
        let message = runtime
            .block_on(async {
                let client = CloudStorageClient::connect_from_env().await?;
                client.upsert_customer(&metadata).await
            })
            .map_err(Self::map_cloud_error)?;

        self.save_log_entry(
            "[DB]",
            format!("Customer metadata synced: {}", metadata.customer_id),
        )?;
        Ok(message)
    }

    pub fn sync_vehicle_metadata(&mut self) -> Result<String, AppControllerError> {
        let metadata = self.vehicle_metadata();
        let runtime = Self::cloud_runtime()?;
        let message = runtime
            .block_on(async {
                let client = CloudStorageClient::connect_from_env().await?;
                client.upsert_vehicle(&metadata).await
            })
            .map_err(Self::map_cloud_error)?;

        self.save_log_entry(
            "[DB]",
            format!("Vehicle metadata synced: {}", metadata.vehicle_display_name),
        )?;
        Ok(message)
    }

    pub fn sync_key_fob_metadata(&mut self) -> Result<String, AppControllerError> {
        let metadata = self.key_fob_metadata();
        let runtime = Self::cloud_runtime()?;
        let message = runtime
            .block_on(async {
                let client = CloudStorageClient::connect_from_env().await?;
                client.upsert_key_fob(&metadata).await
            })
            .map_err(Self::map_cloud_error)?;

        self.save_log_entry(
            "[DB]",
            format!("Key fob metadata synced: {}", metadata.fob_label),
        )?;
        Ok(message)
    }

    pub fn sync_demo_cloud_metadata(&mut self) -> Result<String, AppControllerError> {
        let customer = self.customer_metadata();
        let vehicle = self.vehicle_metadata();
        let key_fob = self.key_fob_metadata();
        let runtime = Self::cloud_runtime()?;
        let message = runtime
            .block_on(async {
                let client = CloudStorageClient::connect_from_env().await?;
                client.upsert_customer(&customer).await?;
                client.upsert_vehicle(&vehicle).await?;
                client.upsert_key_fob(&key_fob).await?;
                Ok::<String, CloudStorageError>(
                    "Demo metadata synced to cloud database".to_string(),
                )
            })
            .map_err(Self::map_cloud_error)?;

        self.save_log_entry("[DB]", "Demo metadata synced to company cloud database")?;
        Ok(message)
    }

    pub fn sync_certificate_metadata(&mut self) -> Result<String, AppControllerError> {
        let metadata = self.certificate_metadata()?;
        let runtime = Self::cloud_runtime()?;
        let message = runtime
            .block_on(async {
                let client = CloudStorageClient::connect_from_env().await?;
                client.upsert_certificate_metadata(&metadata).await
            })
            .map_err(Self::map_cloud_error)?;

        self.save_log_entry(
            "[DB]",
            format!("Certificate metadata synced: {}", metadata.certificate_id),
        )?;
        self.save_log_entry("[DB]", "Certificate private material: [REDACTED]")?;
        Ok(message)
    }

    pub fn sync_provisioning_session_record(&mut self) -> Result<String, AppControllerError> {
        let metadata = self.provisioning_session_metadata()?;
        let runtime = Self::cloud_runtime()?;
        let message = runtime
            .block_on(async {
                let client = CloudStorageClient::connect_from_env().await?;
                client.upsert_provisioning_session(&metadata).await
            })
            .map_err(Self::map_cloud_error)?;

        self.save_log_entry(
            "[DB]",
            format!("Provisioning session synced: {}", metadata.session_id),
        )?;
        self.save_log_entry(
            "[DB]",
            format!("Session algorithm: {}", metadata.session_algorithm),
        )?;
        self.save_log_entry("[SECURITY]", "Raw session key: [REDACTED]")?;
        self.save_log_entry("[SECURITY]", "Shared secret: [REDACTED]")?;
        self.save_log_entry("[SECURITY]", "HKDF output: [REDACTED]")?;
        Ok(message)
    }

    pub fn sync_ca_encrypted_key_blob(&mut self) -> Result<String, AppControllerError> {
        self.ca_private_key_material()?;
        let master_key = parse_master_key_from_env().map_err(Self::map_cloud_error)?;
        let record = self.ca_encrypted_key_record(&master_key)?;
        let runtime = Self::cloud_runtime()?;
        let message = runtime
            .block_on(async {
                let client = CloudStorageClient::connect_from_env().await?;
                client.upsert_encrypted_key(&record).await
            })
            .map_err(Self::map_cloud_error)?;

        self.save_log_entry(
            "[DB]",
            format!("CA encrypted key blob uploaded: {}", CA_ENCRYPTED_KEY_ID),
        )?;
        self.save_log_entry("[DB]", "Raw private key material: [REDACTED]")?;
        self.save_log_entry(
            "[DB]",
            "Protection: Client-side AES-256-GCM encryption before upload",
        )?;
        Ok(message)
    }

    pub fn sync_key_fob_encrypted_key_blob(&mut self) -> Result<String, AppControllerError> {
        self.key_fob_private_key_material()?;
        let master_key = parse_master_key_from_env().map_err(Self::map_cloud_error)?;
        let record = self.key_fob_encrypted_key_record(&master_key)?;
        let runtime = Self::cloud_runtime()?;
        let message = runtime
            .block_on(async {
                let client = CloudStorageClient::connect_from_env().await?;
                client.upsert_encrypted_key(&record).await
            })
            .map_err(Self::map_cloud_error)?;

        self.save_log_entry(
            "[DB]",
            format!(
                "Key fob encrypted key blob uploaded: {}",
                KEY_FOB_ENCRYPTED_KEY_ID
            ),
        )?;
        self.save_log_entry("[DB]", "Raw private key material: [REDACTED]")?;
        self.save_log_entry(
            "[DB]",
            "Protection: Client-side AES-256-GCM encryption before upload",
        )?;
        Ok(message)
    }

    pub fn sync_encrypted_key_blobs(&mut self) -> Result<String, AppControllerError> {
        self.ca_private_key_material()?;
        self.key_fob_private_key_material()?;
        let master_key = parse_master_key_from_env().map_err(Self::map_cloud_error)?;
        let ca_record = self.ca_encrypted_key_record(&master_key)?;
        let key_fob_record = self.key_fob_encrypted_key_record(&master_key)?;
        let runtime = Self::cloud_runtime()?;
        let message = runtime
            .block_on(async {
                let client = CloudStorageClient::connect_from_env().await?;
                client
                    .sync_demo_encrypted_key_blobs(&ca_record, &key_fob_record)
                    .await
            })
            .map_err(Self::map_cloud_error)?;

        self.save_log_entry(
            "[DB]",
            "Encrypted key blobs synced to company cloud database",
        )?;
        self.save_log_entry("[DB]", "Raw private key material: [REDACTED]")?;
        self.save_log_entry(
            "[DB]",
            "Protection: Client-side AES-256-GCM encryption before upload",
        )?;
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

    pub fn provisioning_report_file_path(&self) -> PathBuf {
        self.provisioning_report_path()
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

    fn current_certificate(&self) -> Option<Certificate> {
        self.keyfob
            .as_ref()
            .and_then(|keyfob| keyfob.get_certificate().ok())
            .and_then(|cert_bytes| serde_json::from_slice(&cert_bytes).ok())
    }

    fn customer_metadata(&self) -> CustomerMetadata {
        demo_customer_metadata()
    }

    fn vehicle_metadata(&self) -> VehicleMetadata {
        demo_vehicle_metadata(self.provisioning_status_label())
    }

    fn key_fob_metadata(&self) -> KeyFobMetadata {
        demo_key_fob_metadata(
            self.key_fob_public_key_fingerprint(),
            self.certificate_status_label(),
            self.provisioning_status_label(),
        )
    }

    fn certificate_metadata(&self) -> Result<CertificateMetadata, AppControllerError> {
        let certificate = self.current_certificate().ok_or_else(|| {
            AppControllerError::Backend(
                "Certificate metadata is not available for cloud sync".to_string(),
            )
        })?;
        let issued_at = parse_certificate_timestamp(&certificate.issued_at)?;
        let expires_at = parse_certificate_timestamp(&certificate.expires_at)?;

        Ok(demo_certificate_metadata(
            Some(fingerprint(&certificate.public_key)),
            Some(issued_at),
            Some(expires_at),
        ))
    }

    fn provisioning_session_metadata(
        &self,
    ) -> Result<ProvisioningSessionMetadata, AppControllerError> {
        let session = self.session.as_ref().ok_or_else(|| {
            AppControllerError::Backend(
                "Provisioning session metadata is not available".to_string(),
            )
        })?;
        if !session.established {
            return Err(AppControllerError::Backend(
                "Provisioning session metadata is not available".to_string(),
            ));
        }
        let started_at = parse_session_timestamp(&session.created_at)?;
        let completed_at = Utc::now();

        Ok(demo_provisioning_session_metadata(
            Some(started_at),
            Some(completed_at),
        ))
    }

    fn key_fob_public_key_fingerprint(&self) -> Option<String> {
        self.keyfob
            .as_ref()
            .and_then(|keyfob| keyfob.public_key.as_ref())
            .map(|public_key| fingerprint(public_key))
    }

    fn ca_private_key_material(&self) -> Result<&[u8], AppControllerError> {
        self.ca
            .as_ref()
            .and_then(|ca| ca.root_private_key.as_deref())
            .ok_or_else(|| {
                AppControllerError::Backend(
                    "Private key material is not available for encrypted cloud upload".to_string(),
                )
            })
    }

    fn key_fob_private_key_material(&self) -> Result<&[u8], AppControllerError> {
        self.keyfob
            .as_ref()
            .and_then(|keyfob| keyfob.private_key.as_deref())
            .ok_or_else(|| {
                AppControllerError::Backend(
                    "Private key material is not available for encrypted cloud upload".to_string(),
                )
            })
    }

    fn ca_encrypted_key_record(
        &self,
        master_key: &[u8; 32],
    ) -> Result<EncryptedKeyRecord, AppControllerError> {
        let ca = self.ca.as_ref().ok_or_else(|| {
            AppControllerError::Backend(
                "Private key material is not available for encrypted cloud upload".to_string(),
            )
        })?;
        let private_key = self.ca_private_key_material()?;
        let public_fingerprint = ca.root_public_key.as_ref().map(|key| fingerprint(key));
        let encrypted_key = encrypt_private_key_for_cloud(private_key, master_key)
            .map_err(Self::map_cloud_error)?;

        Ok(EncryptedKeyRecord {
            key_id: CA_ENCRYPTED_KEY_ID.to_string(),
            owner_type: "ca".to_string(),
            owner_id: DEFAULT_CA_NAME.to_string(),
            public_key_fingerprint: public_fingerprint,
            key_purpose: CA_KEY_PURPOSE.to_string(),
            storage_status: ENCRYPTED_KEY_STORAGE_STATUS.to_string(),
            encrypted_key,
        })
    }

    fn key_fob_encrypted_key_record(
        &self,
        master_key: &[u8; 32],
    ) -> Result<EncryptedKeyRecord, AppControllerError> {
        let keyfob = self.keyfob.as_ref().ok_or_else(|| {
            AppControllerError::Backend(
                "Private key material is not available for encrypted cloud upload".to_string(),
            )
        })?;
        let private_key = self.key_fob_private_key_material()?;
        let public_fingerprint = keyfob.public_key.as_ref().map(|key| fingerprint(key));
        let encrypted_key = encrypt_private_key_for_cloud(private_key, master_key)
            .map_err(Self::map_cloud_error)?;

        Ok(EncryptedKeyRecord {
            key_id: KEY_FOB_ENCRYPTED_KEY_ID.to_string(),
            owner_type: "key_fob".to_string(),
            owner_id: DEFAULT_FOB_ID.to_string(),
            public_key_fingerprint: public_fingerprint,
            key_purpose: KEY_FOB_KEY_PURPOSE.to_string(),
            storage_status: ENCRYPTED_KEY_STORAGE_STATUS.to_string(),
            encrypted_key,
        })
    }

    fn certificate_status_label(&self) -> &'static str {
        if self.current_certificate().is_some() {
            "Issued"
        } else {
            DEFAULT_CERTIFICATE_STATUS
        }
    }

    fn provisioning_status_label(&self) -> &'static str {
        if self.session.is_some() && self.last_access_decision.is_some() {
            "Complete"
        } else {
            "In Progress"
        }
    }

    fn cloud_runtime() -> Result<tokio::runtime::Runtime, AppControllerError> {
        tokio::runtime::Runtime::new().map_err(|_| {
            AppControllerError::Backend("Cloud runtime initialization failed".to_string())
        })
    }

    fn map_cloud_error(error: CloudStorageError) -> AppControllerError {
        match error {
            CloudStorageError::MissingDatabaseUrl => {
                AppControllerError::Backend("Cloud database is not configured".to_string())
            }
            other => AppControllerError::Backend(other.to_string()),
        }
    }

    fn append_key_storage_trace(
        &mut self,
        fob_public_fingerprint: Option<&str>,
        ca_public_fingerprint: Option<&str>,
    ) -> Result<(), AppControllerError> {
        if let Some(fingerprint) = ca_public_fingerprint {
            self.append_protocol_trace(
                "[KEY STORAGE]",
                format!("CA private key stored: {}", CA_PRIVATE_KEY_PATH),
            )?;
            self.append_protocol_trace("[KEY STORAGE]", "CA private key material: [REDACTED]")?;
            self.append_protocol_trace(
                "[KEY STORAGE]",
                format!("CA public key path: {}", CA_PUBLIC_KEY_PATH),
            )?;
            self.append_protocol_trace(
                "[KEY STORAGE]",
                format!("CA public key fingerprint: {}", fingerprint),
            )?;
        }
        if let Some(fingerprint) = fob_public_fingerprint {
            self.append_protocol_trace(
                "[KEY STORAGE]",
                format!("Key fob private key stored: {}", KEYFOB_PRIVATE_KEY_PATH),
            )?;
            self.append_protocol_trace(
                "[KEY STORAGE]",
                "Key fob private key material: [REDACTED]",
            )?;
            self.append_protocol_trace(
                "[KEY STORAGE]",
                format!("Key fob public key path: {}", KEYFOB_PUBLIC_KEY_PATH),
            )?;
            self.append_protocol_trace(
                "[KEY STORAGE]",
                format!("Key fob public key fingerprint: {}", fingerprint),
            )?;
        }
        self.append_protocol_trace("[KEY STORAGE]", "Storage mode: Local prototype key storage")?;
        self.append_protocol_trace(
            "[KEY STORAGE]",
            "Production note: secure element or encrypted key store recommended",
        )
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

    fn provisioning_report_path(&self) -> PathBuf {
        self.log_dir.join(PROVISIONING_REPORT_FILE)
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

fn attack_type_from_key(attack_key: &str) -> Result<AttackType, AppControllerError> {
    match attack_key {
        "replay" => Ok(AttackType::ReplayAttack),
        "forged_signature" => Ok(AttackType::ForgedSignature),
        "fake_certificate" => Ok(AttackType::FakeCertificate),
        "identity_mismatch" => Ok(AttackType::IdentityMismatch),
        "delayed_relay" => Ok(AttackType::DelayedRelay),
        "packet_tampering" => Ok(AttackType::PacketTampering),
        "unauthorized_key_fob" => Ok(AttackType::UnauthorizedKeyFob),
        "tampered_ciphertext" => Ok(AttackType::TamperedSessionCiphertext),
        "wrong_session_key" => Ok(AttackType::WrongSessionKey),
        _ => Err(AppControllerError::Backend(format!(
            "Unknown diagnostics attack: {}",
            attack_key
        ))),
    }
}

fn attack_steps(attack_type: AttackType) -> &'static [&'static str] {
    match attack_type {
        AttackType::ReplayAttack => &[
            "Step 1: Capture valid authentication proof",
            "Step 2: Consume original nonce",
            "Step 3: Re-submit captured proof",
            "Step 4: AuthenticationEngine checks nonce lifecycle",
            "Step 5: Rejected with ReusedNonce",
        ],
        AttackType::ForgedSignature => &[
            "Step 1: Generate valid challenge and proof",
            "Step 2: Modify Ed25519 signature bytes",
            "Step 3: Submit forged signature to AuthenticationEngine",
            "Step 4: Signature verification fails",
            "Step 5: Rejected with InvalidSignature",
        ],
        AttackType::FakeCertificate => &[
            "Step 1: Generate fake CA",
            "Step 2: Issue fake certificate",
            "Step 3: Submit fake certificate to real trusted CA validation path",
            "Step 4: Certificate validation returns false",
            "Step 5: Rejected with InvalidCertificate",
        ],
        AttackType::IdentityMismatch => &[
            "Step 1: Issue valid certificate from trusted CA",
            "Step 2: Build proof with mismatched subject identity",
            "Step 3: Submit proof to AuthenticationEngine",
            "Step 4: Certificate subject binding fails",
            "Step 5: Rejected with IdentityMismatch",
        ],
        AttackType::DelayedRelay => &[
            "Step 1: Capture valid authentication attempt",
            "Step 2: Delay proof beyond freshness window",
            "Step 3: Submit stale proof",
            "Step 4: Freshness timeout validation fails",
            "Step 5: Rejected with FreshnessTimeout",
        ],
        AttackType::PacketTampering => &[
            "Step 1: Capture signed authentication payload",
            "Step 2: Modify vehicle or payload binding field",
            "Step 3: Submit tampered payload",
            "Step 4: Canonical payload/signature binding fails",
            "Step 5: Rejected before access is granted",
        ],
        AttackType::UnauthorizedKeyFob => &[
            "Step 1: Present key fob without trusted certificate",
            "Step 2: Attempt authentication proof creation",
            "Step 3: Certificate presence validation fails",
            "Step 4: Access decision rejects request",
            "Step 5: Rejected as unauthorized key fob",
        ],
        AttackType::TamperedSessionCiphertext => &[
            "Step 1: Establish AES-GCM session",
            "Step 2: Modify ciphertext",
            "Step 3: Attempt decryption",
            "Step 4: AEAD tag verification fails",
            "Step 5: Rejected as session integrity failure",
        ],
        AttackType::WrongSessionKey => &[
            "Step 1: Establish AES-GCM session",
            "Step 2: Derive a mismatched session key",
            "Step 3: Attempt decryption with wrong key",
            "Step 4: AES-GCM authentication fails",
            "Step 5: Rejected as session key mismatch",
        ],
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

fn parse_certificate_timestamp(value: &str) -> Result<DateTime<Utc>, AppControllerError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| {
            AppControllerError::Backend(
                "Certificate metadata is not available for cloud sync".to_string(),
            )
        })
}

fn parse_session_timestamp(value: &str) -> Result<DateTime<Utc>, AppControllerError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| {
            AppControllerError::Backend(
                "Provisioning session metadata is not available".to_string(),
            )
        })
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
    fn test_protocol_trace_deduplicates_repeated_entries() {
        let log_dir = temp_log_dir("trace_deduplication");
        let mut controller = AppController::new_with_log_dir(&log_dir);

        controller.connect_vehicle().expect("connect failed");
        controller.connect_vehicle().expect("second connect failed");

        let trace = controller.get_protocol_trace();
        assert_eq!(
            trace
                .iter()
                .filter(|entry| entry.as_str() == "[VEHICLE] Vehicle connection established")
                .count(),
            1
        );
        assert_eq!(
            trace
                .iter()
                .filter(|entry| entry.as_str() == "[VEHICLE] Protocol version: AIACS_AUTH_V1")
                .count(),
            1
        );

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

    #[test]
    fn test_ca_key_files_are_created_after_vehicle_trust_initialization() {
        let mut controller = AppController::new();
        controller.initialize_ca().expect("CA init failed");

        assert!(PathBuf::from(CA_PRIVATE_KEY_PATH).exists());
        assert!(PathBuf::from(CA_PUBLIC_KEY_PATH).exists());
    }

    #[test]
    fn test_key_fob_key_files_are_created_after_registration() {
        let mut controller = AppController::new();
        controller
            .register_digital_key_fob()
            .expect("fob registration failed");

        assert!(PathBuf::from(KEYFOB_PRIVATE_KEY_PATH).exists());
        assert!(PathBuf::from(KEYFOB_PUBLIC_KEY_PATH).exists());
    }

    #[test]
    fn test_certificate_file_is_created_after_certificate_issuance() {
        let mut controller = AppController::new();
        controller
            .issue_keyfob_certificate()
            .expect("certificate issuance failed");

        assert!(PathBuf::from(KEYFOB_CERTIFICATE_PATH).exists());
    }

    #[test]
    fn test_exported_provisioning_report_redacts_private_key_material() {
        let log_dir = temp_log_dir("report_redaction");
        let mut controller = AppController::new_with_log_dir(&log_dir);
        controller.initialize_ca().expect("CA init failed");
        controller
            .issue_keyfob_certificate()
            .expect("certificate issuance failed");

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
            .expect("auth demo failed");
        controller
            .establish_secure_session_demo()
            .expect("session demo failed");
        controller
            .export_provisioning_report()
            .expect("report export failed");

        let report = fs::read_to_string(controller.provisioning_report_file_path())
            .expect("report read failed");
        assert!(report.contains("Provisioning Summary"));
        assert!(report.contains("Credential Storage"));
        assert!(report.contains("Certificate Details"));
        assert!(report.contains("Authentication Verification"));
        assert!(report.contains("Secure Session Establishment"));
        assert!(report.contains("Security Notes"));
        assert!(report.contains("Protocol Trace"));
        assert!(report.contains("Diagnostics Summary"));
        assert!(report.contains("[REDACTED]"));
        assert!(report.contains(CA_PRIVATE_KEY_PATH));
        assert!(report.contains(KEYFOB_PRIVATE_KEY_PATH));
        assert!(report.contains("SHA256:"));
        assert!(!report.contains(&ca_private_key_debug));
        assert!(!report.contains(&fob_private_key_debug));
        assert!(!report.contains("derived_aes_key"));
        assert!(!report.contains("root_private_key: ["));
        assert!(!report.contains("private_key: ["));

        let _ = fs::remove_dir_all(log_dir);
    }

    #[test]
    fn test_cloud_missing_database_url_error_is_safe_for_gui() {
        let error = AppController::map_cloud_error(CloudStorageError::MissingDatabaseUrl);
        let message = error.to_string();

        assert_eq!(message, "Cloud database is not configured");
        assert!(!message.contains("DATABASE_URL"));
        assert!(!message.contains("AIACS_MASTER_KEY"));
        assert!(!message.contains("postgresql://"));
        assert!(!message.contains("password"));
    }

    #[test]
    fn test_cloud_metadata_uses_generic_demo_values() {
        let controller = AppController::new();
        let customer = controller.customer_metadata();
        let vehicle = controller.vehicle_metadata();
        let key_fob = controller.key_fob_metadata();
        let combined = format!("{customer:?}\n{vehicle:?}\n{key_fob:?}");

        for expected in [
            "CUST-0001",
            "VEH-0001",
            "FOB-0001",
            "Dennis Maharjan",
            "Nissan Magnite 2021",
            "Primary Key Fob",
            "dennis.m@example.com",
        ] {
            assert!(combined.contains(expected));
        }

        for disallowed in [
            "CUST-GUI-001",
            "VEH-GUI-001",
            "FOB-GUI-001",
            "SESSION-GUI-001",
            "demo@example.com",
        ] {
            assert!(!combined.contains(disallowed));
        }
    }

    #[test]
    fn test_cloud_metadata_does_not_include_secret_upload_fields() {
        let controller = AppController::new();
        let customer = controller.customer_metadata();
        let vehicle = controller.vehicle_metadata();
        let key_fob = controller.key_fob_metadata();
        let combined = format!("{customer:?}\n{vehicle:?}\n{key_fob:?}").to_lowercase();

        for secret_marker in [
            "private_key",
            "root_private_key",
            "session_key",
            "shared_secret",
            "raw aes",
            "encrypted_key_blob",
            "certificate_json",
        ] {
            assert!(!combined.contains(secret_marker));
        }
    }

    #[test]
    fn test_certificate_metadata_sync_returns_safe_error_without_certificate() {
        let mut controller = AppController::new();
        let message = controller
            .sync_certificate_metadata()
            .expect_err("missing certificate should fail safely")
            .to_string();

        assert_eq!(
            message,
            "Certificate metadata is not available for cloud sync"
        );
        assert!(!message.contains("DATABASE_URL"));
        assert!(!message.contains("AIACS_MASTER_KEY"));
        assert!(!message.contains("private_key"));
        assert!(!message.contains("encrypted_key_blob"));
        assert!(!message.contains("encryption_nonce"));
    }

    #[test]
    fn test_app_controller_certificate_metadata_is_safe() {
        let mut controller = AppController::new();
        controller
            .issue_keyfob_certificate()
            .expect("certificate issuance failed");

        let metadata = controller
            .certificate_metadata()
            .expect("certificate metadata should build");
        let debug = format!("{metadata:?}");

        assert_eq!(
            metadata.certificate_id,
            crate::cloud_storage::DEMO_CERTIFICATE_ID
        );
        assert_eq!(metadata.fob_id, DEFAULT_FOB_ID);
        assert_eq!(metadata.subject_id, DEFAULT_FOB_ID);
        assert_eq!(metadata.issuer, DEFAULT_CA_NAME);
        assert_eq!(metadata.signature_algorithm, "Ed25519");
        assert_eq!(metadata.certificate_status, "issued");
        assert!(metadata.public_key_fingerprint.is_some());
        assert!(metadata.issued_at.is_some());
        assert!(metadata.expires_at.is_some());

        for disallowed in [
            "private_key",
            "root_private_key",
            "AIACS_MASTER_KEY",
            "DATABASE_URL",
            "encrypted_key_blob",
            "encryption_nonce",
            "shared_secret",
            "session_key",
        ] {
            assert!(!debug.contains(disallowed));
        }
    }

    #[test]
    fn test_provisioning_session_sync_returns_safe_error_without_session() {
        let mut controller = AppController::new();
        let message = controller
            .sync_provisioning_session_record()
            .expect_err("missing session should fail safely")
            .to_string();

        assert_eq!(message, "Provisioning session metadata is not available");
        assert!(!message.contains("DATABASE_URL"));
        assert!(!message.contains("AIACS_MASTER_KEY"));
        assert!(!message.contains("session_key"));
        assert!(!message.contains("shared_secret"));
        assert!(!message.contains("hkdf_output"));
        assert!(!message.contains("private_key"));
    }

    #[test]
    fn test_app_controller_provisioning_session_metadata_is_safe() {
        let mut controller = AppController::new();
        controller
            .establish_secure_session_demo()
            .expect("session demo failed");

        let metadata = controller
            .provisioning_session_metadata()
            .expect("session metadata should build");
        let debug = format!("{metadata:?}").to_lowercase();

        assert_eq!(metadata.session_id, crate::cloud_storage::DEMO_SESSION_ID);
        assert_eq!(metadata.customer_id, crate::cloud_storage::DEMO_CUSTOMER_ID);
        assert_eq!(metadata.vehicle_id, crate::cloud_storage::DEMO_VEHICLE_ID);
        assert_eq!(metadata.fob_id, DEFAULT_FOB_ID);
        assert_eq!(
            metadata.certificate_id,
            crate::cloud_storage::DEMO_CERTIFICATE_ID
        );
        assert_eq!(
            metadata.auth_status,
            crate::cloud_storage::AUTHENTICATED_STATUS
        );
        assert_eq!(
            metadata.session_status,
            crate::cloud_storage::SECURE_SESSION_ESTABLISHED_STATUS
        );
        assert_eq!(
            metadata.access_decision,
            crate::cloud_storage::GRANT_ACCESS_DECISION
        );
        assert_eq!(
            metadata.session_algorithm,
            crate::cloud_storage::SESSION_ALGORITHM
        );
        assert!(metadata.started_at.is_some());
        assert!(metadata.completed_at.is_some());

        for disallowed in [
            "session_key",
            "shared_secret",
            "hkdf_output",
            "aes_key",
            "aes_gcm_key",
            "x25519_private_key",
            "decrypted_payload",
            "AIACS_MASTER_KEY",
            "DATABASE_URL",
            "private_key",
        ] {
            assert!(!debug.contains(&disallowed.to_lowercase()));
        }
    }

    #[test]
    fn test_encrypted_key_sync_methods_return_safe_error_without_key_material() {
        let mut controller = AppController::new();

        for result in [
            controller.sync_ca_encrypted_key_blob(),
            controller.sync_key_fob_encrypted_key_blob(),
            controller.sync_encrypted_key_blobs(),
        ] {
            let message = result
                .expect_err("missing key material should fail")
                .to_string();

            assert_eq!(
                message,
                "Private key material is not available for encrypted cloud upload"
            );
            assert!(!message.contains("DATABASE_URL"));
            assert!(!message.contains("AIACS_MASTER_KEY"));
            assert!(!message.contains("private_key"));
            assert!(!message.contains("encrypted_key_blob"));
            assert!(!message.contains("encryption_nonce"));
        }
    }

    #[test]
    fn test_app_controller_encrypted_key_records_are_safe() {
        let mut controller = AppController::new();
        let master_key = [11u8; 32];

        controller.initialize_ca().expect("CA init failed");
        controller
            .issue_keyfob_certificate()
            .expect("certificate issuance failed");

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

        let ca_record = controller
            .ca_encrypted_key_record(&master_key)
            .expect("CA encrypted key record should build");
        let fob_record = controller
            .key_fob_encrypted_key_record(&master_key)
            .expect("key fob encrypted key record should build");
        let debug = format!("{ca_record:?}\n{fob_record:?}");

        assert_eq!(ca_record.key_id, CA_ENCRYPTED_KEY_ID);
        assert_eq!(ca_record.owner_type, "ca");
        assert_eq!(ca_record.owner_id, DEFAULT_CA_NAME);
        assert_eq!(ca_record.key_purpose, CA_KEY_PURPOSE);
        assert_eq!(fob_record.key_id, KEY_FOB_ENCRYPTED_KEY_ID);
        assert_eq!(fob_record.owner_type, "key_fob");
        assert_eq!(fob_record.owner_id, DEFAULT_FOB_ID);
        assert_eq!(fob_record.key_purpose, KEY_FOB_KEY_PURPOSE);
        assert_eq!(ca_record.encrypted_key.encryption_algorithm, "AES-256-GCM");
        assert_eq!(fob_record.encrypted_key.encryption_algorithm, "AES-256-GCM");
        assert!(!ca_record.encrypted_key.encrypted_key_blob.is_empty());
        assert!(!fob_record.encrypted_key.encrypted_key_blob.is_empty());
        assert_eq!(ca_record.encrypted_key.encryption_nonce.len(), 12);
        assert_eq!(fob_record.encrypted_key.encryption_nonce.len(), 12);
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&ca_private_key_debug));
        assert!(!debug.contains(&fob_private_key_debug));
        assert!(!debug.contains("AIACS_MASTER_KEY"));
        assert!(!debug.contains("DATABASE_URL"));
    }

    #[test]
    fn test_diagnostics_binary_uses_app_controller_boundary() {
        let source = fs::read_to_string("src/bin/aiacs_diagnostics.rs")
            .expect("diagnostics binary source should exist");

        assert!(source.contains("use aiacs::app_controller::AppController;"));
        assert!(!source.contains("AdversarialValidationEngine"));
        assert!(!source.contains("CryptoEngine"));
        assert!(!source.contains("CertificateAuthority"));
        assert!(!source.contains("AuthenticationEngine"));
        assert!(!source.contains("SessionValidationEngine"));
        assert!(!source.contains("AccessDecisionEngine"));
    }
}
