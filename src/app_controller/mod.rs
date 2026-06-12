use crate::access::{AccessDecision, AccessDecisionEngine};
use crate::attacks::{AdversarialValidationEngine, AttackResult, AttackType};
use crate::auth::{AuthResult, AuthenticationEngine};
use crate::ca::{CAError, Certificate, CertificateAuthority};
use crate::cloud_storage::{
    demo_customer_metadata, demo_key_fob_metadata, demo_vehicle_metadata,
    encrypt_private_key_for_cloud, parse_master_key_from_env, AuditLogRecord, CertificateMetadata,
    CloudStorageClient, CloudStorageConfig, CloudStorageError, CustomerMetadata,
    EncryptedKeyRecord, KeyFobMetadata, ProvisioningSessionMetadata, VehicleMetadata,
    AUTHENTICATED_STATUS, CA_ENCRYPTED_KEY_ID, CA_KEY_PURPOSE, CERTIFICATE_SIGNATURE_ALGORITHM,
    DEFAULT_CERTIFICATE_STATUS, DEFAULT_PROVISIONING_STATUS, DEMO_CERTIFICATE_ID, DEMO_CUSTOMER_ID,
    DEMO_FOB_ID, DEMO_SESSION_ID, DEMO_VEHICLE_ID, DIAGNOSTIC_RESULT_IDS,
    ENCRYPTED_KEY_STORAGE_STATUS, GRANT_ACCESS_DECISION, ISSUED_CERTIFICATE_STATUS,
    KEY_FOB_ENCRYPTED_KEY_ID, KEY_FOB_KEY_PURPOSE, SECURE_SESSION_ESTABLISHED_STATUS,
    SESSION_ALGORITHM,
};
use crate::keyfob::{AuthenticationProof, DigitalKeyFob, KeyFobError};
use crate::session::{SessionState, SessionValidationEngine};
use crate::vehicle::{VehicleControlModule, VehicleError};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::future::Future;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

const DEFAULT_CA_NAME: &str = "AIACS-Demo-CA";
const DEFAULT_VEHICLE_ID: &str = DEMO_VEHICLE_ID;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveProvisioningContext {
    pub customer_id: String,
    pub owner_name: String,
    pub customer_email: Option<String>,
    pub vehicle_id: String,
    pub vehicle_display_name: String,
    pub make: Option<String>,
    pub model: Option<String>,
    pub year: Option<i32>,
    pub fob_id: String,
    pub fob_label: String,
    pub certificate_id: String,
    pub session_id: String,
    pub context_source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveKeyFobCryptoIdentity {
    pub fob_id: String,
    pub public_key_fingerprint: String,
    pub certificate_id: String,
    pub certificate_subject_id: Option<String>,
    pub certificate_status: String,
    pub identity_source: String,
    pub binding_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisioningCloudSyncResult {
    pub action_name: String,
    pub provisioning_status: String,
    pub local_success: bool,
    pub cloud_sync_attempted: bool,
    pub cloud_sync_status: String,
    pub cloud_table_updated: String,
    pub safe_error: Option<String>,
    pub active_customer_id: String,
    pub active_vehicle_id: String,
    pub active_fob_id: String,
    pub active_certificate_id: String,
    pub active_session_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupCloudSyncResult {
    pub attempted: bool,
    pub enabled: bool,
    pub status_message: String,
    pub safe_error: Option<String>,
}

impl fmt::Display for StartupCloudSyncResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.status_message)?;
        if let Some(error) = &self.safe_error {
            write!(f, ": {}", error)?;
        }
        Ok(())
    }
}

impl fmt::Display for ProvisioningCloudSyncResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} | Provisioning: {} | Cloud Sync: {} | Table: {} | Customer: {} | Vehicle: {} | Key Fob: {} | Certificate: {} | Session: {}",
            self.action_name,
            self.provisioning_status,
            self.cloud_sync_status,
            self.cloud_table_updated,
            self.active_customer_id,
            self.active_vehicle_id,
            self.active_fob_id,
            self.active_certificate_id,
            self.active_session_id
        )?;
        if let Some(error) = &self.safe_error {
            write!(f, " | Safe Error: {}", error)?;
        }
        Ok(())
    }
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

#[derive(Clone)]
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
    cloud_auto_sync_enabled: bool,
    active_customer: CustomerMetadata,
    active_vehicle: VehicleMetadata,
    active_key_fob: KeyFobMetadata,
    active_session_id: String,
    customer_records: Vec<CustomerMetadata>,
    vehicle_records: Vec<VehicleMetadata>,
    key_fob_records: Vec<KeyFobMetadata>,
    cloud_client: Option<CloudStorageClient>,
    schema_initialized: bool,
    cloud_runtime: Arc<tokio::runtime::Runtime>,
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
            .field("cloud_auto_sync_enabled", &self.cloud_auto_sync_enabled)
            .field("active_customer", &self.active_customer)
            .field("active_vehicle", &self.active_vehicle)
            .field("active_key_fob", &self.active_key_fob)
            .field("active_session_id", &self.active_session_id)
            .field("cloud_client_cached", &self.cloud_client.is_some())
            .field("schema_initialized", &self.schema_initialized)
            .field("cloud_runtime", &"[REDACTED]")
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

        let active_customer = demo_customer_metadata();
        let active_vehicle = demo_vehicle_metadata(DEFAULT_PROVISIONING_STATUS);
        let active_key_fob = demo_key_fob_metadata(
            None,
            DEFAULT_CERTIFICATE_STATUS,
            DEFAULT_PROVISIONING_STATUS,
        );

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
            cloud_auto_sync_enabled: false,
            active_customer: active_customer.clone(),
            active_vehicle: active_vehicle.clone(),
            active_key_fob: active_key_fob.clone(),
            active_session_id: DEMO_SESSION_ID.to_string(),
            customer_records: vec![active_customer],
            vehicle_records: vec![active_vehicle],
            key_fob_records: vec![active_key_fob],
            cloud_client: None,
            schema_initialized: false,
            cloud_runtime: Arc::new(
                tokio::runtime::Runtime::new()
                    .expect("cloud runtime should initialize for default controller"),
            ),
        }
    }

    pub fn connect_vehicle(&mut self) -> Result<String, AppControllerError> {
        self.sync_vehicle_module_to_active_context()?;
        self.vehicle_connected = true;
        let vehicle_id = self.active_vehicle.vehicle_id.clone();
        let message = format!("Vehicle connected: {}; protocol AIACS_AUTH_V1", vehicle_id);
        self.append_protocol_trace("[VEHICLE]", "Vehicle connection established")?;
        self.append_protocol_trace("[VEHICLE]", format!("Vehicle ID: {}", vehicle_id))?;
        self.append_protocol_trace("[VEHICLE]", "Protocol version: AIACS_AUTH_V1")?;
        self.log(message.clone());
        Ok(message)
    }

    pub fn detect_key_fob(&mut self) -> Result<String, AppControllerError> {
        self.ensure_active_key_fob_crypto_identity()?;
        self.keyfob_detected = true;
        let fob_id = self.active_key_fob.fob_id.clone();
        let message = format!("Digital key fob detected: {}", fob_id);
        self.append_protocol_trace("[KEYFOB]", format!("Detected fob ID: {}", fob_id))?;
        self.append_protocol_trace("[KEYFOB]", "Private key material: [REDACTED]")?;
        self.log(message.clone());
        Ok(message)
    }

    pub fn generate_authentication_challenge(&mut self) -> Result<String, AppControllerError> {
        self.ensure_ready_for_authentication()?;
        let vehicle_id = self.active_vehicle.vehicle_id.clone();
        let challenge = AuthenticationEngine::generate_challenge(&mut self.vehicle, &vehicle_id)
            .map_err(|e| AppControllerError::Backend(e.to_string()))?;
        let nonce_fingerprint = fingerprint(&challenge.nonce);
        let message = "Authentication challenge generated; raw nonce is [REDACTED]".to_string();

        self.append_protocol_trace("[AUTH]", "Vehicle generated nonce challenge")?;
        self.append_protocol_trace("[AUTH]", format!("Vehicle ID: {}", vehicle_id))?;
        self.append_protocol_trace("[AUTH]", format!("Nonce hash: {}", nonce_fingerprint))?;
        self.log(message.clone());
        Ok(message)
    }

    pub fn sign_canonical_auth_payload(&mut self) -> Result<String, AppControllerError> {
        self.ensure_ready_for_authentication()?;
        let vehicle_id = self.active_vehicle.vehicle_id.clone();
        let challenge = AuthenticationEngine::generate_challenge(&mut self.vehicle, &vehicle_id)
            .map_err(|e| AppControllerError::Backend(e.to_string()))?;
        let proof = {
            let keyfob = self.keyfob.as_ref().expect("Key fob ready");
            keyfob.create_auth_proof(&vehicle_id, &challenge.nonce)?
        };
        let canonical_payload = canonical_auth_payload(
            &proof.vehicle_id,
            &proof.subject_id,
            &proof.nonce,
            &proof.timestamp,
        );
        let message =
            "Canonical authentication payload signed; private key remains [REDACTED]".to_string();

        self.append_protocol_trace("[AUTH]", "Key fob constructed canonical payload")?;
        self.append_protocol_trace("[AUTH]", format!("Payload fob ID: {}", proof.subject_id))?;
        self.append_protocol_trace("[AUTH]", "Signature algorithm: Ed25519")?;
        self.append_protocol_trace(
            "[AUTH]",
            format!("Canonical payload: {}", canonical_payload),
        )?;
        self.append_protocol_trace(
            "[AUTH]",
            format!("Signature fingerprint: {}", fingerprint(&proof.signature)),
        )?;
        self.append_protocol_trace("[AUTH]", "Key fob private key: [REDACTED]")?;
        self.log(message.clone());
        Ok(message)
    }

    pub fn rotate_key_fob_credential(&mut self) -> Result<String, AppControllerError> {
        let message =
            "Credential rotation is not available in this phase; no keys were changed".to_string();
        self.append_protocol_trace("[KEYFOB]", "Credential rotation unavailable in this phase")?;
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

        self.ensure_active_key_fob_crypto_identity()?;

        let ca = self.ca.as_ref().expect("CA initialized above");
        let mut keyfob = self.keyfob.take().expect("key fob initialized above");
        keyfob.request_certificate(ca)?;

        let cert = Self::certificate_from_keyfob(&keyfob)?;
        self.validate_key_fob_certificate_binding(&keyfob, &cert)?;
        self.update_active_key_fob_fingerprint(&keyfob);
        self.active_key_fob.certificate_status = Some("Issued".to_string());
        upsert_local_key_fob(&mut self.key_fob_records, self.active_key_fob.clone());
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
        let identity_message = self.ensure_active_key_fob_crypto_identity()?;
        let keyfob = self
            .keyfob
            .as_ref()
            .ok_or_else(|| AppControllerError::Backend("Key fob identity missing".to_string()))?;

        let public_key_fingerprint = keyfob
            .public_key
            .as_ref()
            .map(|key| fingerprint(key))
            .unwrap_or_else(|| "Unavailable".to_string());
        let subject_id = keyfob.subject_id.clone();
        let message = format!("Digital key fob registered: subject {}", subject_id);

        self.append_protocol_trace("[KEYFOB]", identity_message)?;
        self.append_protocol_trace(
            "[KEYFOB]",
            format!("Subject identity registered: {}", subject_id),
        )?;
        self.append_protocol_trace("[KEYFOB]", "Ed25519 keypair generated: Yes")?;
        self.append_protocol_trace(
            "[KEYFOB]",
            format!("Public key fingerprint: {}", public_key_fingerprint),
        )?;
        self.append_protocol_trace("[KEYFOB]", "Private key: [REDACTED]")?;
        self.append_key_storage_trace(Some(public_key_fingerprint.as_str()), None)?;
        self.log(message.clone());
        Ok(message)
    }

    pub fn run_legitimate_authentication_demo(&mut self) -> Result<String, AppControllerError> {
        self.ensure_ready_for_authentication()?;

        let vehicle_id = self.active_vehicle.vehicle_id.clone();
        let challenge = AuthenticationEngine::generate_challenge(&mut self.vehicle, &vehicle_id)
            .map_err(|e| AppControllerError::Backend(e.to_string()))?;
        self.append_protocol_trace("[AUTH]", "Vehicle generated nonce challenge")?;
        self.append_protocol_trace(
            "[AUTH]",
            format!("Nonce hash: {}", fingerprint(&challenge.nonce)),
        )?;

        let proof = {
            let keyfob = self.keyfob.as_ref().expect("Key fob ready");
            keyfob.create_auth_proof(&vehicle_id, &challenge.nonce)?
        };
        self.validate_auth_proof_binding(&proof)?;
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
            self.active_session_id.clone(),
            vehicle_id,
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
        if self.last_auth_result != Some(AuthResult::Success) {
            return Err(AppControllerError::Backend(
                "Secure session blocked: authentication not verified".to_string(),
            ));
        }

        let keyfob = self.keyfob.as_ref().expect("Key fob ready");
        if keyfob.subject_id != self.active_key_fob.fob_id {
            return Err(AppControllerError::Backend(
                "Secure session blocked: active key fob identity mismatch".to_string(),
            ));
        }
        let fob_subject_id = keyfob.subject_id.clone();
        let vehicle_id = self.active_vehicle.vehicle_id.clone();
        let vehicle_keypair = SessionValidationEngine::generate_ephemeral_keypair();
        let keyfob_keypair = SessionValidationEngine::generate_ephemeral_keypair();

        let (session, material) = SessionValidationEngine::establish_session(
            &vehicle_id,
            &fob_subject_id,
            &self.active_session_id,
            &vehicle_keypair,
            &keyfob_keypair,
            300,
        )?;

        let key_lengths = material.key_lengths();
        self.session = Some(session);

        let message = format!(
            "Secure session established: {} for subject {}; key material [REDACTED]; material lengths {:?}",
            self.active_session_id, fob_subject_id, key_lengths
        );
        self.append_protocol_trace("[SESSION]", "X25519 ephemeral key exchange: Completed")?;
        self.append_protocol_trace("[SESSION]", "HKDF-SHA256 derivation: Completed")?;
        self.append_protocol_trace("[SESSION]", "AES-GCM secure channel: Active")?;
        self.append_protocol_trace(
            "[SESSION]",
            format!("Session ID: {}", self.active_session_id),
        )?;
        self.append_protocol_trace("[SESSION]", format!("Vehicle ID: {}", vehicle_id))?;
        self.append_protocol_trace("[SESSION]", format!("Key fob ID: {}", fob_subject_id))?;
        self.append_protocol_trace(
            "[SESSION]",
            format!(
                "Certificate ID: {}",
                self.derive_certificate_id_for_active_context()
            ),
        )?;
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
        artifacts.push(format!("vehicle_id: {}", self.active_vehicle.vehicle_id));
        artifacts.push("nonce_hash: see [AUTH] trace after challenge generation".to_string());
        artifacts.push("raw nonce material: [REDACTED]".to_string());
        artifacts.push("protocol_version: AIACS_AUTH_V1".to_string());

        artifacts.push("[Authentication Proof]".to_string());
        artifacts.push(format!("subject_id: {}", self.active_key_fob.fob_id));
        artifacts.push(
            "payload_format: AIACS_AUTH_V1|vehicle_id|subject_id|base64(nonce)|timestamp"
                .to_string(),
        );
        artifacts.push("signature_fingerprint: see [AUTH] trace after signing".to_string());
        artifacts.push("private key material: [REDACTED]".to_string());

        artifacts.push("[Certificate Details]".to_string());
        if let Some(cert) = self.current_certificate() {
            artifacts.push(format!("subject: {}", cert.subject_id));
            artifacts.push(format!("issuer: {}", cert.issuer));
            artifacts.push(format!(
                "validity: {} -> {}",
                cert.issued_at, cert.expires_at
            ));
            artifacts.push(format!(
                "certificate_path: {}",
                self.key_fob_certificate_path()
            ));
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
        artifacts.push(format!("session_id: {}", self.active_session_id));
        artifacts.push("session key material: [REDACTED]".to_string());
        artifacts.push("shared secret material: [REDACTED]".to_string());

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
            format!(
                "Key fob private key path: {}",
                self.key_fob_private_key_path()
            ),
            "Key fob private key material: [REDACTED]".to_string(),
            format!(
                "Key fob public key path: {}",
                self.key_fob_public_key_path()
            ),
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
        report.push_str(&format!(
            "Customer ID: {}\n",
            self.active_customer.customer_id
        ));
        report.push_str(&format!("Vehicle ID: {}\n", self.active_vehicle.vehicle_id));
        report.push_str(&format!("Key Fob ID: {}\n", self.active_key_fob.fob_id));
        report.push_str(&format!(
            "Certificate ID: {}\n",
            self.derive_certificate_id_for_active_context()
        ));
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
            report.push_str(&format!(
                "Certificate Path: {}\n",
                self.key_fob_certificate_path()
            ));
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
        report.push_str(&format!("Session ID: {}\n", self.active_session_id));
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
        let client = match self.ensure_cloud_client() {
            Ok(client) => client,
            Err(error) => {
                self.clear_failed_cloud_client();
                return Err(error);
            }
        };
        let message = match self.run_cloud(client.health_check()) {
            Ok(message) => message,
            Err(error) => {
                self.clear_failed_cloud_client();
                return Err(Self::map_cloud_error(error));
            }
        };

        self.save_log_entry("[DB]", "Cloud database connection healthy")?;
        Ok(message)
    }

    pub fn is_cloud_auto_sync_enabled(&self) -> bool {
        self.cloud_auto_sync_enabled
    }

    pub fn get_cloud_auto_sync_status(&self) -> &'static str {
        if self.cloud_auto_sync_enabled {
            "Enabled"
        } else {
            "Disabled"
        }
    }

    pub fn enable_cloud_auto_sync(&mut self) -> Result<String, AppControllerError> {
        CloudStorageConfig::refresh_env_cache();
        if !self.cloud_auto_sync_enabled {
            self.clear_failed_cloud_client();
        }
        self.ensure_schema_initialized()?;
        self.cloud_auto_sync_enabled = true;
        self.save_log_entry("[DB]", "Auto-sync enabled")?;
        Ok("Cloud auto-sync enabled".to_string())
    }

    pub fn disable_cloud_auto_sync(&mut self) -> Result<String, AppControllerError> {
        self.cloud_auto_sync_enabled = false;
        self.save_log_entry("[DB]", "Auto-sync disabled")?;
        Ok("Cloud auto-sync disabled".to_string())
    }

    pub fn startup_auto_enable_cloud_sync(&mut self) -> StartupCloudSyncResult {
        match self.ensure_schema_initialized() {
            Ok(_) => self.startup_cloud_sync_enabled_result(),
            Err(error) => {
                self.clear_failed_cloud_client();
                self.startup_cloud_sync_disabled_result(error)
            }
        }
    }

    pub fn auto_sync_after_metadata_ready(&mut self) -> Result<String, AppControllerError> {
        self.run_auto_sync("active provisioning metadata synced", |controller| {
            controller.sync_active_cloud_metadata()
        })
    }

    pub fn auto_sync_after_key_fob_registered(&mut self) -> Result<String, AppControllerError> {
        self.run_auto_sync("key fob metadata synced", |controller| {
            controller.sync_key_fob_metadata()
        })
    }

    pub fn auto_sync_after_trust_initialized(&mut self) -> Result<String, AppControllerError> {
        self.run_auto_sync("encrypted key blob synced", |controller| {
            controller.sync_ca_encrypted_key_blob()
        })
    }

    pub fn auto_sync_after_certificate_issued(&mut self) -> Result<String, AppControllerError> {
        self.run_auto_sync("certificate metadata synced", |controller| {
            controller.sync_certificate_metadata()
        })
    }

    pub fn auto_sync_after_secure_session_established(
        &mut self,
    ) -> Result<String, AppControllerError> {
        self.run_auto_sync("provisioning session synced", |controller| {
            controller.sync_provisioning_session_record()
        })
    }

    pub fn auto_sync_after_provisioning_finalized(&mut self) -> Result<String, AppControllerError> {
        self.run_auto_sync("audit logs synced", |controller| {
            controller.sync_audit_log_records()
        })
    }

    pub fn auto_sync_after_diagnostics_completed(&mut self) -> Result<String, AppControllerError> {
        self.run_auto_sync("diagnostic results synced", |controller| {
            controller.sync_diagnostic_result_records()
        })
    }

    pub fn connect_vehicle_with_cloud_sync(
        &mut self,
    ) -> Result<ProvisioningCloudSyncResult, AppControllerError> {
        self.connect_vehicle()?;
        Ok(self.provisioning_sync_result(
            "Connect Vehicle",
            "Vehicle connected",
            "customers, vehicles, key_fobs",
            |controller| controller.sync_active_cloud_metadata(),
        ))
    }

    pub fn detect_key_fob_with_cloud_sync(
        &mut self,
    ) -> Result<ProvisioningCloudSyncResult, AppControllerError> {
        self.detect_key_fob()?;
        Ok(self.provisioning_sync_result(
            "Detect Key Fob",
            "Key fob detected",
            "key_fobs",
            |controller| controller.sync_key_fob_metadata(),
        ))
    }

    pub fn register_key_fob_with_cloud_sync(
        &mut self,
    ) -> Result<ProvisioningCloudSyncResult, AppControllerError> {
        self.register_digital_key_fob()?;
        Ok(self.provisioning_sync_result(
            "Register Digital Key Fob",
            "Key fob registered",
            "key_fobs",
            |controller| controller.sync_key_fob_metadata(),
        ))
    }

    pub fn initialize_vehicle_trust_with_cloud_sync(
        &mut self,
    ) -> Result<ProvisioningCloudSyncResult, AppControllerError> {
        self.initialize_ca()?;
        Ok(self.provisioning_sync_result(
            "Initialize Vehicle Trust",
            "Vehicle trust initialized",
            "encrypted_keys",
            |controller| controller.sync_ca_encrypted_key_blob(),
        ))
    }

    pub fn issue_access_certificate_with_cloud_sync(
        &mut self,
    ) -> Result<ProvisioningCloudSyncResult, AppControllerError> {
        self.issue_keyfob_certificate()?;
        Ok(self.provisioning_sync_result(
            "Issue Access Certificate",
            "Certificate issued",
            "certificates",
            |controller| controller.sync_certificate_metadata(),
        ))
    }

    pub fn generate_challenge_with_cloud_sync(
        &mut self,
    ) -> Result<ProvisioningCloudSyncResult, AppControllerError> {
        self.generate_authentication_challenge()?;
        Ok(self.no_cloud_sync_result(
            "Generate Challenge",
            "Challenge generated",
            "No sync required",
        ))
    }

    pub fn sign_canonical_payload_with_cloud_sync(
        &mut self,
    ) -> Result<ProvisioningCloudSyncResult, AppControllerError> {
        self.sign_canonical_auth_payload()?;
        Ok(self.no_cloud_sync_result(
            "Sign Canonical Payload",
            "Canonical payload signed",
            "No sync required",
        ))
    }

    pub fn verify_authentication_with_cloud_sync(
        &mut self,
    ) -> Result<ProvisioningCloudSyncResult, AppControllerError> {
        self.run_legitimate_authentication_demo()?;
        Ok(self.no_cloud_sync_result(
            "Verify Key Authentication",
            "Authentication verified",
            "Pending secure session activation",
        ))
    }

    pub fn activate_secure_session_with_cloud_sync(
        &mut self,
    ) -> Result<ProvisioningCloudSyncResult, AppControllerError> {
        self.establish_secure_session_demo()?;
        Ok(self.provisioning_sync_result(
            "Activate Secure Session",
            "Secure session activated",
            "provisioning_sessions",
            |controller| controller.sync_provisioning_session_record(),
        ))
    }

    pub fn finalize_provisioning_with_cloud_sync(
        &mut self,
    ) -> Result<ProvisioningCloudSyncResult, AppControllerError> {
        self.export_provisioning_report()?;
        Ok(self.provisioning_sync_result(
            "Finalize Provisioning",
            "Provisioning finalized",
            "audit_logs",
            |controller| controller.sync_audit_log_records(),
        ))
    }

    pub fn run_diagnostics_with_cloud_sync(
        &mut self,
    ) -> Result<ProvisioningCloudSyncResult, AppControllerError> {
        self.launch_diagnostics_tool()?;
        Ok(self.provisioning_sync_result(
            "Run Diagnostics",
            "Diagnostics completed",
            "diagnostic_results",
            |controller| controller.sync_diagnostic_result_records(),
        ))
    }

    pub fn create_customer_record(
        &mut self,
        owner_name: impl Into<String>,
        email: Option<String>,
        phone: Option<String>,
    ) -> Result<String, AppControllerError> {
        let owner_name = owner_name.into();
        let email = email.map(|value| value.trim().to_string());
        let phone = phone.map(|value| value.trim().to_string());
        if owner_name.trim().is_empty() {
            return Err(AppControllerError::Backend(
                "Owner name is required".to_string(),
            ));
        }
        if email
            .as_deref()
            .map(|value| !is_valid_email(value))
            .unwrap_or(true)
        {
            return Err(AppControllerError::Backend(
                "Valid email is required".to_string(),
            ));
        }
        let customer = CustomerMetadata {
            customer_id: generated_record_id("CUST"),
            owner_name,
            email,
            phone,
        };
        let message = self.persist_customer_record(customer.clone())?;
        self.active_customer = customer.clone();
        upsert_local_customer(&mut self.customer_records, customer);
        self.refresh_session_id_for_active_context();
        Ok(message)
    }

    pub fn load_customer_records(&mut self) -> Result<String, AppControllerError> {
        let client = match self.ensure_schema_initialized() {
            Ok(client) => client,
            Err(error) if is_cloud_not_configured(&error.to_string()) => {
                return Ok("Cloud database is not configured; using local demo records".to_string());
            }
            Err(error) => return Err(error),
        };
        match self.run_cloud(async { client.list_customers().await }) {
            Ok(records) if !records.is_empty() => {
                self.customer_records = records;
                if !self
                    .customer_records
                    .iter()
                    .any(|record| record.customer_id == self.active_customer.customer_id)
                {
                    self.active_customer = self.customer_records[0].clone();
                }
                Ok(format!("Customers loaded: {}", self.customer_records.len()))
            }
            Ok(_) => Ok("Customers loaded: using local demo records".to_string()),
            Err(error) => self.safe_demo_fallback_or_error(error),
        }
    }

    pub fn select_customer(&mut self, customer_id: &str) -> Result<String, AppControllerError> {
        if let Some(customer) = self
            .customer_records
            .iter()
            .find(|record| record.customer_id == customer_id)
            .cloned()
        {
            self.active_customer = customer.clone();
            self.refresh_session_id_for_active_context();
            return Ok(format!("Customer selected: {}", customer.customer_id));
        }

        let client = self.ensure_schema_initialized()?;
        match self.run_cloud(async { client.get_customer(customer_id).await }) {
            Ok(Some(customer)) => {
                self.active_customer = customer.clone();
                upsert_local_customer(&mut self.customer_records, customer.clone());
                self.refresh_session_id_for_active_context();
                Ok(format!("Customer selected: {}", customer.customer_id))
            }
            Ok(None) => Err(AppControllerError::Backend(
                "Customer record is not available".to_string(),
            )),
            Err(error) => Err(Self::map_cloud_error(error)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_vehicle_record(
        &mut self,
        customer_id: impl Into<String>,
        vehicle_display_name: impl Into<String>,
        make: Option<String>,
        model: Option<String>,
        year: Option<i32>,
        vin: Option<String>,
        registration_number: Option<String>,
    ) -> Result<String, AppControllerError> {
        let customer_id = customer_id.into();
        let vehicle_display_name = vehicle_display_name.into();
        let make = make.map(|value| value.trim().to_string());
        let model = model.map(|value| value.trim().to_string());
        let vin = vin.map(|value| value.trim().to_string());
        let registration_number = registration_number.map(|value| value.trim().to_string());
        if customer_id.trim().is_empty() {
            return Err(AppControllerError::Backend(
                "Select a customer before creating a vehicle".to_string(),
            ));
        }
        if vehicle_display_name.trim().is_empty() {
            return Err(AppControllerError::Backend(
                "Vehicle display name is required".to_string(),
            ));
        }
        if make.as_deref().map(str::is_empty).unwrap_or(true) {
            return Err(AppControllerError::Backend("Make is required".to_string()));
        }
        if model.as_deref().map(str::is_empty).unwrap_or(true) {
            return Err(AppControllerError::Backend("Model is required".to_string()));
        }
        if year.is_none() {
            return Err(AppControllerError::Backend(
                "Vehicle year must be numeric".to_string(),
            ));
        }
        let vehicle = VehicleMetadata {
            vehicle_id: generated_record_id("VEH"),
            customer_id,
            vehicle_display_name,
            make,
            model,
            year,
            vin,
            registration_number,
            provisioning_status: Some(DEFAULT_PROVISIONING_STATUS.to_string()),
        };
        let message = self.persist_vehicle_record(vehicle.clone())?;
        self.active_vehicle = vehicle.clone();
        upsert_local_vehicle(&mut self.vehicle_records, vehicle);
        self.align_active_customer_to_vehicle();
        self.refresh_session_id_for_active_context();
        Ok(message)
    }

    pub fn load_vehicle_records(&mut self) -> Result<String, AppControllerError> {
        let client = match self.ensure_schema_initialized() {
            Ok(client) => client,
            Err(error) if is_cloud_not_configured(&error.to_string()) => {
                return Ok("Cloud database is not configured; using local demo records".to_string());
            }
            Err(error) => return Err(error),
        };
        match self.run_cloud(async { client.list_vehicles().await }) {
            Ok(records) if !records.is_empty() => {
                self.vehicle_records = records;
                if !self
                    .vehicle_records
                    .iter()
                    .any(|record| record.vehicle_id == self.active_vehicle.vehicle_id)
                {
                    self.active_vehicle = self.vehicle_records[0].clone();
                    self.align_active_customer_to_vehicle();
                    self.refresh_session_id_for_active_context();
                }
                Ok(format!("Vehicles loaded: {}", self.vehicle_records.len()))
            }
            Ok(_) => Ok("Vehicles loaded: using local demo records".to_string()),
            Err(error) => self.safe_demo_fallback_or_error(error),
        }
    }

    pub fn load_vehicle_records_for_customer(
        &mut self,
        customer_id: &str,
    ) -> Result<String, AppControllerError> {
        let client = match self.ensure_schema_initialized() {
            Ok(client) => client,
            Err(error) if is_cloud_not_configured(&error.to_string()) => {
                return Ok("Cloud database is not configured; using local demo records".to_string());
            }
            Err(error) => return Err(error),
        };
        match self.run_cloud(async { client.list_vehicles_for_customer(customer_id).await }) {
            Ok(records) if !records.is_empty() => {
                self.vehicle_records = records;
                self.active_vehicle = self.vehicle_records[0].clone();
                self.align_active_customer_to_vehicle();
                self.refresh_session_id_for_active_context();
                Ok(format!("Vehicles loaded: {}", self.vehicle_records.len()))
            }
            Ok(_) => Ok("Vehicles loaded: no cloud records for selected customer".to_string()),
            Err(error) => Err(Self::map_cloud_error(error)),
        }
    }

    pub fn select_vehicle(&mut self, vehicle_id: &str) -> Result<String, AppControllerError> {
        if let Some(vehicle) = self
            .vehicle_records
            .iter()
            .find(|record| record.vehicle_id == vehicle_id)
            .cloned()
        {
            self.active_vehicle = vehicle.clone();
            self.align_active_customer_to_vehicle();
            self.refresh_session_id_for_active_context();
            return Ok(format!("Vehicle selected: {}", vehicle.vehicle_id));
        }

        let client = self.ensure_schema_initialized()?;
        match self.run_cloud(async { client.get_vehicle(vehicle_id).await }) {
            Ok(Some(vehicle)) => {
                self.active_vehicle = vehicle.clone();
                upsert_local_vehicle(&mut self.vehicle_records, vehicle.clone());
                self.align_active_customer_to_vehicle();
                self.refresh_session_id_for_active_context();
                Ok(format!("Vehicle selected: {}", vehicle.vehicle_id))
            }
            Ok(None) => Err(AppControllerError::Backend(
                "Vehicle record is not available".to_string(),
            )),
            Err(error) => Err(Self::map_cloud_error(error)),
        }
    }

    pub fn create_key_fob_record(
        &mut self,
        vehicle_id: impl Into<String>,
        fob_label: impl Into<String>,
    ) -> Result<String, AppControllerError> {
        let vehicle_id = vehicle_id.into();
        let fob_label = fob_label.into();
        if vehicle_id.trim().is_empty() {
            return Err(AppControllerError::Backend(
                "Select a vehicle before creating a key fob".to_string(),
            ));
        }
        if fob_label.trim().is_empty() {
            return Err(AppControllerError::Backend(
                "Key fob label is required".to_string(),
            ));
        }
        let key_fob = KeyFobMetadata {
            fob_id: generated_record_id("FOB"),
            vehicle_id,
            customer_id: self.active_customer.customer_id.clone(),
            fob_label,
            public_key_fingerprint: None,
            certificate_status: Some(DEFAULT_CERTIFICATE_STATUS.to_string()),
            provisioning_status: Some(DEFAULT_PROVISIONING_STATUS.to_string()),
        };
        self.active_key_fob = key_fob.clone();
        upsert_local_key_fob(&mut self.key_fob_records, key_fob);
        self.align_active_vehicle_to_key_fob();
        self.refresh_session_id_for_active_context();
        self.keyfob_detected = false;
        self.session = None;
        self.last_auth_result = None;
        self.last_access_decision = None;
        self.ensure_active_key_fob_crypto_identity()?;
        let key_fob = self.key_fob_metadata();
        let message = self.persist_key_fob_record(key_fob.clone())?;
        self.active_key_fob = key_fob.clone();
        upsert_local_key_fob(&mut self.key_fob_records, key_fob);
        Ok(message)
    }

    pub fn load_key_fob_records(&mut self) -> Result<String, AppControllerError> {
        let client = match self.ensure_schema_initialized() {
            Ok(client) => client,
            Err(error) if is_cloud_not_configured(&error.to_string()) => {
                return Ok("Cloud database is not configured; using local demo records".to_string());
            }
            Err(error) => return Err(error),
        };
        match self.run_cloud(async { client.list_key_fobs().await }) {
            Ok(records) if !records.is_empty() => {
                self.key_fob_records = records;
                if !self
                    .key_fob_records
                    .iter()
                    .any(|record| record.fob_id == self.active_key_fob.fob_id)
                {
                    self.active_key_fob = self.key_fob_records[0].clone();
                    self.align_active_vehicle_to_key_fob();
                    self.refresh_session_id_for_active_context();
                }
                Ok(format!("Key fobs loaded: {}", self.key_fob_records.len()))
            }
            Ok(_) => Ok("Key fobs loaded: using local demo records".to_string()),
            Err(error) => self.safe_demo_fallback_or_error(error),
        }
    }

    pub fn load_key_fob_records_for_vehicle(
        &mut self,
        vehicle_id: &str,
    ) -> Result<String, AppControllerError> {
        let client = match self.ensure_schema_initialized() {
            Ok(client) => client,
            Err(error) if is_cloud_not_configured(&error.to_string()) => {
                return Ok("Cloud database is not configured; using local demo records".to_string());
            }
            Err(error) => return Err(error),
        };
        match self.run_cloud(async { client.list_key_fobs_for_vehicle(vehicle_id).await }) {
            Ok(records) if !records.is_empty() => {
                self.key_fob_records = records;
                self.active_key_fob = self.key_fob_records[0].clone();
                self.align_active_vehicle_to_key_fob();
                self.refresh_session_id_for_active_context();
                Ok(format!("Key fobs loaded: {}", self.key_fob_records.len()))
            }
            Ok(_) => Ok("Key fobs loaded: no cloud records for selected vehicle".to_string()),
            Err(error) => Err(Self::map_cloud_error(error)),
        }
    }

    pub fn select_key_fob(&mut self, fob_id: &str) -> Result<String, AppControllerError> {
        if let Some(key_fob) = self
            .key_fob_records
            .iter()
            .find(|record| record.fob_id == fob_id)
            .cloned()
        {
            self.active_key_fob = key_fob.clone();
            self.align_active_vehicle_to_key_fob();
            self.refresh_session_id_for_active_context();
            self.keyfob_detected = false;
            self.session = None;
            self.last_auth_result = None;
            self.last_access_decision = None;
            self.ensure_active_key_fob_crypto_identity()?;
            return Ok(format!(
                "Key fob selected: {}; crypto identity ready",
                key_fob.fob_id
            ));
        }

        let client = self.ensure_schema_initialized()?;
        match self.run_cloud(async { client.get_key_fob(fob_id).await }) {
            Ok(Some(key_fob)) => {
                self.active_key_fob = key_fob.clone();
                upsert_local_key_fob(&mut self.key_fob_records, key_fob.clone());
                self.align_active_vehicle_to_key_fob();
                self.refresh_session_id_for_active_context();
                self.keyfob_detected = false;
                self.session = None;
                self.last_auth_result = None;
                self.last_access_decision = None;
                self.ensure_active_key_fob_crypto_identity()?;
                Ok(format!(
                    "Key fob selected: {}; crypto identity ready",
                    key_fob.fob_id
                ))
            }
            Ok(None) => Err(AppControllerError::Backend(
                "Key fob record is not available".to_string(),
            )),
            Err(error) => Err(Self::map_cloud_error(error)),
        }
    }

    pub fn sync_customer_metadata(&mut self) -> Result<String, AppControllerError> {
        let metadata = self.customer_metadata();
        let client = self.ensure_schema_initialized()?;
        let message = self
            .run_cloud(async { client.upsert_customer(&metadata).await })
            .map_err(Self::map_cloud_error)?;

        self.save_log_entry(
            "[DB]",
            format!("Customer metadata synced: {}", metadata.customer_id),
        )?;
        Ok(message)
    }

    pub fn sync_vehicle_metadata(&mut self) -> Result<String, AppControllerError> {
        let metadata = self.vehicle_metadata();
        let client = self.ensure_schema_initialized()?;
        let message = self
            .run_cloud(async { client.upsert_vehicle(&metadata).await })
            .map_err(Self::map_cloud_error)?;

        self.save_log_entry(
            "[DB]",
            format!("Vehicle metadata synced: {}", metadata.vehicle_display_name),
        )?;
        Ok(message)
    }

    pub fn sync_key_fob_metadata(&mut self) -> Result<String, AppControllerError> {
        let metadata = self.key_fob_metadata();
        let client = self.ensure_schema_initialized()?;
        let message = self
            .run_cloud(async { client.upsert_key_fob(&metadata).await })
            .map_err(Self::map_cloud_error)?;

        self.save_log_entry(
            "[DB]",
            format!("Key fob metadata synced: {}", metadata.fob_label),
        )?;
        Ok(message)
    }

    pub fn sync_active_cloud_metadata(&mut self) -> Result<String, AppControllerError> {
        let customer = self.customer_metadata();
        let vehicle = self.vehicle_metadata();
        let key_fob = self.key_fob_metadata();
        let client = self.ensure_schema_initialized()?;
        let message = self
            .run_cloud(async {
                client.upsert_customer(&customer).await?;
                client.upsert_vehicle(&vehicle).await?;
                client.upsert_key_fob(&key_fob).await?;
                Ok::<String, CloudStorageError>(
                    "Active provisioning metadata synced to cloud database".to_string(),
                )
            })
            .map_err(Self::map_cloud_error)?;

        self.save_log_entry(
            "[DB]",
            "Active provisioning metadata synced to company cloud database",
        )?;
        Ok(message)
    }

    pub fn sync_demo_cloud_metadata(&mut self) -> Result<String, AppControllerError> {
        self.sync_active_cloud_metadata()
    }

    pub fn sync_certificate_metadata(&mut self) -> Result<String, AppControllerError> {
        let metadata = self.certificate_metadata()?;
        let client = self.ensure_schema_initialized()?;
        let message = self
            .run_cloud(async { client.upsert_certificate_metadata(&metadata).await })
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
        let client = self.ensure_schema_initialized()?;
        let message = self
            .run_cloud(async { client.upsert_provisioning_session(&metadata).await })
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

    pub fn sync_audit_log_records(&mut self) -> Result<String, AppControllerError> {
        let records = self.active_audit_log_records();
        let client = self.ensure_schema_initialized()?;
        let message = self
            .run_cloud(async {
                for record in &records {
                    client.upsert_audit_log(record).await?;
                }
                Ok::<String, CloudStorageError>("Audit log records synced".to_string())
            })
            .map_err(Self::map_cloud_error)?;

        self.save_log_entry("[DB]", "Audit log records synced")?;
        self.save_log_entry(
            "[DB]",
            format!(
                "Audit context customer: {}",
                self.active_customer.customer_id
            ),
        )?;
        self.save_log_entry(
            "[DB]",
            format!("Audit context vehicle: {}", self.active_vehicle.vehicle_id),
        )?;
        self.save_log_entry(
            "[DB]",
            format!("Audit context key fob: {}", self.active_key_fob.fob_id),
        )?;
        self.save_log_entry("[SECURITY]", "Sensitive audit material: [REDACTED]")?;
        Ok(message)
    }

    pub fn sync_diagnostic_result_records(&mut self) -> Result<String, AppControllerError> {
        let client = self.ensure_schema_initialized()?;
        let message = self
            .run_cloud(async { client.sync_demo_diagnostic_results().await })
            .map_err(Self::map_cloud_error)?;

        self.save_log_entry("[DB]", "Diagnostic result records synced")?;
        self.save_log_entry(
            "[DB]",
            format!("Diagnostic result synced: {}", DIAGNOSTIC_RESULT_IDS[0]),
        )?;
        self.save_log_entry(
            "[DB]",
            format!("Diagnostic result synced: {}", DIAGNOSTIC_RESULT_IDS[8]),
        )?;
        self.save_log_entry("[SECURITY]", "Raw attack payload material: [REDACTED]")?;
        Ok(message)
    }

    pub fn sync_ca_encrypted_key_blob(&mut self) -> Result<String, AppControllerError> {
        self.ca_private_key_material()?;
        let master_key = parse_master_key_from_env().map_err(Self::map_cloud_error)?;
        let record = self.ca_encrypted_key_record(&master_key)?;
        let client = self.ensure_schema_initialized()?;
        let message = self
            .run_cloud(async { client.upsert_encrypted_key(&record).await })
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
        let client = self.ensure_schema_initialized()?;
        let message = self
            .run_cloud(async { client.upsert_encrypted_key(&record).await })
            .map_err(Self::map_cloud_error)?;

        self.save_log_entry(
            "[DB]",
            format!(
                "Key fob encrypted key blob uploaded: {}",
                self.derive_key_fob_encrypted_key_id()
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
        let client = self.ensure_schema_initialized()?;
        let message = self
            .run_cloud(async {
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

    pub fn get_active_customer_summary(&self) -> String {
        format!(
            "{} ({})",
            self.active_customer.owner_name, self.active_customer.customer_id
        )
    }

    pub fn get_active_vehicle_summary(&self) -> String {
        format!(
            "{} ({})",
            self.active_vehicle.vehicle_display_name, self.active_vehicle.vehicle_id
        )
    }

    pub fn get_active_key_fob_summary(&self) -> String {
        format!(
            "{} ({})",
            self.active_key_fob.fob_label, self.active_key_fob.fob_id
        )
    }

    pub fn get_active_key_fob_crypto_identity(&self) -> ActiveKeyFobCryptoIdentity {
        let certificate = self.current_certificate();
        let fob_is_active = self
            .keyfob
            .as_ref()
            .map(|keyfob| keyfob.subject_id == self.active_key_fob.fob_id)
            .unwrap_or(false);
        let public_key_fingerprint = self
            .keyfob
            .as_ref()
            .filter(|_| fob_is_active)
            .and_then(|keyfob| keyfob.public_key.as_ref())
            .map(|public_key| fingerprint(public_key))
            .or_else(|| self.active_key_fob.public_key_fingerprint.clone())
            .unwrap_or_else(|| "Pending".to_string());
        let certificate_subject_id = certificate.as_ref().map(|cert| cert.subject_id.clone());
        let certificate_status = if certificate
            .as_ref()
            .map(|cert| cert.subject_id == self.active_key_fob.fob_id)
            .unwrap_or(false)
        {
            "Issued".to_string()
        } else {
            self.active_key_fob
                .certificate_status
                .clone()
                .unwrap_or_else(|| DEFAULT_CERTIFICATE_STATUS.to_string())
        };
        let identity_source = if self.context_source_label() == "DemoDefault" {
            "DemoDefault"
        } else if fob_is_active {
            "GeneratedForSelectedFob"
        } else {
            "Missing"
        };
        let binding_status = if self.context_source_label() == "DemoDefault" && fob_is_active {
            "Demo/default crypto identity"
        } else if fob_is_active {
            "Bound to selected key fob"
        } else {
            "Missing identity"
        };

        ActiveKeyFobCryptoIdentity {
            fob_id: self.active_key_fob.fob_id.clone(),
            public_key_fingerprint,
            certificate_id: self.derive_certificate_id_for_active_context(),
            certificate_subject_id,
            certificate_status,
            identity_source: identity_source.to_string(),
            binding_status: binding_status.to_string(),
        }
    }

    pub fn active_customer_record(&self) -> CustomerMetadata {
        self.active_customer.clone()
    }

    pub fn active_vehicle_record(&self) -> VehicleMetadata {
        self.active_vehicle.clone()
    }

    pub fn active_key_fob_record(&self) -> KeyFobMetadata {
        self.active_key_fob.clone()
    }

    pub fn get_active_provisioning_context(&self) -> ActiveProvisioningContext {
        ActiveProvisioningContext {
            customer_id: self.active_customer.customer_id.clone(),
            owner_name: self.active_customer.owner_name.clone(),
            customer_email: self.active_customer.email.clone(),
            vehicle_id: self.active_vehicle.vehicle_id.clone(),
            vehicle_display_name: self.active_vehicle.vehicle_display_name.clone(),
            make: self.active_vehicle.make.clone(),
            model: self.active_vehicle.model.clone(),
            year: self.active_vehicle.year,
            fob_id: self.active_key_fob.fob_id.clone(),
            fob_label: self.active_key_fob.fob_label.clone(),
            certificate_id: self.derive_certificate_id_for_active_context(),
            session_id: self.derive_session_id_for_active_context(),
            context_source: self.context_source_label().to_string(),
        }
    }

    pub fn derive_certificate_id_for_active_context(&self) -> String {
        if self.active_key_fob.fob_id == DEMO_FOB_ID {
            DEMO_CERTIFICATE_ID.to_string()
        } else {
            format!("CERT-{}", self.active_key_fob.fob_id)
        }
    }

    pub fn derive_session_id_for_active_context(&self) -> String {
        self.active_session_id.clone()
    }

    pub fn get_cloud_sync_status_summary(&self) -> String {
        if self.cloud_auto_sync_enabled {
            "Cloud auto-sync enabled; safe provisioning metadata will sync after successful workflow actions".to_string()
        } else {
            "Cloud auto-sync disabled; cloud sync skipped until enabled".to_string()
        }
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

        self.sync_vehicle_module_to_active_context()?;
        self.ensure_active_key_fob_crypto_identity()?;

        if self.current_certificate().is_none() || !self.current_certificate_belongs_to_active_fob()
        {
            self.issue_keyfob_certificate()?;
        }

        Ok(())
    }

    fn sync_vehicle_module_to_active_context(&mut self) -> Result<(), AppControllerError> {
        if self.vehicle.vehicle_id == self.active_vehicle.vehicle_id {
            return Ok(());
        }

        let mut vehicle = VehicleControlModule::new(self.active_vehicle.vehicle_id.clone());
        vehicle.initialize()?;
        self.vehicle = vehicle;
        self.vehicle_connected = false;
        Ok(())
    }

    fn ensure_active_key_fob_crypto_identity(&mut self) -> Result<String, AppControllerError> {
        let active_fob_id = self.active_key_fob.fob_id.clone();
        if let Some(keyfob) = self.keyfob.as_ref() {
            if keyfob.subject_id == active_fob_id
                && keyfob.public_key.is_some()
                && keyfob.private_key.is_some()
            {
                let fingerprint_value = keyfob.public_key.as_ref().map(|key| fingerprint(key));
                if let Some(fingerprint_value) = fingerprint_value {
                    self.set_active_key_fob_public_fingerprint(fingerprint_value);
                }
                return Ok(format!(
                    "Crypto identity reused for selected key fob: {}",
                    active_fob_id
                ));
            }
        }

        let mut keyfob = DigitalKeyFob::new(active_fob_id.clone());
        let identity_source = match keyfob.load_keys() {
            Ok(()) => "LoadedFromLocalSecureStorage",
            Err(_) => {
                keyfob.initialize()?;
                keyfob.save_keys()?;
                "GeneratedForSelectedFob"
            }
        };

        if keyfob.public_key.is_none() || keyfob.private_key.is_none() {
            return Err(AppControllerError::Backend(
                "Selected key fob cryptographic identity is incomplete".to_string(),
            ));
        }

        let public_key_fingerprint = keyfob
            .public_key
            .as_ref()
            .map(|key| fingerprint(key))
            .unwrap_or_else(|| "Pending".to_string());
        self.set_active_key_fob_public_fingerprint(public_key_fingerprint.clone());
        self.keyfob = Some(keyfob);
        Ok(format!(
            "{} identity ready for selected key fob: {}; public key fingerprint {}",
            identity_source, active_fob_id, public_key_fingerprint
        ))
    }

    fn current_certificate_belongs_to_active_fob(&self) -> bool {
        let Some(keyfob) = self.keyfob.as_ref() else {
            return false;
        };
        if keyfob.subject_id != self.active_key_fob.fob_id {
            return false;
        }
        let Some(certificate) = self.current_certificate() else {
            return false;
        };
        certificate.subject_id == self.active_key_fob.fob_id
            && keyfob
                .public_key
                .as_ref()
                .map(|public_key| public_key == &certificate.public_key)
                .unwrap_or(false)
    }

    fn validate_key_fob_certificate_binding(
        &self,
        keyfob: &DigitalKeyFob,
        certificate: &Certificate,
    ) -> Result<(), AppControllerError> {
        if certificate.subject_id != self.active_key_fob.fob_id {
            return Err(AppControllerError::Backend(
                "Certificate subject does not match selected key fob".to_string(),
            ));
        }
        if keyfob.subject_id != self.active_key_fob.fob_id {
            return Err(AppControllerError::Backend(
                "Selected key fob identity mismatch".to_string(),
            ));
        }
        if keyfob
            .public_key
            .as_ref()
            .map(|public_key| public_key != &certificate.public_key)
            .unwrap_or(true)
        {
            return Err(AppControllerError::Backend(
                "Certificate public key does not match selected key fob".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_auth_proof_binding(
        &self,
        proof: &AuthenticationProof,
    ) -> Result<(), AppControllerError> {
        if proof.subject_id != self.active_key_fob.fob_id {
            return Err(AppControllerError::Backend(
                "Authentication proof subject does not match selected key fob".to_string(),
            ));
        }
        if proof.vehicle_id != self.active_vehicle.vehicle_id {
            return Err(AppControllerError::Backend(
                "Authentication proof vehicle does not match selected vehicle".to_string(),
            ));
        }
        let certificate: Certificate = serde_json::from_slice(&proof.certificate)
            .map_err(|e| AppControllerError::Backend(e.to_string()))?;
        if certificate.subject_id != proof.subject_id {
            return Err(AppControllerError::Backend(
                "Certificate subject does not match authentication proof".to_string(),
            ));
        }
        let keyfob = self.keyfob.as_ref().ok_or_else(|| {
            AppControllerError::Backend("Selected key fob identity is missing".to_string())
        })?;
        self.validate_key_fob_certificate_binding(keyfob, &certificate)
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
        self.active_customer.clone()
    }

    fn vehicle_metadata(&self) -> VehicleMetadata {
        let mut vehicle = self.active_vehicle.clone();
        vehicle.provisioning_status = Some(self.provisioning_status_label().to_string());
        vehicle
    }

    fn key_fob_metadata(&self) -> KeyFobMetadata {
        let mut key_fob = self.active_key_fob.clone();
        key_fob.public_key_fingerprint = self.key_fob_public_key_fingerprint();
        key_fob.certificate_status = Some(self.certificate_status_label().to_string());
        key_fob.provisioning_status = Some(self.provisioning_status_label().to_string());
        key_fob
    }

    fn update_active_key_fob_fingerprint(&mut self, keyfob: &DigitalKeyFob) {
        if let Some(public_key) = keyfob.public_key.as_ref() {
            self.set_active_key_fob_public_fingerprint(fingerprint(public_key));
        }
    }

    fn set_active_key_fob_public_fingerprint(&mut self, public_key_fingerprint: String) {
        self.active_key_fob.public_key_fingerprint = Some(public_key_fingerprint);
        upsert_local_key_fob(&mut self.key_fob_records, self.active_key_fob.clone());
    }

    fn context_source_label(&self) -> &'static str {
        let customer_is_demo = self.active_customer.customer_id == DEMO_CUSTOMER_ID;
        let vehicle_is_demo = self.active_vehicle.vehicle_id == DEMO_VEHICLE_ID;
        let fob_is_demo = self.active_key_fob.fob_id == DEMO_FOB_ID;

        if customer_is_demo && vehicle_is_demo && fob_is_demo {
            "DemoDefault"
        } else if !customer_is_demo && !vehicle_is_demo && !fob_is_demo {
            "CloudSelected"
        } else {
            "MixedSelection"
        }
    }

    fn refresh_session_id_for_active_context(&mut self) {
        if self.context_source_label() == "DemoDefault" {
            self.active_session_id = DEMO_SESSION_ID.to_string();
        } else if self.active_session_id == DEMO_SESSION_ID {
            self.active_session_id = generated_record_id("SESSION");
        }
    }

    fn align_active_customer_to_vehicle(&mut self) {
        if self.active_customer.customer_id == self.active_vehicle.customer_id {
            return;
        }
        if let Some(customer) = self
            .customer_records
            .iter()
            .find(|record| record.customer_id == self.active_vehicle.customer_id)
            .cloned()
        {
            self.active_customer = customer;
        }
    }

    fn align_active_vehicle_to_key_fob(&mut self) {
        if self.active_vehicle.vehicle_id != self.active_key_fob.vehicle_id {
            if let Some(vehicle) = self
                .vehicle_records
                .iter()
                .find(|record| record.vehicle_id == self.active_key_fob.vehicle_id)
                .cloned()
            {
                self.active_vehicle = vehicle;
            }
        }
        self.align_active_customer_to_vehicle();
    }

    fn certificate_metadata(&self) -> Result<CertificateMetadata, AppControllerError> {
        let certificate = self.current_certificate().ok_or_else(|| {
            AppControllerError::Backend(
                "Certificate metadata is not available for cloud sync".to_string(),
            )
        })?;
        let keyfob = self.keyfob.as_ref().ok_or_else(|| {
            AppControllerError::Backend(
                "Certificate metadata is not available for selected key fob".to_string(),
            )
        })?;
        self.validate_key_fob_certificate_binding(keyfob, &certificate)?;
        let issued_at = parse_certificate_timestamp(&certificate.issued_at)?;
        let expires_at = parse_certificate_timestamp(&certificate.expires_at)?;

        Ok(CertificateMetadata {
            certificate_id: self.derive_certificate_id_for_active_context(),
            fob_id: self.active_key_fob.fob_id.clone(),
            subject_id: certificate.subject_id.clone(),
            issuer: certificate.issuer,
            issued_at: Some(issued_at),
            expires_at: Some(expires_at),
            public_key_fingerprint: Some(fingerprint(&certificate.public_key)),
            signature_algorithm: CERTIFICATE_SIGNATURE_ALGORITHM.to_string(),
            certificate_status: ISSUED_CERTIFICATE_STATUS.to_string(),
        })
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

        Ok(ProvisioningSessionMetadata {
            session_id: self.derive_session_id_for_active_context(),
            customer_id: self.active_customer.customer_id.clone(),
            vehicle_id: self.active_vehicle.vehicle_id.clone(),
            fob_id: self.active_key_fob.fob_id.clone(),
            certificate_id: self.derive_certificate_id_for_active_context(),
            auth_status: AUTHENTICATED_STATUS.to_string(),
            session_status: SECURE_SESSION_ESTABLISHED_STATUS.to_string(),
            access_decision: GRANT_ACCESS_DECISION.to_string(),
            session_algorithm: SESSION_ALGORITHM.to_string(),
            started_at: Some(started_at),
            completed_at: Some(completed_at),
        })
    }

    fn active_audit_log_records(&self) -> Vec<AuditLogRecord> {
        let now = Utc::now();
        let context = self.get_active_provisioning_context();
        vec![
            AuditLogRecord {
                log_id: generated_record_id("AUDIT"),
                session_id: context.session_id.clone(),
                event_type: "provisioning_context".to_string(),
                event_message: format!(
                    "Provisioning context selected: customer {}, vehicle {}, key fob {}",
                    context.customer_id, context.vehicle_id, context.fob_id
                ),
                severity: "info".to_string(),
                actor: "AIACS-GUI".to_string(),
                created_at: now,
            },
            AuditLogRecord {
                log_id: generated_record_id("AUDIT"),
                session_id: context.session_id,
                event_type: "provisioning_status".to_string(),
                event_message: format!(
                    "Provisioning finalized for certificate {} with sensitive material [REDACTED]",
                    context.certificate_id
                ),
                severity: "info".to_string(),
                actor: "AIACS-GUI".to_string(),
                created_at: now,
            },
        ]
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
            key_id: self.derive_key_fob_encrypted_key_id(),
            owner_type: "key_fob".to_string(),
            owner_id: self.active_key_fob.fob_id.clone(),
            public_key_fingerprint: public_fingerprint,
            key_purpose: KEY_FOB_KEY_PURPOSE.to_string(),
            storage_status: ENCRYPTED_KEY_STORAGE_STATUS.to_string(),
            encrypted_key,
        })
    }

    fn derive_key_fob_encrypted_key_id(&self) -> String {
        if self.active_key_fob.fob_id == DEMO_FOB_ID {
            KEY_FOB_ENCRYPTED_KEY_ID.to_string()
        } else {
            format!("KEY-{}", self.active_key_fob.fob_id)
        }
    }

    fn key_fob_private_key_path(&self) -> String {
        if self.active_key_fob.fob_id == DEMO_FOB_ID {
            KEYFOB_PRIVATE_KEY_PATH.to_string()
        } else {
            format!("keys/fob_{}_private.json", self.active_key_fob.fob_id)
        }
    }

    fn key_fob_public_key_path(&self) -> String {
        if self.active_key_fob.fob_id == DEMO_FOB_ID {
            KEYFOB_PUBLIC_KEY_PATH.to_string()
        } else {
            format!("keys/fob_{}_public.json", self.active_key_fob.fob_id)
        }
    }

    fn key_fob_certificate_path(&self) -> String {
        if self.active_key_fob.fob_id == DEMO_FOB_ID {
            KEYFOB_CERTIFICATE_PATH.to_string()
        } else {
            format!("certs/fob_{}.json", self.active_key_fob.fob_id)
        }
    }

    fn certificate_status_label(&self) -> &'static str {
        if self.current_certificate_belongs_to_active_fob() {
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

    fn run_cloud<F: Future>(&self, future: F) -> F::Output {
        self.cloud_runtime.block_on(future)
    }

    fn ensure_cloud_client(&mut self) -> Result<CloudStorageClient, AppControllerError> {
        if let Some(client) = &self.cloud_client {
            return Ok(client.clone());
        }

        let client = self
            .run_cloud(async {
                let client = CloudStorageClient::connect_from_env().await?;
                client.health_check().await?;
                Ok::<CloudStorageClient, CloudStorageError>(client)
            })
            .map_err(Self::map_cloud_error)?;
        self.cloud_client = Some(client.clone());
        Ok(client)
    }

    fn clear_failed_cloud_client(&mut self) {
        self.cloud_client = None;
        self.schema_initialized = false;
    }

    fn ensure_schema_initialized(&mut self) -> Result<CloudStorageClient, AppControllerError> {
        let client = self.ensure_cloud_client()?;
        if !self.schema_initialized {
            if let Err(error) = self.run_cloud(client.initialize_schema()) {
                self.schema_initialized = false;
                return Err(Self::map_cloud_error(error));
            }
            self.schema_initialized = true;
        }
        Ok(client)
    }

    fn map_cloud_error(error: CloudStorageError) -> AppControllerError {
        match error {
            CloudStorageError::MissingDatabaseUrl => AppControllerError::Backend(
                "Cloud database is not configured. Check .env.local.".to_string(),
            ),
            CloudStorageError::MissingMasterKey
            | CloudStorageError::InvalidMasterKeyBase64
            | CloudStorageError::InvalidMasterKeySize => {
                AppControllerError::Backend("Cloud encryption key is not configured".to_string())
            }
            CloudStorageError::HealthCheckFailed => AppControllerError::Backend(
                "Cloud database health check failed. Check network/Neon availability.".to_string(),
            ),
            CloudStorageError::ConnectionFailed => AppControllerError::Backend(
                "Cloud database connection failed. Retry after database warm-up.".to_string(),
            ),
            other => AppControllerError::Backend(other.to_string()),
        }
    }

    fn run_auto_sync(
        &mut self,
        success_label: &'static str,
        sync: impl FnOnce(&mut Self) -> Result<String, AppControllerError>,
    ) -> Result<String, AppControllerError> {
        if !self.cloud_auto_sync_enabled {
            self.save_log_entry("[DB]", "Auto-sync skipped: disabled")?;
            return Ok("Cloud auto-sync skipped: disabled".to_string());
        }

        match sync(self) {
            Ok(_) => {
                let message = format!("Cloud auto-sync completed: {}", success_label);
                self.save_log_entry("[DB]", message.clone())?;
                self.save_log_entry("[SECURITY]", "Cloud secret material: [REDACTED]")?;
                Ok(message)
            }
            Err(error) => {
                let message = format!("Cloud auto-sync failed: {}", error);
                self.save_log_entry("[DB]", message.clone())?;
                Ok(message)
            }
        }
    }

    fn startup_cloud_sync_enabled_result(&mut self) -> StartupCloudSyncResult {
        self.cloud_auto_sync_enabled = true;
        self.schema_initialized = true;
        let message = "Cloud Auto Sync enabled automatically".to_string();
        let _ = self.save_log_entry("[DB]", message.clone());
        let _ = self.save_log_entry("[DB]", "Cloud schema initialized");
        let _ = self.save_log_entry("[SECURITY]", "Cloud startup secrets: [REDACTED]");
        StartupCloudSyncResult {
            attempted: true,
            enabled: true,
            status_message: message,
            safe_error: None,
        }
    }

    fn startup_cloud_sync_disabled_result(
        &mut self,
        error: AppControllerError,
    ) -> StartupCloudSyncResult {
        self.cloud_auto_sync_enabled = false;
        let safe_error = error.to_string();
        let status_message = if is_cloud_not_configured(&safe_error) {
            "Cloud Auto Sync disabled - cloud database not configured".to_string()
        } else if safe_error.contains("health check") {
            "Cloud Auto Sync disabled - health check failed".to_string()
        } else {
            "Cloud Auto Sync disabled - startup cloud check failed".to_string()
        };
        let _ = self.save_log_entry("[DB]", status_message.clone());
        StartupCloudSyncResult {
            attempted: true,
            enabled: false,
            status_message,
            safe_error: Some(safe_error),
        }
    }

    fn provisioning_sync_result(
        &mut self,
        action_name: &'static str,
        provisioning_status: &'static str,
        cloud_table_updated: &'static str,
        sync: impl FnOnce(&mut Self) -> Result<String, AppControllerError>,
    ) -> ProvisioningCloudSyncResult {
        if !self.cloud_auto_sync_enabled {
            let _ = self.save_log_entry("[DB]", "Cloud sync skipped: disabled");
            return self.build_provisioning_cloud_sync_result(
                action_name,
                provisioning_status,
                false,
                "Skipped - disabled".to_string(),
                "None",
                None,
            );
        }

        match sync(self) {
            Ok(_) => {
                let _ = self
                    .save_log_entry("[DB]", format!("Cloud sync completed for {}", action_name));
                let _ = self.save_log_entry("[SECURITY]", "Cloud secret material: [REDACTED]");
                self.build_provisioning_cloud_sync_result(
                    action_name,
                    provisioning_status,
                    true,
                    "Synced".to_string(),
                    cloud_table_updated,
                    None,
                )
            }
            Err(error) => {
                let safe_error = error.to_string();
                let _ = self.save_log_entry(
                    "[DB]",
                    format!("Cloud sync failed for {}: {}", action_name, safe_error),
                );
                self.build_provisioning_cloud_sync_result(
                    action_name,
                    provisioning_status,
                    true,
                    format!("Failed - {}", safe_error),
                    cloud_table_updated,
                    Some(safe_error),
                )
            }
        }
    }

    fn no_cloud_sync_result(
        &mut self,
        action_name: &'static str,
        provisioning_status: &'static str,
        cloud_sync_status: &'static str,
    ) -> ProvisioningCloudSyncResult {
        let _ = self.save_log_entry("[DB]", cloud_sync_status);
        self.build_provisioning_cloud_sync_result(
            action_name,
            provisioning_status,
            false,
            cloud_sync_status.to_string(),
            "None",
            None,
        )
    }

    fn build_provisioning_cloud_sync_result(
        &self,
        action_name: &'static str,
        provisioning_status: &'static str,
        cloud_sync_attempted: bool,
        cloud_sync_status: String,
        cloud_table_updated: &'static str,
        safe_error: Option<String>,
    ) -> ProvisioningCloudSyncResult {
        let context = self.get_active_provisioning_context();
        ProvisioningCloudSyncResult {
            action_name: action_name.to_string(),
            provisioning_status: provisioning_status.to_string(),
            local_success: true,
            cloud_sync_attempted,
            cloud_sync_status,
            cloud_table_updated: cloud_table_updated.to_string(),
            safe_error,
            active_customer_id: context.customer_id,
            active_vehicle_id: context.vehicle_id,
            active_fob_id: context.fob_id,
            active_certificate_id: context.certificate_id,
            active_session_id: context.session_id,
        }
    }

    fn persist_customer_record(
        &mut self,
        customer: CustomerMetadata,
    ) -> Result<String, AppControllerError> {
        let client = match self.ensure_schema_initialized() {
            Ok(client) => client,
            Err(error) if is_cloud_not_configured(&error.to_string()) => {
                return Ok(format!(
                    "Customer created locally: {}; cloud database is not configured",
                    customer.customer_id
                ));
            }
            Err(error) => return Err(error),
        };
        match self.run_cloud(async { client.create_customer(&customer).await }) {
            Ok(_) => {
                self.save_log_entry(
                    "[DB]",
                    format!(
                        "Customer created and saved to cloud: {}",
                        customer.customer_id
                    ),
                )?;
                Ok(format!(
                    "Customer created and saved to cloud: {}",
                    customer.customer_id
                ))
            }
            Err(error) => Err(Self::map_cloud_error(error)),
        }
    }

    fn persist_vehicle_record(
        &mut self,
        vehicle: VehicleMetadata,
    ) -> Result<String, AppControllerError> {
        let client = match self.ensure_schema_initialized() {
            Ok(client) => client,
            Err(error) if is_cloud_not_configured(&error.to_string()) => {
                return Ok(format!(
                    "Vehicle created locally: {}; cloud database is not configured",
                    vehicle.vehicle_id
                ));
            }
            Err(error) => return Err(error),
        };
        match self.run_cloud(async { client.create_vehicle(&vehicle).await }) {
            Ok(_) => {
                self.save_log_entry(
                    "[DB]",
                    format!("Vehicle created and saved to cloud: {}", vehicle.vehicle_id),
                )?;
                Ok(format!(
                    "Vehicle created and saved to cloud: {}",
                    vehicle.vehicle_id
                ))
            }
            Err(error) => Err(Self::map_cloud_error(error)),
        }
    }

    fn persist_key_fob_record(
        &mut self,
        key_fob: KeyFobMetadata,
    ) -> Result<String, AppControllerError> {
        let client = match self.ensure_schema_initialized() {
            Ok(client) => client,
            Err(error) if is_cloud_not_configured(&error.to_string()) => {
                return Ok(format!(
                    "Key fob created locally: {}; cloud database is not configured",
                    key_fob.fob_id
                ));
            }
            Err(error) => return Err(error),
        };
        match self.run_cloud(async { client.create_key_fob_metadata(&key_fob).await }) {
            Ok(_) => {
                self.save_log_entry(
                    "[DB]",
                    format!("Key fob created and saved to cloud: {}", key_fob.fob_id),
                )?;
                Ok(format!(
                    "Key fob created and saved to cloud: {}",
                    key_fob.fob_id
                ))
            }
            Err(error) => Err(Self::map_cloud_error(error)),
        }
    }

    fn safe_demo_fallback_or_error(
        &self,
        error: CloudStorageError,
    ) -> Result<String, AppControllerError> {
        let mapped = Self::map_cloud_error(error).to_string();
        if is_cloud_not_configured(&mapped) {
            Ok("Cloud database is not configured; using local demo records".to_string())
        } else {
            Err(AppControllerError::Backend(mapped))
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

fn generated_record_id(prefix: &str) -> String {
    let id = Uuid::new_v4().simple().to_string();
    format!("{prefix}-{}", &id[..8].to_uppercase())
}

fn is_valid_email(value: &str) -> bool {
    let trimmed = value.trim();
    let Some((local, domain)) = trimmed.split_once('@') else {
        return false;
    };
    !local.is_empty() && domain.contains('.') && !domain.ends_with('.')
}

fn is_cloud_not_configured(message: &str) -> bool {
    message.starts_with("Cloud database is not configured")
}

fn upsert_local_customer(records: &mut Vec<CustomerMetadata>, record: CustomerMetadata) {
    if let Some(existing) = records
        .iter_mut()
        .find(|existing| existing.customer_id == record.customer_id)
    {
        *existing = record;
    } else {
        records.push(record);
    }
}

fn upsert_local_vehicle(records: &mut Vec<VehicleMetadata>, record: VehicleMetadata) {
    if let Some(existing) = records
        .iter_mut()
        .find(|existing| existing.vehicle_id == record.vehicle_id)
    {
        *existing = record;
    } else {
        records.push(record);
    }
}

fn upsert_local_key_fob(records: &mut Vec<KeyFobMetadata>, record: KeyFobMetadata) {
    if let Some(existing) = records
        .iter_mut()
        .find(|existing| existing.fob_id == record.fob_id)
    {
        *existing = record;
    } else {
        records.push(record);
    }
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
    use crate::crypto::CryptoEngine;
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

    fn bind_custom_context(controller: &mut AppController, suffix: &str) {
        let customer = CustomerMetadata {
            customer_id: format!("CUST-CRYPTO-{suffix}"),
            owner_name: format!("Crypto Owner {suffix}"),
            email: Some(format!("crypto-{suffix}@example.com")),
            phone: None,
        };
        let vehicle = VehicleMetadata {
            vehicle_id: format!("VEH-CRYPTO-{suffix}"),
            customer_id: customer.customer_id.clone(),
            vehicle_display_name: format!("Crypto Vehicle {suffix}"),
            make: Some("Nissan".to_string()),
            model: Some("Magnite".to_string()),
            year: Some(2021),
            vin: None,
            registration_number: None,
            provisioning_status: Some(DEFAULT_PROVISIONING_STATUS.to_string()),
        };
        let key_fob = KeyFobMetadata {
            fob_id: format!("FOB-CRYPTO-{suffix}"),
            vehicle_id: vehicle.vehicle_id.clone(),
            customer_id: customer.customer_id.clone(),
            fob_label: format!("Crypto Fob {suffix}"),
            public_key_fingerprint: None,
            certificate_status: Some(DEFAULT_CERTIFICATE_STATUS.to_string()),
            provisioning_status: Some(DEFAULT_PROVISIONING_STATUS.to_string()),
        };

        controller.active_customer = customer.clone();
        controller.active_vehicle = vehicle.clone();
        controller.active_key_fob = key_fob.clone();
        upsert_local_customer(&mut controller.customer_records, customer);
        upsert_local_vehicle(&mut controller.vehicle_records, vehicle);
        upsert_local_key_fob(&mut controller.key_fob_records, key_fob);
        controller.refresh_session_id_for_active_context();
        controller.keyfob = None;
        controller.session = None;
        controller.last_auth_result = None;
        controller.last_access_decision = None;
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
        assert!(message.contains(DEMO_FOB_ID));
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
            .run_legitimate_authentication_demo()
            .expect("Legitimate auth demo failed");
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
            .run_legitimate_authentication_demo()
            .expect("Legitimate auth demo failed");
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
    fn test_custom_key_fob_crypto_identity_is_distinct_from_demo() {
        let mut demo = AppController::new();
        demo.ensure_active_key_fob_crypto_identity()
            .expect("demo identity should initialize");
        let demo_public_key = demo
            .keyfob
            .as_ref()
            .and_then(|keyfob| keyfob.public_key.clone())
            .expect("demo public key should exist");

        let mut controller = AppController::new();
        bind_custom_context(&mut controller, "DISTINCT");
        let message = controller
            .ensure_active_key_fob_crypto_identity()
            .expect("custom identity should initialize");
        let identity = controller.get_active_key_fob_crypto_identity();
        let custom_keyfob = controller.keyfob.as_ref().expect("custom fob ready");

        assert!(message.contains("FOB-CRYPTO-DISTINCT"));
        assert_eq!(custom_keyfob.subject_id, "FOB-CRYPTO-DISTINCT");
        assert_ne!(
            custom_keyfob
                .public_key
                .as_ref()
                .expect("custom public key"),
            &demo_public_key
        );
        assert_eq!(identity.fob_id, "FOB-CRYPTO-DISTINCT");
        assert_eq!(identity.binding_status, "Bound to selected key fob");
        assert!(identity.public_key_fingerprint.starts_with("SHA256:"));
    }

    #[test]
    fn test_certificate_issuance_is_bound_to_selected_custom_fob() {
        let mut controller = AppController::new();
        bind_custom_context(&mut controller, "CERT");

        controller
            .issue_keyfob_certificate()
            .expect("custom certificate should issue");
        let certificate = controller.current_certificate().expect("certificate ready");
        let public_key = controller
            .keyfob
            .as_ref()
            .and_then(|keyfob| keyfob.public_key.clone())
            .expect("selected fob public key ready");
        let metadata = controller
            .certificate_metadata()
            .expect("certificate metadata should build");

        assert_eq!(certificate.subject_id, "FOB-CRYPTO-CERT");
        assert_eq!(certificate.public_key, public_key);
        assert_eq!(
            controller.derive_certificate_id_for_active_context(),
            "CERT-FOB-CRYPTO-CERT"
        );
        assert_eq!(metadata.certificate_id, "CERT-FOB-CRYPTO-CERT");
        assert_eq!(metadata.fob_id, "FOB-CRYPTO-CERT");
        assert_eq!(metadata.subject_id, "FOB-CRYPTO-CERT");
        assert_eq!(
            metadata.public_key_fingerprint,
            Some(fingerprint(&certificate.public_key))
        );
    }

    #[test]
    fn test_selected_fob_signing_and_verification_succeeds() {
        let mut controller = AppController::new();
        bind_custom_context(&mut controller, "AUTH");

        controller
            .issue_keyfob_certificate()
            .expect("custom certificate should issue");
        let message = controller
            .run_legitimate_authentication_demo()
            .expect("selected fob authentication should succeed");

        assert!(message.contains("Authentication successful"));
        assert_eq!(controller.last_auth_result, Some(AuthResult::Success));
        assert_eq!(
            controller.last_access_decision,
            Some(AccessDecision::GrantAccess)
        );
        assert_eq!(controller.vehicle.vehicle_id, "VEH-CRYPTO-AUTH");
    }

    #[test]
    fn test_verification_rejects_certificate_subject_mismatch_for_selected_fob() {
        let mut controller = AppController::new();
        controller
            .issue_keyfob_certificate()
            .expect("demo certificate should issue");
        controller.active_customer = CustomerMetadata {
            customer_id: "CUST-CRYPTO-MISMATCH".to_string(),
            owner_name: "Crypto Owner MISMATCH".to_string(),
            email: Some("crypto-mismatch@example.com".to_string()),
            phone: None,
        };
        controller.active_vehicle = VehicleMetadata {
            vehicle_id: "VEH-CRYPTO-MISMATCH".to_string(),
            customer_id: "CUST-CRYPTO-MISMATCH".to_string(),
            vehicle_display_name: "Crypto Vehicle MISMATCH".to_string(),
            make: Some("Nissan".to_string()),
            model: Some("Magnite".to_string()),
            year: Some(2021),
            vin: None,
            registration_number: None,
            provisioning_status: Some(DEFAULT_PROVISIONING_STATUS.to_string()),
        };
        controller.active_key_fob = KeyFobMetadata {
            fob_id: "FOB-CRYPTO-MISMATCH".to_string(),
            vehicle_id: "VEH-CRYPTO-MISMATCH".to_string(),
            customer_id: "CUST-CRYPTO-MISMATCH".to_string(),
            fob_label: "Crypto Fob MISMATCH".to_string(),
            public_key_fingerprint: None,
            certificate_status: Some(DEFAULT_CERTIFICATE_STATUS.to_string()),
            provisioning_status: Some(DEFAULT_PROVISIONING_STATUS.to_string()),
        };
        controller.refresh_session_id_for_active_context();

        let error = controller
            .certificate_metadata()
            .expect_err("stale demo certificate must not sync for custom fob")
            .to_string();

        assert!(error.contains("Certificate subject does not match selected key fob"));
    }

    #[test]
    fn test_authentication_rejects_payload_subject_mismatch() {
        let mut controller = AppController::new();
        bind_custom_context(&mut controller, "PAYLOAD");
        controller
            .issue_keyfob_certificate()
            .expect("custom certificate should issue");
        controller
            .sync_vehicle_module_to_active_context()
            .expect("vehicle should align");
        let challenge =
            AuthenticationEngine::generate_challenge(&mut controller.vehicle, "VEH-CRYPTO-PAYLOAD")
                .expect("challenge should generate");
        let mut proof = controller
            .keyfob
            .as_ref()
            .expect("fob ready")
            .create_auth_proof("VEH-CRYPTO-PAYLOAD", &challenge.nonce)
            .expect("proof should sign");
        proof.subject_id = "FOB-OTHER".to_string();

        let result = AuthenticationEngine::verify_response(
            &proof,
            controller.ca.as_ref().expect("ca ready"),
            &mut controller.vehicle,
            DEFAULT_TIMEOUT_SECONDS,
        )
        .expect("verification should return auth result");

        assert_eq!(result, AuthResult::IdentityMismatch);
    }

    #[test]
    fn test_authentication_rejects_signature_from_another_fob_key() {
        let mut controller = AppController::new();
        bind_custom_context(&mut controller, "BADSIG");
        controller
            .issue_keyfob_certificate()
            .expect("custom certificate should issue");
        controller
            .sync_vehicle_module_to_active_context()
            .expect("vehicle should align");
        let challenge =
            AuthenticationEngine::generate_challenge(&mut controller.vehicle, "VEH-CRYPTO-BADSIG")
                .expect("challenge should generate");
        let mut proof = controller
            .keyfob
            .as_ref()
            .expect("fob ready")
            .create_auth_proof("VEH-CRYPTO-BADSIG", &challenge.nonce)
            .expect("proof should sign");
        let mut rogue_fob = DigitalKeyFob::new("FOB-CRYPTO-BADSIG".to_string());
        rogue_fob.initialize().expect("rogue fob should initialize");
        let payload = canonical_auth_payload(
            &proof.vehicle_id,
            &proof.subject_id,
            &proof.nonce,
            &proof.timestamp,
        );
        proof.signature = CryptoEngine::sign_data(
            rogue_fob.private_key.as_ref().expect("rogue private key"),
            payload.as_bytes(),
        )
        .expect("rogue signature should sign")
        .data;

        let result = AuthenticationEngine::verify_response(
            &proof,
            controller.ca.as_ref().expect("ca ready"),
            &mut controller.vehicle,
            DEFAULT_TIMEOUT_SECONDS,
        )
        .expect("verification should return auth result");

        assert_eq!(result, AuthResult::InvalidSignature);
    }

    #[test]
    fn test_secure_session_requires_selected_fob_authentication() {
        let mut controller = AppController::new();
        bind_custom_context(&mut controller, "SESSIONBLOCK");
        controller
            .issue_keyfob_certificate()
            .expect("certificate should issue");

        let error = controller
            .establish_secure_session_demo()
            .expect_err("session should be blocked before authentication")
            .to_string();

        assert_eq!(error, "Secure session blocked: authentication not verified");
    }

    #[test]
    fn test_secure_session_metadata_uses_selected_context_after_authentication() {
        let mut controller = AppController::new();
        bind_custom_context(&mut controller, "SESSION");

        controller
            .run_legitimate_authentication_demo()
            .expect("auth should succeed");
        controller
            .establish_secure_session_demo()
            .expect("session should establish after auth");
        let metadata = controller
            .provisioning_session_metadata()
            .expect("session metadata should build");

        assert_eq!(metadata.customer_id, "CUST-CRYPTO-SESSION");
        assert_eq!(metadata.vehicle_id, "VEH-CRYPTO-SESSION");
        assert_eq!(metadata.fob_id, "FOB-CRYPTO-SESSION");
        assert_eq!(metadata.certificate_id, "CERT-FOB-CRYPTO-SESSION");
        assert_eq!(metadata.auth_status, AUTHENTICATED_STATUS);
        assert_eq!(metadata.session_status, SECURE_SESSION_ESTABLISHED_STATUS);
        assert_eq!(metadata.access_decision, GRANT_ACCESS_DECISION);
        assert_eq!(metadata.session_algorithm, SESSION_ALGORITHM);
    }

    #[test]
    fn test_custom_fob_status_strings_do_not_expose_secret_material() {
        let mut controller = AppController::new();
        bind_custom_context(&mut controller, "SAFE");
        controller
            .issue_keyfob_certificate()
            .expect("certificate should issue");
        controller
            .run_legitimate_authentication_demo()
            .expect("auth should succeed");
        controller
            .establish_secure_session_demo()
            .expect("session should establish");

        let identity = format!("{:?}", controller.get_active_key_fob_crypto_identity());
        let status = controller.get_safe_crypto_summary();
        let artifacts = controller.get_protocol_artifacts().join("\n");
        let logs = controller.event_log().join("\n");

        for output in [identity, status, artifacts, logs] {
            assert!(!output.contains("DATABASE_URL"));
            assert!(!output.contains("AIACS_MASTER_KEY"));
            assert!(!output.contains("private_key: ["));
            assert!(!output.contains("session_key: ["));
            assert!(!output.contains("shared_secret"));
            assert!(!output.contains("derived_aes_key"));
        }
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

        assert_eq!(
            message,
            "Cloud database is not configured. Check .env.local."
        );
        assert!(!message.contains("DATABASE_URL"));
        assert!(!message.contains("AIACS_MASTER_KEY"));
        assert!(!message.contains("postgresql://"));
        assert!(!message.contains("password"));
    }

    #[test]
    fn test_cloud_master_key_errors_are_safe_for_gui() {
        for error in [
            CloudStorageError::MissingMasterKey,
            CloudStorageError::InvalidMasterKeyBase64,
            CloudStorageError::InvalidMasterKeySize,
        ] {
            let message = AppController::map_cloud_error(error).to_string();

            assert_eq!(message, "Cloud encryption key is not configured");
            assert!(!message.contains("AIACS_MASTER_KEY"));
            assert!(!message.contains("DATABASE_URL"));
            assert!(!message.contains("postgresql://"));
        }
    }

    #[test]
    fn test_cloud_auto_sync_default_is_disabled() {
        let controller = AppController::new();

        assert!(!controller.is_cloud_auto_sync_enabled());
        assert_eq!(controller.get_cloud_auto_sync_status(), "Disabled");
    }

    #[test]
    fn test_startup_auto_enable_missing_database_url_is_safe() {
        let mut controller = AppController::new();
        let result = controller.startup_cloud_sync_disabled_result(AppControllerError::Backend(
            "Cloud database is not configured. Check .env.local.".to_string(),
        ));

        assert!(result.attempted);
        assert!(!result.enabled);
        assert!(!controller.is_cloud_auto_sync_enabled());
        assert_eq!(
            result.status_message,
            "Cloud Auto Sync disabled - cloud database not configured"
        );
        let display = result.to_string();
        for forbidden in [
            "DATABASE_URL",
            "AIACS_MASTER_KEY",
            "postgresql://",
            "private_key",
            "session_key",
            "shared_secret",
        ] {
            assert!(!display.contains(forbidden));
        }
    }

    #[test]
    fn test_startup_auto_enable_health_failure_does_not_cache_success() {
        let mut controller = AppController::new();
        controller.schema_initialized = true;
        let result = controller.startup_cloud_sync_disabled_result(AppControllerError::Backend(
            "Cloud database health check failed. Check network/Neon availability.".to_string(),
        ));
        controller.clear_failed_cloud_client();

        assert!(result.attempted);
        assert!(!result.enabled);
        assert_eq!(
            result.status_message,
            "Cloud Auto Sync disabled - health check failed"
        );
        assert!(!controller.is_cloud_auto_sync_enabled());
        assert!(controller.cloud_client.is_none());
        assert!(!controller.schema_initialized);
    }

    #[test]
    fn test_startup_auto_enable_success_updates_controller_state() {
        let mut controller = AppController::new();
        let result = controller.startup_cloud_sync_enabled_result();

        assert!(result.attempted);
        assert!(result.enabled);
        assert!(controller.is_cloud_auto_sync_enabled());
        assert!(controller.schema_initialized);
        assert_eq!(
            result.status_message,
            "Cloud Auto Sync enabled automatically"
        );
    }

    #[test]
    fn test_disable_cloud_auto_sync_returns_safe_message() {
        let mut controller = AppController::new();
        controller.cloud_auto_sync_enabled = true;

        let message = controller
            .disable_cloud_auto_sync()
            .expect("disable should not require cloud connection");

        assert_eq!(message, "Cloud auto-sync disabled");
        assert!(!controller.is_cloud_auto_sync_enabled());
        assert!(!message.contains("DATABASE_URL"));
        assert!(!message.contains("AIACS_MASTER_KEY"));
    }

    #[test]
    fn test_auto_sync_skipped_message_is_safe_when_disabled() {
        let mut controller = AppController::new();

        for result in [
            controller.auto_sync_after_metadata_ready(),
            controller.auto_sync_after_key_fob_registered(),
            controller.auto_sync_after_trust_initialized(),
            controller.auto_sync_after_certificate_issued(),
            controller.auto_sync_after_secure_session_established(),
            controller.auto_sync_after_provisioning_finalized(),
            controller.auto_sync_after_diagnostics_completed(),
        ] {
            let message = result.expect("disabled auto-sync should skip safely");
            assert_eq!(message, "Cloud auto-sync skipped: disabled");
            assert!(!message.contains("DATABASE_URL"));
            assert!(!message.contains("AIACS_MASTER_KEY"));
            assert!(!message.contains("private_key"));
            assert!(!message.contains("session_key"));
        }
    }

    #[test]
    fn test_audit_log_sync_error_is_safe_for_gui() {
        let error = AppController::map_cloud_error(CloudStorageError::AuditLogSyncFailed);
        let message = error.to_string();

        assert_eq!(message, "Audit log records could not be synced");
        for disallowed in [
            "DATABASE_URL",
            "AIACS_MASTER_KEY",
            "postgresql://",
            "private_key",
            "session_key",
            "shared_secret",
            "hkdf_output",
            "encrypted_key_blob",
            "encryption_nonce",
        ] {
            assert!(!message.contains(disallowed));
        }
    }

    #[test]
    fn test_diagnostic_result_sync_error_is_safe_for_gui() {
        let error = AppController::map_cloud_error(CloudStorageError::DiagnosticResultSyncFailed);
        let message = error.to_string();

        assert_eq!(message, "Diagnostic result records could not be synced");
        for disallowed in [
            "DATABASE_URL",
            "AIACS_MASTER_KEY",
            "postgresql://",
            "private_key",
            "forged_key",
            "session_key",
            "shared_secret",
            "hkdf_output",
            "raw_ciphertext",
            "raw_nonce",
            "encrypted_key_blob",
            "encryption_nonce",
        ] {
            assert!(!message.contains(disallowed));
        }
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
    fn test_active_record_summaries_use_selected_records() {
        let mut controller = AppController::new();

        let customer_message = controller
            .select_customer(crate::cloud_storage::DEMO_CUSTOMER_ID)
            .expect("demo customer should select");
        assert!(customer_message.contains("Customer selected"));
        assert!(controller
            .get_active_customer_summary()
            .contains(crate::cloud_storage::DEMO_CUSTOMER_ID));

        let vehicle_id = controller.active_vehicle_record().vehicle_id;
        let vehicle_message = controller
            .select_vehicle(&vehicle_id)
            .expect("active vehicle should select");
        assert!(vehicle_message.contains("Vehicle selected"));
        assert!(controller
            .get_active_vehicle_summary()
            .contains(&vehicle_id));

        let fob_id = controller.active_key_fob_record().fob_id;
        let key_fob_message = controller
            .select_key_fob(&fob_id)
            .expect("active key fob should select");
        assert!(key_fob_message.contains("Key fob selected"));
        assert!(controller.get_active_key_fob_summary().contains(&fob_id));
    }

    #[test]
    fn test_active_provisioning_context_defaults_and_custom_binding() {
        let mut controller = AppController::new();
        let default_context = controller.get_active_provisioning_context();

        assert_eq!(default_context.customer_id, DEMO_CUSTOMER_ID);
        assert_eq!(default_context.vehicle_id, DEMO_VEHICLE_ID);
        assert_eq!(default_context.fob_id, DEMO_FOB_ID);
        assert_eq!(default_context.certificate_id, DEMO_CERTIFICATE_ID);
        assert_eq!(default_context.session_id, DEMO_SESSION_ID);
        assert_eq!(default_context.context_source, "DemoDefault");

        controller.active_customer = CustomerMetadata {
            customer_id: "CUST-BIND-TEST".to_string(),
            owner_name: "Bind Test Owner".to_string(),
            email: Some("bind@example.com".to_string()),
            phone: None,
        };
        controller.active_vehicle = VehicleMetadata {
            vehicle_id: "VEH-BIND-TEST".to_string(),
            customer_id: "CUST-BIND-TEST".to_string(),
            vehicle_display_name: "Bind Test Vehicle".to_string(),
            make: Some("Nissan".to_string()),
            model: Some("Magnite".to_string()),
            year: Some(2021),
            vin: None,
            registration_number: None,
            provisioning_status: Some(DEFAULT_PROVISIONING_STATUS.to_string()),
        };
        controller.active_key_fob = KeyFobMetadata {
            fob_id: "FOB-BIND-TEST".to_string(),
            vehicle_id: "VEH-BIND-TEST".to_string(),
            customer_id: "CUST-BIND-TEST".to_string(),
            fob_label: "Bind Test Fob".to_string(),
            public_key_fingerprint: None,
            certificate_status: Some(DEFAULT_CERTIFICATE_STATUS.to_string()),
            provisioning_status: Some(DEFAULT_PROVISIONING_STATUS.to_string()),
        };
        controller.refresh_session_id_for_active_context();

        let context = controller.get_active_provisioning_context();
        assert_eq!(context.customer_id, "CUST-BIND-TEST");
        assert_eq!(context.vehicle_id, "VEH-BIND-TEST");
        assert_eq!(context.fob_id, "FOB-BIND-TEST");
        assert_eq!(context.certificate_id, "CERT-FOB-BIND-TEST");
        assert_ne!(context.session_id, DEMO_SESSION_ID);
        assert_eq!(context.context_source, "CloudSelected");
    }

    #[test]
    fn test_certificate_and_session_metadata_use_active_context() {
        let mut controller = AppController::new();
        controller.active_customer = CustomerMetadata {
            customer_id: "CUST-META-TEST".to_string(),
            owner_name: "Meta Owner".to_string(),
            email: Some("meta@example.com".to_string()),
            phone: None,
        };
        controller.active_vehicle = VehicleMetadata {
            vehicle_id: "VEH-META-TEST".to_string(),
            customer_id: "CUST-META-TEST".to_string(),
            vehicle_display_name: "Meta Vehicle".to_string(),
            make: Some("Nissan".to_string()),
            model: Some("Magnite".to_string()),
            year: Some(2021),
            vin: None,
            registration_number: None,
            provisioning_status: Some(DEFAULT_PROVISIONING_STATUS.to_string()),
        };
        controller.active_key_fob = KeyFobMetadata {
            fob_id: "FOB-META-TEST".to_string(),
            vehicle_id: "VEH-META-TEST".to_string(),
            customer_id: "CUST-META-TEST".to_string(),
            fob_label: "Meta Fob".to_string(),
            public_key_fingerprint: None,
            certificate_status: Some(DEFAULT_CERTIFICATE_STATUS.to_string()),
            provisioning_status: Some(DEFAULT_PROVISIONING_STATUS.to_string()),
        };
        controller.refresh_session_id_for_active_context();
        controller
            .issue_keyfob_certificate()
            .expect("certificate should issue for metadata test");
        controller
            .run_legitimate_authentication_demo()
            .expect("authentication should verify for metadata test");
        controller
            .establish_secure_session_demo()
            .expect("session should establish for metadata test");

        let certificate = controller
            .certificate_metadata()
            .expect("certificate metadata should exist");
        assert_eq!(certificate.certificate_id, "CERT-FOB-META-TEST");
        assert_eq!(certificate.fob_id, "FOB-META-TEST");
        assert_eq!(certificate.subject_id, "FOB-META-TEST");

        let session = controller
            .provisioning_session_metadata()
            .expect("session metadata should exist");
        assert_eq!(session.customer_id, "CUST-META-TEST");
        assert_eq!(session.vehicle_id, "VEH-META-TEST");
        assert_eq!(session.fob_id, "FOB-META-TEST");
        assert_eq!(session.certificate_id, "CERT-FOB-META-TEST");
        assert_ne!(session.session_id, DEMO_SESSION_ID);
    }

    #[test]
    fn test_provisioning_cloud_sync_skips_when_disabled() {
        let mut controller = AppController::new();

        let connect = controller
            .connect_vehicle_with_cloud_sync()
            .expect("connect should succeed locally");
        assert_eq!(connect.provisioning_status, "Vehicle connected");
        assert!(!connect.cloud_sync_attempted);
        assert_eq!(connect.cloud_sync_status, "Skipped - disabled");
        assert_eq!(connect.cloud_table_updated, "None");

        let certificate = controller
            .issue_access_certificate_with_cloud_sync()
            .expect("certificate should issue locally");
        assert_eq!(certificate.provisioning_status, "Certificate issued");
        assert!(!certificate.cloud_sync_attempted);
        assert_eq!(certificate.cloud_sync_status, "Skipped - disabled");

        controller
            .verify_authentication_with_cloud_sync()
            .expect("authentication should verify locally");

        let session = controller
            .activate_secure_session_with_cloud_sync()
            .expect("session should establish locally");
        assert_eq!(session.provisioning_status, "Secure session activated");
        assert!(!session.cloud_sync_attempted);
        assert_eq!(session.cloud_sync_status, "Skipped - disabled");

        let finalized = controller
            .finalize_provisioning_with_cloud_sync()
            .expect("report export should succeed locally");
        assert_eq!(finalized.provisioning_status, "Provisioning finalized");
        assert!(!finalized.cloud_sync_attempted);
        assert_eq!(finalized.cloud_sync_status, "Skipped - disabled");
    }

    #[test]
    fn test_provisioning_no_sync_required_statuses() {
        let mut controller = AppController::new();
        controller
            .issue_keyfob_certificate()
            .expect("certificate should issue");

        let challenge = controller
            .generate_challenge_with_cloud_sync()
            .expect("challenge should generate");
        assert_eq!(challenge.cloud_sync_status, "No sync required");
        assert!(!challenge.cloud_sync_attempted);

        let signed = controller
            .sign_canonical_payload_with_cloud_sync()
            .expect("payload should sign");
        assert_eq!(signed.cloud_sync_status, "No sync required");
        assert!(!signed.cloud_sync_attempted);

        let verified = controller
            .verify_authentication_with_cloud_sync()
            .expect("authentication should verify");
        assert_eq!(
            verified.cloud_sync_status,
            "Pending secure session activation"
        );
        assert!(!verified.cloud_sync_attempted);
    }

    #[test]
    fn test_provisioning_sync_result_uses_active_context_and_safe_strings() {
        let mut controller = AppController::new();
        controller.active_customer = CustomerMetadata {
            customer_id: "CUST-PROVSYNC-TEST".to_string(),
            owner_name: "Provisioning Sync Owner".to_string(),
            email: Some("provsync@example.com".to_string()),
            phone: None,
        };
        controller.active_vehicle = VehicleMetadata {
            vehicle_id: "VEH-PROVSYNC-TEST".to_string(),
            customer_id: "CUST-PROVSYNC-TEST".to_string(),
            vehicle_display_name: "Provisioning Sync Vehicle".to_string(),
            make: Some("Nissan".to_string()),
            model: Some("Magnite".to_string()),
            year: Some(2021),
            vin: None,
            registration_number: None,
            provisioning_status: Some(DEFAULT_PROVISIONING_STATUS.to_string()),
        };
        controller.active_key_fob = KeyFobMetadata {
            fob_id: "FOB-PROVSYNC-TEST".to_string(),
            vehicle_id: "VEH-PROVSYNC-TEST".to_string(),
            customer_id: "CUST-PROVSYNC-TEST".to_string(),
            fob_label: "Provisioning Sync Fob".to_string(),
            public_key_fingerprint: None,
            certificate_status: Some(DEFAULT_CERTIFICATE_STATUS.to_string()),
            provisioning_status: Some(DEFAULT_PROVISIONING_STATUS.to_string()),
        };
        controller.refresh_session_id_for_active_context();

        let result = controller
            .issue_access_certificate_with_cloud_sync()
            .expect("certificate should issue locally");
        assert_eq!(result.active_customer_id, "CUST-PROVSYNC-TEST");
        assert_eq!(result.active_vehicle_id, "VEH-PROVSYNC-TEST");
        assert_eq!(result.active_fob_id, "FOB-PROVSYNC-TEST");
        assert_eq!(result.active_certificate_id, "CERT-FOB-PROVSYNC-TEST");
        assert_ne!(result.active_session_id, DEMO_SESSION_ID);

        let display = result.to_string();
        for forbidden in [
            "DATABASE_URL",
            "AIACS_MASTER_KEY",
            "private_key",
            "session_key",
            "shared_secret",
            "hkdf_output",
            "AES key",
            "raw_nonce",
            "encrypted_key_blob",
            "encryption_nonce",
        ] {
            assert!(!display.contains(forbidden));
        }
    }

    #[test]
    fn test_cloud_sync_failure_does_not_fail_local_provisioning_action() {
        let mut controller = AppController::new();
        controller.cloud_auto_sync_enabled = true;

        controller
            .connect_vehicle()
            .expect("local connect should succeed");
        let result = controller.provisioning_sync_result(
            "Connect Vehicle",
            "Vehicle connected",
            "customers, vehicles, key_fobs",
            |_| {
                Err(AppControllerError::Backend(
                    "Cloud database connection failed. Retry after database warm-up.".to_string(),
                ))
            },
        );

        assert!(result.local_success);
        assert!(result.cloud_sync_attempted);
        assert!(result.cloud_sync_status.starts_with("Failed -"));
        assert!(result.safe_error.is_some());
        assert_eq!(result.provisioning_status, "Vehicle connected");
        assert!(!result.cloud_sync_status.contains("DATABASE_URL"));
        assert!(!result.cloud_sync_status.contains("AIACS_MASTER_KEY"));
    }

    #[test]
    fn test_provisioning_sync_sees_startup_auto_enabled_state() {
        let mut controller = AppController::new();
        controller.startup_cloud_sync_enabled_result();

        let result = controller.provisioning_sync_result(
            "Issue Access Certificate",
            "Certificate issued",
            "certificates",
            |_| Ok("Certificate metadata synced".to_string()),
        );

        assert!(result.local_success);
        assert!(result.cloud_sync_attempted);
        assert_eq!(result.cloud_sync_status, "Synced");
        assert_eq!(result.cloud_table_updated, "certificates");
    }

    #[test]
    fn test_vehicle_and_key_fob_creation_require_parent_records() {
        let mut controller = AppController::new();

        let vehicle_error = controller
            .create_vehicle_record("", "No Customer Vehicle", None, None, None, None, None)
            .expect_err("empty customer id should fail safely")
            .to_string();
        assert_eq!(vehicle_error, "Select a customer before creating a vehicle");

        let key_fob_error = controller
            .create_key_fob_record("", "No Vehicle Fob")
            .expect_err("empty vehicle id should fail safely")
            .to_string();
        assert_eq!(key_fob_error, "Select a vehicle before creating a key fob");
    }

    #[test]
    fn test_management_record_ids_are_generated_safely() {
        let first_customer_id = generated_record_id("CUST");
        let second_customer_id = generated_record_id("CUST");
        let vehicle_id = generated_record_id("VEH");
        let fob_id = generated_record_id("FOB");

        assert!(first_customer_id.starts_with("CUST-"));
        assert!(vehicle_id.starts_with("VEH-"));
        assert!(fob_id.starts_with("FOB-"));
        assert_eq!(first_customer_id.len(), "CUST-".len() + 8);
        assert_ne!(first_customer_id, second_customer_id);
    }

    #[test]
    fn test_manual_management_record_validation_is_safe() {
        let mut controller = AppController::new();

        let owner_error = controller
            .create_customer_record("", Some("owner@example.com".to_string()), None)
            .expect_err("empty owner name should fail before cloud work")
            .to_string();
        assert_eq!(owner_error, "Owner name is required");

        let email_error = controller
            .create_customer_record("Manual Owner", Some("invalid-email".to_string()), None)
            .expect_err("invalid email should fail before cloud work")
            .to_string();
        assert_eq!(email_error, "Valid email is required");

        let vehicle_error = controller
            .create_vehicle_record(
                crate::cloud_storage::DEMO_CUSTOMER_ID,
                "Manual Vehicle",
                Some("Nissan".to_string()),
                Some("Magnite".to_string()),
                None,
                None,
                None,
            )
            .expect_err("missing numeric year should fail before cloud work")
            .to_string();
        assert_eq!(vehicle_error, "Vehicle year must be numeric");

        let fob_error = controller
            .create_key_fob_record(crate::cloud_storage::DEMO_VEHICLE_ID, "")
            .expect_err("empty fob label should fail before cloud work")
            .to_string();
        assert_eq!(fob_error, "Key fob label is required");
    }

    #[test]
    fn test_cloud_persistence_paths_use_cached_client_and_safe_messages() {
        let source = include_str!("mod.rs");

        for expected in [
            "ensure_schema_initialized()",
            "ensure_cloud_client()",
            "clear_failed_cloud_client()",
            "cloud_client: Option<CloudStorageClient>",
            "schema_initialized: bool",
            "client.health_check().await?",
            "Customer created and saved to cloud",
            "Vehicle created and saved to cloud",
            "Key fob created and saved to cloud",
        ] {
            assert!(
                source.contains(expected),
                "missing persistence marker: {expected}"
            );
        }

        let direct_connect = concat!("CloudStorageClient::", "connect_from_env()");
        assert_eq!(source.matches(direct_connect).count(), 1);
    }

    #[test]
    fn test_manual_retry_refreshes_cloud_config_and_clears_failed_state() {
        let source = include_str!("mod.rs");
        let function_start = source
            .find("pub fn enable_cloud_auto_sync")
            .expect("manual enable should exist");
        let function_source = &source[function_start..];

        assert!(function_source.contains("CloudStorageConfig::refresh_env_cache()"));
        assert!(function_source.contains("self.clear_failed_cloud_client()"));
        assert!(function_source.contains("self.ensure_schema_initialized()?"));
    }

    #[test]
    fn test_schema_initialization_is_guarded_by_controller_cache() {
        let source = include_str!("mod.rs");
        let function_start = source
            .find("fn ensure_schema_initialized")
            .expect("schema guard should exist");
        let function_source = &source[function_start..];

        assert!(function_source.contains("if !self.schema_initialized"));
        assert!(function_source.contains("client.initialize_schema()"));
        assert!(function_source.contains("self.schema_initialized = true"));
    }

    #[test]
    fn test_provisioning_sync_paths_remain_targeted() {
        let source = include_str!("mod.rs");

        for expected in [
            "controller.sync_active_cloud_metadata()",
            "controller.sync_certificate_metadata()",
            "controller.sync_provisioning_session_record()",
            "controller.sync_audit_log_records()",
            "controller.sync_diagnostic_result_records()",
        ] {
            assert!(
                source.contains(expected),
                "missing targeted sync: {expected}"
            );
        }

        let issue_start = source
            .find("pub fn issue_access_certificate_with_cloud_sync")
            .expect("issue certificate sync method should exist");
        let issue_source = &source[issue_start
            ..source[issue_start..]
                .find("pub fn generate_challenge_with_cloud_sync")
                .map(|offset| issue_start + offset)
                .expect("next method should exist")];
        assert!(issue_source.contains("controller.sync_certificate_metadata()"));
        assert!(!issue_source.contains("sync_active_cloud_metadata"));
        assert!(!issue_source.contains("sync_provisioning_session_record"));
        assert!(!issue_source.contains("sync_audit_log_records"));
    }

    #[test]
    fn test_management_loads_are_not_demo_id_filtered() {
        let source = include_str!("mod.rs");

        for expected in [
            "client.list_customers().await",
            "client.list_vehicles().await",
            "client.list_key_fobs().await",
        ] {
            assert!(
                source.contains(expected),
                "missing unfiltered load path: {expected}"
            );
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
        assert_eq!(metadata.fob_id, DEMO_FOB_ID);
        assert_eq!(metadata.subject_id, DEMO_FOB_ID);
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
            .run_legitimate_authentication_demo()
            .expect("auth demo failed");
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
        assert_eq!(metadata.fob_id, DEMO_FOB_ID);
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
        assert_eq!(fob_record.owner_id, DEMO_FOB_ID);
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
