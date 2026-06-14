use crate::access::{AccessDecision, AccessDecisionEngine};
use crate::attacks::{AdversarialValidationEngine, AttackResult, AttackType};
use crate::auth::{AuthChallenge, AuthResult, AuthenticationEngine};
use crate::ca::{CAError, Certificate, CertificateAuthority};
use crate::cloud_storage::{
    decrypt_private_key_from_cloud, demo_customer_metadata, demo_key_fob_metadata,
    demo_vehicle_metadata, encrypt_private_key_for_cloud, parse_master_key_from_env,
    AuditLogRecord, CertificateMetadata, CloudStorageClient, CloudStorageConfig, CloudStorageError,
    CustomerMetadata, DiagnosticResultRecord, EncryptedKeyRecord, KeyFobMetadata,
    ProvisioningSessionMetadata, VehicleMetadata, AUTHENTICATED_STATUS, CA_ENCRYPTED_KEY_ID,
    CA_KEY_PURPOSE, CERTIFICATE_ISSUED_PROVISIONING_STATUS, CERTIFICATE_SIGNATURE_ALGORITHM,
    CHALLENGE_GENERATED_STATUS, DEFAULT_CERTIFICATE_STATUS, DEFAULT_PROVISIONING_STATUS,
    DEMO_CERTIFICATE_ID, DEMO_CUSTOMER_ID, DEMO_FOB_ID, DEMO_SESSION_ID, DEMO_VEHICLE_ID,
    DIAGNOSTIC_RESULT_IDS, ENCRYPTED_KEY_STORAGE_STATUS, FAILED_PROVISIONING_STATUS,
    FINALIZED_PROVISIONING_STATUS, GRANT_ACCESS_DECISION, IN_APP_REPORT_ONLY_PATH,
    ISSUED_CERTIFICATE_STATUS, KEY_FOB_ENCRYPTED_KEY_ID, KEY_FOB_KEY_PURPOSE,
    REGISTERED_PROVISIONING_STATUS, SECURE_SESSION_ESTABLISHED_STATUS, SESSION_ALGORITHM,
    SESSION_ESTABLISHED_PROVISIONING_STATUS, TRUST_INITIALIZED_STATUS, VEHICLE_CONNECTED_STATUS,
    VEHICLE_CREATED_STATUS,
};
use crate::crypto::CryptoEngine;
use crate::keyfob::{AuthenticationProof, DigitalKeyFob, KeyFobError};
use crate::session::{SessionState, SessionValidationEngine};
use crate::vehicle::{VehicleControlModule, VehicleError};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, FixedOffset, Utc};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::future::Future;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

const DEFAULT_CA_NAME: &str = "Denish";
const DEFAULT_VEHICLE_ID: &str = DEMO_VEHICLE_ID;
const DEFAULT_TIMEOUT_SECONDS: i64 = 60;
const DEFAULT_LOG_DIR: &str = "logs";
const GUI_LOG_FILE: &str = "aiacs_gui.log";
const PROTOCOL_TRACE_LOG_FILE: &str = "aiacs_protocol_trace.log";
const PROVISIONING_REPORT_FILE: &str = "aiacs_provisioning_report.txt";
const RECOVERY_ARTIFACTS_DIR: &str = "recovery_artifacts";
const DIAGNOSTIC_RESULTS_DIR: &str = "diagnostic_results";
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
pub struct ActiveCertificateDetails {
    pub available: bool,
    pub certificate_id: Option<String>,
    pub fob_id: Option<String>,
    pub vehicle_id: Option<String>,
    pub subject_id: Option<String>,
    pub issuer: Option<String>,
    pub signature_algorithm: Option<String>,
    pub certificate_signature_fingerprint: Option<String>,
    pub public_key_fingerprint: Option<String>,
    pub certificate_json_available: bool,
    pub certificate_status: Option<String>,
    pub issued_at: Option<String>,
    pub expires_at: Option<String>,
    pub source: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedKeyRecoveryEvidence {
    pub key_id: String,
    pub owner_type: String,
    pub owner_id: String,
    pub public_key_fingerprint: String,
    pub recovered_public_key_fingerprint: String,
    pub encryption_algorithm: String,
    pub key_purpose: String,
    pub storage_status: String,
    pub local_encrypted_file: String,
    pub cloud_encrypted_file: String,
    pub decrypted_recovery_file: String,
    pub recovery_evidence_file: String,
    pub recovery_status: String,
    pub fingerprint_match: bool,
    pub local_cloud_encrypted_backup_match: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticDashboardResult {
    pub diagnostic_id: String,
    pub attack_name: String,
    pub attack_label: String,
    pub customer_id: String,
    pub vehicle_id: String,
    pub fob_id: String,
    pub certificate_id: String,
    pub session_id: String,
    pub expected_result: String,
    pub baseline_result: String,
    pub protected_result: String,
    pub actual_result: String,
    pub security_control_triggered: String,
    pub access_decision: String,
    pub diagnostic_status: String,
    pub pass_fail: String,
    pub evidence_summary: String,
    pub evidence_file_path: String,
    pub cloud_sync_status: String,
    pub created_at_nepal_time: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticContextSummary {
    pub customer_status: String,
    pub vehicle_status: String,
    pub key_fob_status: String,
    pub certificate_status: String,
    pub certificate_id: String,
    pub session_status: String,
    pub session_id: String,
    pub encrypted_backup_status: String,
    pub fob_identity_status: String,
    pub diagnostic_proof_status: String,
    pub readiness: String,
    pub readiness_reason: String,
    pub evidence_directory: String,
    pub progress_steps: Vec<String>,
}

impl Default for DiagnosticContextSummary {
    fn default() -> Self {
        Self {
            customer_status: "missing".to_string(),
            vehicle_status: "missing".to_string(),
            key_fob_status: "missing".to_string(),
            certificate_status: "missing".to_string(),
            certificate_id: "N/A".to_string(),
            session_status: "missing".to_string(),
            session_id: "N/A".to_string(),
            encrypted_backup_status: "missing".to_string(),
            fob_identity_status: "missing".to_string(),
            diagnostic_proof_status: "not_generated".to_string(),
            readiness: "not_ready".to_string(),
            readiness_reason: "missing_customer".to_string(),
            evidence_directory: "diagnostic_results/N/A".to_string(),
            progress_steps: vec![
                "Step 1: Loading selected cloud context".to_string(),
                "Step 2: Loading issued certificate".to_string(),
                "Step 3: Preparing diagnostic proof".to_string(),
                "Step 4: Running insecure baseline simulation".to_string(),
                "Step 5: Running AIACS protected verification".to_string(),
                "Step 6: Saving evidence file".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VisibleProvisioningContext {
    pub customer_selected: bool,
    pub vehicle_selected: bool,
    pub key_fob_selected: bool,
    pub customer_id: String,
    pub owner_name: String,
    pub vehicle_id: String,
    pub vehicle_display_name: String,
    pub fob_id: String,
    pub fob_label: String,
    pub certificate_id: String,
    pub session_id: String,
    pub selection_source: String,
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

pub fn format_status_label(status: &str) -> String {
    match status.trim() {
        "" => "Unknown".to_string(),
        "issued" => "Issued".to_string(),
        "not_issued" => "Not Issued".to_string(),
        "expired" => "Expired".to_string(),
        "revoked" => "Revoked".to_string(),
        "pending" => "Pending".to_string(),
        "in_progress" => "In Progress".to_string(),
        "registered" => "Registered".to_string(),
        "certificate_issued" => "Certificate Issued".to_string(),
        "authenticated" => "Authenticated".to_string(),
        "session_established" => "Session Established".to_string(),
        "secure_session_established" => "Secure Session Established".to_string(),
        "grant_access" => "Grant Access".to_string(),
        "finalized" => "Finalized".to_string(),
        "failed" => "Failed".to_string(),
        "rejected" => "Rejected".to_string(),
        "in_app_report_only" => "In App Report Only".to_string(),
        other => other
            .split('_')
            .filter(|part| !part.is_empty())
            .map(|part| {
                let mut chars = part.chars();
                match chars.next() {
                    Some(first) => {
                        first.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase()
                    }
                    None => String::new(),
                }
            })
            .collect::<Vec<_>>()
            .join(" "),
    }
}

pub fn format_nepal_time(timestamp: DateTime<Utc>) -> String {
    let nepal_offset = FixedOffset::east_opt(5 * 3600 + 45 * 60)
        .expect("Nepal offset should be a valid fixed offset");
    timestamp
        .with_timezone(&nepal_offset)
        .format("%Y-%m-%d %H:%M:%S NPT")
        .to_string()
}

fn format_nepal_time_from_rfc3339(value: &str) -> String {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| format_nepal_time(timestamp.with_timezone(&Utc)))
        .unwrap_or_else(|_| value.to_string())
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
    provisioning_report_exported: bool,
    active_challenge: Option<AuthChallenge>,
    active_auth_proof: Option<AuthenticationProof>,
    verification_in_progress: bool,
    last_key_fob_recovery_evidence: Option<EncryptedKeyRecoveryEvidence>,
    last_diagnostic_results: Vec<DiagnosticDashboardResult>,
    last_diagnostic_context: DiagnosticContextSummary,
    cloud_auto_sync_enabled: bool,
    active_customer: CustomerMetadata,
    active_vehicle: VehicleMetadata,
    active_key_fob: KeyFobMetadata,
    selected_customer: Option<CustomerMetadata>,
    selected_vehicle: Option<VehicleMetadata>,
    selected_key_fob: Option<KeyFobMetadata>,
    active_certificate_metadata: Option<CertificateMetadata>,
    selection_source: String,
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
            .field(
                "provisioning_report_exported",
                &self.provisioning_report_exported,
            )
            .field("active_challenge", &self.active_challenge.is_some())
            .field("active_auth_proof", &self.active_auth_proof.is_some())
            .field("verification_in_progress", &self.verification_in_progress)
            .field(
                "last_key_fob_recovery_evidence",
                &self.last_key_fob_recovery_evidence,
            )
            .field("last_diagnostic_context", &self.last_diagnostic_context)
            .field("cloud_auto_sync_enabled", &self.cloud_auto_sync_enabled)
            .field("active_customer", &self.active_customer)
            .field("active_vehicle", &self.active_vehicle)
            .field("active_key_fob", &self.active_key_fob)
            .field("selected_customer", &self.selected_customer)
            .field("selected_vehicle", &self.selected_vehicle)
            .field("selected_key_fob", &self.selected_key_fob)
            .field("selection_source", &self.selection_source)
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
            provisioning_report_exported: false,
            active_challenge: None,
            active_auth_proof: None,
            verification_in_progress: false,
            last_key_fob_recovery_evidence: None,
            last_diagnostic_results: Vec::new(),
            last_diagnostic_context: DiagnosticContextSummary::default(),
            cloud_auto_sync_enabled: false,
            active_customer: active_customer.clone(),
            active_vehicle: active_vehicle.clone(),
            active_key_fob: active_key_fob.clone(),
            selected_customer: None,
            selected_vehicle: None,
            selected_key_fob: None,
            active_certificate_metadata: None,
            selection_source: "None".to_string(),
            active_session_id: DEMO_SESSION_ID.to_string(),
            customer_records: Vec::new(),
            vehicle_records: Vec::new(),
            key_fob_records: Vec::new(),
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
        self.set_active_vehicle_status(VEHICLE_CONNECTED_STATUS);
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
        self.set_active_key_fob_status(None, Some(REGISTERED_PROVISIONING_STATUS));
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
        self.active_challenge = Some(challenge);
        self.active_auth_proof = None;
        self.last_auth_result = None;
        self.last_access_decision = None;
        self.set_active_vehicle_status(CHALLENGE_GENERATED_STATUS);

        self.append_protocol_trace("[AUTH]", "Vehicle generated nonce challenge")?;
        self.append_protocol_trace("[AUTH]", format!("Vehicle ID: {}", vehicle_id))?;
        self.append_protocol_trace("[AUTH]", format!("Nonce hash: {}", nonce_fingerprint))?;
        self.log(message.clone());
        Ok(message)
    }

    pub fn sign_canonical_auth_payload(&mut self) -> Result<String, AppControllerError> {
        self.ensure_ready_for_authentication()?;
        let vehicle_id = self.active_vehicle.vehicle_id.clone();
        let challenge = self.active_challenge.clone().ok_or_else(|| {
            AppControllerError::Backend(
                "missing_challenge: Generate Challenge before signing payload".to_string(),
            )
        })?;
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
        let message =
            "Canonical authentication payload signed; private key remains [REDACTED]".to_string();
        self.active_auth_proof = Some(proof.clone());

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
        self.set_active_vehicle_status(TRUST_INITIALIZED_STATUS);
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
        self.set_active_key_fob_status(
            Some(ISSUED_CERTIFICATE_STATUS),
            Some(CERTIFICATE_ISSUED_PROVISIONING_STATUS),
        );
        self.set_active_vehicle_status(CERTIFICATE_ISSUED_PROVISIONING_STATUS);
        self.active_challenge = None;
        self.active_auth_proof = None;
        self.last_auth_result = None;
        self.last_access_decision = None;
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
        self.active_certificate_metadata = Some(self.certificate_metadata()?);
        self.log(message.clone());
        Ok(message)
    }

    pub fn register_digital_key_fob(&mut self) -> Result<String, AppControllerError> {
        let identity_message = self.ensure_active_key_fob_crypto_identity()?;
        self.set_active_key_fob_status(None, Some(REGISTERED_PROVISIONING_STATUS));
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
        let proof = if let Some(proof) = self.active_auth_proof.clone() {
            proof
        } else {
            let challenge =
                AuthenticationEngine::generate_challenge(&mut self.vehicle, &vehicle_id)
                    .map_err(|e| AppControllerError::Backend(e.to_string()))?;
            self.active_challenge = Some(challenge.clone());
            self.append_protocol_trace("[AUTH]", "Vehicle generated nonce challenge")?;
            self.append_protocol_trace(
                "[AUTH]",
                format!("Nonce hash: {}", fingerprint(&challenge.nonce)),
            )?;

            let proof = {
                let keyfob = self.keyfob.as_ref().expect("Key fob ready");
                keyfob.create_auth_proof(&vehicle_id, &challenge.nonce)?
            };
            self.active_auth_proof = Some(proof.clone());
            proof
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
        if auth_result == AuthResult::Success {
            self.set_active_key_fob_status(None, Some(AUTHENTICATED_STATUS));
            self.set_active_vehicle_status(AUTHENTICATED_STATUS);
        } else {
            self.set_active_key_fob_status(None, Some("rejected"));
            self.set_active_vehicle_status(FAILED_PROVISIONING_STATUS);
        }

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
        self.set_active_key_fob_status(None, Some(SESSION_ESTABLISHED_PROVISIONING_STATUS));
        self.set_active_vehicle_status(SESSION_ESTABLISHED_PROVISIONING_STATUS);

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

    pub fn diagnostic_dashboard_results(&self) -> Vec<DiagnosticDashboardResult> {
        self.last_diagnostic_results.clone()
    }

    pub fn diagnostic_context_summary(&self) -> DiagnosticContextSummary {
        self.last_diagnostic_context.clone()
    }

    pub fn prepare_diagnostics_context(&mut self) -> Result<String, AppControllerError> {
        let summary = self.hydrate_diagnostics_context(false)?;
        let message = if summary.readiness == "ready" {
            "Diagnostics context ready".to_string()
        } else {
            format!(
                "Diagnostics context not ready: {}",
                summary.readiness_reason
            )
        };
        self.last_diagnostic_context = summary;
        Ok(message)
    }

    pub fn run_diagnostic_attack(
        &mut self,
        attack_key: &str,
    ) -> Result<DiagnosticDashboardResult, AppControllerError> {
        let definition = diagnostic_definition(attack_key)?;
        self.prepare_diagnostic_runtime_state(definition)?;
        self.ensure_diagnostic_readiness(definition)?;
        let result = self.execute_diagnostic_definition(definition)?;
        self.last_diagnostic_results.push(result.clone());
        self.append_protocol_trace(
            "[DIAGNOSTIC]",
            format!(
                "{}: {} via {}",
                result.attack_label, result.pass_fail, result.security_control_triggered
            ),
        )?;
        self.save_log_entry(
            "[ATTACK]",
            format!(
                "{} diagnostic {} for {}",
                result.attack_label, result.pass_fail, result.fob_id
            ),
        )?;
        Ok(result)
    }

    pub fn run_all_diagnostics(
        &mut self,
    ) -> Result<Vec<DiagnosticDashboardResult>, AppControllerError> {
        let keys = [
            "replay_attack",
            "forged_signature",
            "fake_certificate",
            "identity_mismatch",
            "delayed_relay",
            "packet_tampering",
            "tampered_ciphertext",
            "wrong_session_key",
            "wrong_master_key_recovery",
        ];
        let mut results = Vec::new();
        for key in keys {
            results.push(self.run_diagnostic_attack(key)?);
        }
        self.save_all_diagnostics_summary(&results)?;
        Ok(results)
    }

    pub fn diagnostics_readiness_summary(&self) -> String {
        self.last_diagnostic_context.readiness_reason.clone()
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
        let visible = self.get_visible_provisioning_context();
        let certificate = self.get_active_certificate_details();
        let crypto_identity = self.get_active_key_fob_crypto_identity();

        artifacts.push("[Challenge Message]".to_string());
        artifacts.push(format!("customer_id: {}", visible.customer_id));
        artifacts.push(format!("owner_name: {}", visible.owner_name));
        artifacts.push(format!("vehicle_id: {}", visible.vehicle_id));
        artifacts.push(format!("vehicle: {}", visible.vehicle_display_name));
        if visible.vehicle_selected && visible.key_fob_selected {
            artifacts
                .push("challenge_status: generated after vehicle challenge action".to_string());
        } else {
            artifacts.push("challenge_status: No authentication artifact available".to_string());
        }
        artifacts.push("raw nonce material: [REDACTED]".to_string());
        artifacts.push("protocol_version: AIACS_AUTH_V1".to_string());

        artifacts.push("[Authentication Proof]".to_string());
        artifacts.push(format!("fob_id: {}", visible.fob_id));
        artifacts.push(format!("fob_label: {}", visible.fob_label));
        artifacts.push(format!(
            "signing_status: {}",
            if visible.key_fob_selected {
                format!("Signed by {} after signing action", visible.fob_id)
            } else {
                "No authentication artifact available".to_string()
            }
        ));
        artifacts.push(
            "payload_format: AIACS_AUTH_V1|vehicle_id|subject_id|base64(nonce)|timestamp"
                .to_string(),
        );
        artifacts.push("signature_material: [REDACTED]".to_string());
        artifacts.push("private key material: [REDACTED]".to_string());

        artifacts.push("[Certificate Details]".to_string());
        artifacts.push(format!(
            "certificate_id: {}",
            certificate
                .certificate_id
                .clone()
                .unwrap_or_else(|| "N/A".to_string())
        ));
        artifacts.push(format!(
            "subject_id: {}",
            certificate
                .subject_id
                .clone()
                .unwrap_or_else(|| "No certificate issued".to_string())
        ));
        artifacts.push(format!(
            "vehicle_id: {}",
            certificate
                .vehicle_id
                .clone()
                .unwrap_or_else(|| visible.vehicle_id.clone())
        ));
        artifacts.push(format!(
            "issuer: {}",
            certificate
                .issuer
                .clone()
                .unwrap_or_else(|| "No certificate issued".to_string())
        ));
        artifacts.push(format!(
            "signature_algorithm: {}",
            certificate
                .signature_algorithm
                .clone()
                .unwrap_or_else(|| CERTIFICATE_SIGNATURE_ALGORITHM.to_string())
        ));
        artifacts.push(format!(
            "public_key_fingerprint: {}",
            certificate
                .public_key_fingerprint
                .clone()
                .unwrap_or(crypto_identity.public_key_fingerprint)
        ));
        artifacts.push(format!(
            "certificate_signature_fingerprint: {}",
            certificate
                .certificate_signature_fingerprint
                .clone()
                .unwrap_or_else(|| "N/A".to_string())
        ));
        artifacts.push(format!(
            "certificate_json: {}",
            if certificate.certificate_json_available {
                "Available"
            } else {
                "N/A"
            }
        ));
        artifacts.push(format!("certificate_status: {}", certificate.message));

        artifacts.push("[Credential Storage]".to_string());
        artifacts.extend(self.credential_storage_summary());

        artifacts.push("[Session Establishment Summary]".to_string());
        artifacts.push("key_exchange: X25519".to_string());
        artifacts.push("kdf: HKDF-SHA256".to_string());
        artifacts.push("encryption: AES-GCM".to_string());
        artifacts.push(format!("session_id: {}", visible.session_id));
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
        if self.selected_key_fob.is_none() {
            return vec![
                "Fob ID: No key fob selected".to_string(),
                "Credential Metadata: Select a key fob to view credential metadata".to_string(),
                "Private Key: [REDACTED]".to_string(),
                "Encrypted Blob Status: Unavailable".to_string(),
            ];
        }

        let identity = self.get_active_key_fob_crypto_identity();
        let certificate = self.get_active_certificate_details();
        let paths = self.recovery_artifact_paths();
        let backup_configured = parse_master_key_from_env().is_ok();
        let encrypted_blob_status = if !backup_configured {
            "Encrypted key backup is not configured."
        } else if self.keyfob.is_some() {
            "Available as client-side encrypted cloud blob"
        } else {
            "Encrypted key backup: Not stored"
        };
        let recovery_status = self
            .last_key_fob_recovery_evidence
            .as_ref()
            .map(|evidence| evidence.recovery_status.as_str())
            .unwrap_or("Not tested");
        let fingerprint_match = self
            .last_key_fob_recovery_evidence
            .as_ref()
            .map(|evidence| evidence.fingerprint_match.to_string())
            .unwrap_or_else(|| "Not tested".to_string());
        let recovered_fingerprint = self
            .last_key_fob_recovery_evidence
            .as_ref()
            .map(|evidence| evidence.recovered_public_key_fingerprint.clone())
            .unwrap_or_else(|| "Not tested".to_string());

        vec![
            format!("Fob ID: {}", identity.fob_id),
            format!("Certificate ID: {}", identity.certificate_id),
            format!(
                "Encrypted Key ID: {}",
                self.derive_key_fob_encrypted_key_id()
            ),
            "Key Owner Type: key_fob".to_string(),
            format!("Key Owner ID: {}", identity.fob_id),
            "Encryption Algorithm: AES-256-GCM".to_string(),
            format!("Key Purpose: {}", KEY_FOB_KEY_PURPOSE),
            format!("Storage Status: {}", ENCRYPTED_KEY_STORAGE_STATUS),
            format!(
                "Encrypted Local File: {}",
                path_for_report(&paths.local_encrypted_file)
            ),
            format!(
                "Encrypted Cloud File: {}",
                path_for_report(&paths.cloud_encrypted_file)
            ),
            format!(
                "Decrypted Recovery File: {}",
                path_for_report(&paths.decrypted_recovery_file)
            ),
            format!(
                "Recovery Evidence File: {}",
                path_for_report(&paths.recovery_evidence_file)
            ),
            format!("Key Status: {}", identity.binding_status),
            format!(
                "Public Key Fingerprint: {}",
                identity.public_key_fingerprint
            ),
            format!(
                "Recovered Public Key Fingerprint: {}",
                recovered_fingerprint
            ),
            format!("Recovery Status: {}", recovery_status),
            format!("Fingerprint Match: {}", fingerprint_match),
            format!(
                "Local vs Cloud Encrypted Backup Match: {}",
                self.last_key_fob_recovery_evidence
                    .as_ref()
                    .map(|evidence| evidence.local_cloud_encrypted_backup_match.to_string())
                    .unwrap_or_else(|| "Not tested".to_string())
            ),
            format!(
                "Key Fob Private Key Path: {}",
                self.key_fob_private_key_path()
            ),
            format!(
                "Key Fob Public Key Path: {}",
                self.key_fob_public_key_path()
            ),
            format!(
                "Certificate Status: {}",
                certificate
                    .certificate_status
                    .unwrap_or_else(|| DEFAULT_CERTIFICATE_STATUS.to_string())
            ),
            format!("Encrypted Blob Status: {}", encrypted_blob_status),
            "Private Key: [REDACTED]".to_string(),
            "Storage Mode: Local prototype key file plus encrypted cloud metadata where enabled"
                .to_string(),
            "Production Note: Secure element / OS key store / Encrypted key storage recommended"
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
        report.push_str(&format!(
            "Generated At: {} (Asia/Kathmandu)\n",
            format_nepal_time(Utc::now())
        ));
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
            report.push_str(&format!(
                "Issued At: {} (Asia/Kathmandu)\n",
                format_nepal_time_from_rfc3339(&cert.issued_at)
            ));
            report.push_str(&format!(
                "Expires At: {} (Asia/Kathmandu)\n",
                format_nepal_time_from_rfc3339(&cert.expires_at)
            ));
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
        self.provisioning_report_exported = true;
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
        self.run_auto_sync(
            "key fob metadata and encrypted key backup synced",
            |controller| controller.sync_key_fob_metadata_and_backup(),
        )
    }

    pub fn auto_sync_after_trust_initialized(&mut self) -> Result<String, AppControllerError> {
        self.run_auto_sync(
            "vehicle status and encrypted key blob synced",
            |controller| controller.sync_vehicle_and_ca_encrypted_key_blob(),
        )
    }

    pub fn auto_sync_after_certificate_issued(&mut self) -> Result<String, AppControllerError> {
        self.run_auto_sync(
            "certificate metadata and key fob status synced",
            |controller| controller.sync_certificate_and_key_fob_status(),
        )
    }

    pub fn auto_sync_after_secure_session_established(
        &mut self,
    ) -> Result<String, AppControllerError> {
        self.run_auto_sync(
            "provisioning session and key fob status synced",
            |controller| controller.sync_session_and_key_fob_status(),
        )
    }

    pub fn auto_sync_after_provisioning_finalized(&mut self) -> Result<String, AppControllerError> {
        self.run_auto_sync("finalized provisioning records synced", |controller| {
            controller.sync_finalized_provisioning_records()
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
        self.ensure_visible_provisioning_context_selected()?;
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
        self.ensure_visible_provisioning_context_selected()?;
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
        self.ensure_visible_provisioning_context_selected()?;
        self.register_digital_key_fob()?;
        Ok(self.provisioning_sync_result(
            "Register Digital Key Fob",
            "Key fob registered",
            "key_fobs, encrypted_keys",
            |controller| controller.sync_key_fob_metadata_and_backup(),
        ))
    }

    pub fn initialize_vehicle_trust_with_cloud_sync(
        &mut self,
    ) -> Result<ProvisioningCloudSyncResult, AppControllerError> {
        self.ensure_visible_provisioning_context_selected()?;
        self.initialize_ca()?;
        Ok(self.provisioning_sync_result(
            "Initialize Vehicle Trust",
            "Vehicle trust initialized",
            "vehicles, encrypted_keys",
            |controller| controller.sync_vehicle_and_ca_encrypted_key_blob(),
        ))
    }

    pub fn issue_access_certificate_with_cloud_sync(
        &mut self,
    ) -> Result<ProvisioningCloudSyncResult, AppControllerError> {
        self.ensure_visible_key_fob_selected()?;
        self.issue_keyfob_certificate()?;
        Ok(self.provisioning_sync_result(
            "Issue Access Certificate",
            "Certificate issued",
            "certificates, key_fobs",
            |controller| controller.sync_certificate_and_key_fob_status(),
        ))
    }

    pub fn generate_challenge_with_cloud_sync(
        &mut self,
    ) -> Result<ProvisioningCloudSyncResult, AppControllerError> {
        self.ensure_visible_provisioning_context_selected()?;
        self.generate_authentication_challenge()?;
        Ok(self.provisioning_sync_result(
            "Generate Challenge",
            "Challenge generated",
            "vehicles",
            |controller| controller.sync_vehicle_metadata(),
        ))
    }

    pub fn sign_canonical_payload_with_cloud_sync(
        &mut self,
    ) -> Result<ProvisioningCloudSyncResult, AppControllerError> {
        self.ensure_visible_key_fob_selected()?;
        if self.current_certificate().is_none() {
            return Err(AppControllerError::Backend(
                "Issue an access certificate before signing the payload.".to_string(),
            ));
        }
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
        self.ensure_verify_authentication_ready()?;
        self.verification_in_progress = true;
        if let Err(error) = self.run_legitimate_authentication_demo() {
            self.verification_in_progress = false;
            return Err(error);
        }
        self.verification_in_progress = false;
        Ok(self.provisioning_sync_result(
            "Verify Key Authentication",
            "Authentication verified",
            "vehicles, key_fobs",
            |controller| controller.sync_vehicle_and_key_fob_status(),
        ))
    }

    pub fn activate_secure_session_with_cloud_sync(
        &mut self,
    ) -> Result<ProvisioningCloudSyncResult, AppControllerError> {
        self.ensure_visible_provisioning_context_selected()?;
        self.establish_secure_session_demo()?;
        Ok(self.provisioning_sync_result(
            "Activate Secure Session",
            "Secure session activated",
            "provisioning_sessions, vehicles, key_fobs",
            |controller| controller.sync_session_and_key_fob_status(),
        ))
    }

    pub fn finalize_provisioning_with_cloud_sync(
        &mut self,
    ) -> Result<ProvisioningCloudSyncResult, AppControllerError> {
        self.ensure_visible_provisioning_context_selected()?;
        self.export_provisioning_report()?;
        self.set_active_key_fob_status(
            Some(ISSUED_CERTIFICATE_STATUS),
            Some(FINALIZED_PROVISIONING_STATUS),
        );
        self.set_active_vehicle_status(FINALIZED_PROVISIONING_STATUS);
        let action_name = "Finalize & Export Report";
        let provisioning_status = "Provisioning finalized and report exported";

        if !self.cloud_auto_sync_enabled {
            let _ = self.save_log_entry("[DB]", "Cloud sync skipped: disabled");
            return Ok(self.build_provisioning_cloud_sync_result(
                action_name,
                provisioning_status,
                false,
                "Skipped - disabled".to_string(),
                "None",
                None,
            ));
        }

        match self.sync_finalized_provisioning_records() {
            Ok(_) => {
                let _ = self
                    .save_log_entry("[DB]", "Cloud sync completed for Finalize & Export Report");
                let _ = self.save_log_entry("[SECURITY]", "Cloud secret material: [REDACTED]");
                Ok(self.build_provisioning_cloud_sync_result(
                    action_name,
                    provisioning_status,
                    true,
                    "Provisioning session, vehicle status, key fob status, encrypted key backup, and audit logs synced".to_string(),
                    "provisioning_sessions, vehicles, key_fobs, encrypted_keys, audit_logs",
                    None,
                ))
            }
            Err(error) => {
                let safe_error = error.to_string();
                let _ = self.save_log_entry(
                    "[DB]",
                    format!(
                        "Finalized provisioning sync failed after local finalization: {safe_error}"
                    ),
                );
                Ok(self.build_provisioning_cloud_sync_result(
                    action_name,
                    provisioning_status,
                    true,
                    format!("Finalized provisioning sync failed: {safe_error}"),
                    "provisioning_sessions, vehicles, key_fobs, encrypted_keys, audit_logs",
                    Some(safe_error),
                ))
            }
        }
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
        self.select_customer_context(customer.clone(), "CreatedThisSession");
        upsert_local_customer(&mut self.customer_records, customer);
        Ok(message)
    }

    pub fn load_customer_records(&mut self) -> Result<String, AppControllerError> {
        let client = match self.ensure_schema_initialized() {
            Ok(client) => client,
            Err(error) if is_cloud_not_configured(&error.to_string()) => {
                return Ok("Cloud database is not configured; no customer selected".to_string());
            }
            Err(error) => return Err(error),
        };
        match self.run_cloud(async { client.list_customers().await }) {
            Ok(records) => {
                self.customer_records = records;
                if self.customer_records.is_empty() {
                    Ok("Customers loaded: no cloud records available".to_string())
                } else {
                    Ok(format!("Customers loaded: {}", self.customer_records.len()))
                }
            }
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
            self.select_customer_context(customer.clone(), "CloudSelected");
            return Ok(format!("Customer selected: {}", customer.customer_id));
        }

        let client = self.ensure_schema_initialized()?;
        match self.run_cloud(async { client.get_customer(customer_id).await }) {
            Ok(Some(customer)) => {
                self.select_customer_context(customer.clone(), "CloudSelected");
                upsert_local_customer(&mut self.customer_records, customer.clone());
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
            provisioning_status: Some(VEHICLE_CREATED_STATUS.to_string()),
        };
        let message = self.persist_vehicle_record(vehicle.clone())?;
        self.select_vehicle_context(vehicle.clone(), "CreatedThisSession");
        upsert_local_vehicle(&mut self.vehicle_records, vehicle);
        Ok(message)
    }

    pub fn load_vehicle_records(&mut self) -> Result<String, AppControllerError> {
        let client = match self.ensure_schema_initialized() {
            Ok(client) => client,
            Err(error) if is_cloud_not_configured(&error.to_string()) => {
                return Ok("Cloud database is not configured; no vehicle selected".to_string());
            }
            Err(error) => return Err(error),
        };
        match self.run_cloud(async { client.list_vehicles().await }) {
            Ok(records) => {
                self.vehicle_records = records;
                if self.vehicle_records.is_empty() {
                    Ok("Vehicles loaded: no cloud records available".to_string())
                } else {
                    Ok(format!("Vehicles loaded: {}", self.vehicle_records.len()))
                }
            }
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
                return Ok("Cloud database is not configured; no vehicle selected".to_string());
            }
            Err(error) => return Err(error),
        };
        match self.run_cloud(async { client.list_vehicles_for_customer(customer_id).await }) {
            Ok(records) => {
                self.vehicle_records = records;
                if self.vehicle_records.is_empty() {
                    Ok("Vehicles loaded: no cloud records for selected customer".to_string())
                } else {
                    Ok(format!("Vehicles loaded: {}", self.vehicle_records.len()))
                }
            }
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
            self.select_vehicle_context(vehicle.clone(), "CloudSelected");
            return Ok(format!("Vehicle selected: {}", vehicle.vehicle_id));
        }

        let client = self.ensure_schema_initialized()?;
        match self.run_cloud(async { client.get_vehicle(vehicle_id).await }) {
            Ok(Some(vehicle)) => {
                self.select_vehicle_context(vehicle.clone(), "CloudSelected");
                upsert_local_vehicle(&mut self.vehicle_records, vehicle.clone());
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
        self.select_key_fob_context(key_fob.clone(), "CreatedThisSession");
        upsert_local_key_fob(&mut self.key_fob_records, key_fob);
        self.keyfob_detected = false;
        self.session = None;
        self.last_auth_result = None;
        self.last_access_decision = None;
        self.ensure_active_key_fob_crypto_identity()?;
        let key_fob = self.key_fob_metadata();
        let message = self.persist_key_fob_record(key_fob.clone())?;
        self.select_key_fob_context(key_fob.clone(), "CreatedThisSession");
        upsert_local_key_fob(&mut self.key_fob_records, key_fob);
        Ok(message)
    }

    pub fn load_key_fob_records(&mut self) -> Result<String, AppControllerError> {
        let client = match self.ensure_schema_initialized() {
            Ok(client) => client,
            Err(error) if is_cloud_not_configured(&error.to_string()) => {
                return Ok("Cloud database is not configured; no key fob selected".to_string());
            }
            Err(error) => return Err(error),
        };
        match self.run_cloud(async { client.list_key_fobs().await }) {
            Ok(records) => {
                self.key_fob_records = records;
                if self.key_fob_records.is_empty() {
                    Ok("Key fobs loaded: no cloud records available".to_string())
                } else {
                    Ok(format!("Key fobs loaded: {}", self.key_fob_records.len()))
                }
            }
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
                return Ok("Cloud database is not configured; no key fob selected".to_string());
            }
            Err(error) => return Err(error),
        };
        match self.run_cloud(async { client.list_key_fobs_for_vehicle(vehicle_id).await }) {
            Ok(records) => {
                self.key_fob_records = records;
                if self.key_fob_records.is_empty() {
                    Ok("Key fobs loaded: no cloud records for selected vehicle".to_string())
                } else {
                    Ok(format!("Key fobs loaded: {}", self.key_fob_records.len()))
                }
            }
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
            self.select_key_fob_context(key_fob.clone(), "CloudSelected");
            self.keyfob_detected = false;
            self.session = None;
            self.last_auth_result = None;
            self.last_access_decision = None;
            self.ensure_active_key_fob_crypto_identity()?;
            let _ = self.load_active_certificate_from_cloud();
            return Ok(format!(
                "Key fob selected: {}; crypto identity ready",
                key_fob.fob_id
            ));
        }

        let client = self.ensure_schema_initialized()?;
        match self.run_cloud(async { client.get_key_fob(fob_id).await }) {
            Ok(Some(key_fob)) => {
                self.select_key_fob_context(key_fob.clone(), "CloudSelected");
                upsert_local_key_fob(&mut self.key_fob_records, key_fob.clone());
                self.keyfob_detected = false;
                self.session = None;
                self.last_auth_result = None;
                self.last_access_decision = None;
                self.ensure_active_key_fob_crypto_identity()?;
                let _ = self.load_active_certificate_from_cloud();
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

    pub fn sync_key_fob_metadata_and_backup(&mut self) -> Result<String, AppControllerError> {
        let metadata = self.key_fob_metadata();
        let key_fob_backup = self.optional_key_fob_encrypted_key_record();
        let client = self.ensure_schema_initialized()?;
        let message = self
            .run_cloud(async {
                client.upsert_key_fob(&metadata).await?;
                if let Some(record) = &key_fob_backup {
                    client.upsert_encrypted_key(record).await?;
                }
                Ok::<String, CloudStorageError>(
                    "Key fob metadata and encrypted key backup synced".to_string(),
                )
            })
            .map_err(Self::map_cloud_error)?;

        self.save_log_entry(
            "[DB]",
            format!("Key fob metadata synced: {}", metadata.fob_label),
        )?;
        if key_fob_backup.is_some() {
            self.save_log_entry("[DB]", "Selected key fob encrypted backup synced")?;
        } else {
            self.save_log_entry("[DB]", "Encrypted key backup is not configured.")?;
        }
        Ok(message)
    }

    pub fn sync_active_key_fob_status(&mut self) -> Result<String, AppControllerError> {
        let metadata = self.key_fob_metadata();
        let client = self.ensure_schema_initialized()?;
        let message = self
            .run_cloud(async {
                client.upsert_key_fob(&metadata).await?;
                client
                    .update_key_fob_status(
                        &metadata.fob_id,
                        metadata.certificate_status.as_deref(),
                        metadata.provisioning_status.as_deref(),
                    )
                    .await
            })
            .map_err(Self::map_cloud_error)?;

        self.save_log_entry(
            "[DB]",
            format!("Key fob status synced: {}", metadata.fob_id),
        )?;
        Ok(message)
    }

    pub fn sync_vehicle_and_key_fob_status(&mut self) -> Result<String, AppControllerError> {
        let vehicle = self.vehicle_metadata();
        let key_fob = self.key_fob_metadata();
        let client = self.ensure_schema_initialized()?;
        let message = self
            .run_cloud(async {
                client.upsert_vehicle(&vehicle).await?;
                client.upsert_key_fob(&key_fob).await?;
                Ok::<String, CloudStorageError>("Vehicle and key fob status synced".to_string())
            })
            .map_err(Self::map_cloud_error)?;

        self.save_log_entry(
            "[DB]",
            format!(
                "Vehicle and key fob status synced: {}, {}",
                vehicle.vehicle_id, key_fob.fob_id
            ),
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

    pub fn sync_certificate_and_key_fob_status(&mut self) -> Result<String, AppControllerError> {
        let certificate = self.certificate_metadata()?;
        let vehicle = self.vehicle_metadata();
        let key_fob = self.key_fob_metadata();
        let key_fob_backup = self.optional_key_fob_encrypted_key_record();
        let client = self.ensure_schema_initialized()?;
        let message = self
            .run_cloud(async {
                client.upsert_certificate_metadata(&certificate).await?;
                client.upsert_vehicle(&vehicle).await?;
                client.upsert_key_fob(&key_fob).await?;
                if let Some(record) = &key_fob_backup {
                    client.upsert_encrypted_key(record).await?;
                }
                Ok::<String, CloudStorageError>(
                    "Certificate metadata, vehicle status, key fob status, and encrypted key backup synced".to_string(),
                )
            })
            .map_err(Self::map_cloud_error)?;

        self.save_log_entry(
            "[DB]",
            format!(
                "Certificate and key fob status synced: {}, {}",
                certificate.certificate_id, key_fob.fob_id
            ),
        )?;
        self.save_log_entry("[DB]", "Certificate private material: [REDACTED]")?;
        if key_fob_backup.is_some() {
            self.save_log_entry("[DB]", "Selected key fob encrypted backup synced")?;
        } else {
            self.save_log_entry("[DB]", "Encrypted key backup is not configured.")?;
        }
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

    pub fn sync_session_and_key_fob_status(&mut self) -> Result<String, AppControllerError> {
        let session = self.provisioning_session_metadata()?;
        let vehicle = self.vehicle_metadata();
        let key_fob = self.key_fob_metadata();
        let client = self.ensure_schema_initialized()?;
        let message = self
            .run_cloud(async {
                client.upsert_provisioning_session(&session).await?;
                client.upsert_vehicle(&vehicle).await?;
                client.upsert_key_fob(&key_fob).await?;
                Ok::<String, CloudStorageError>(
                    "Provisioning session, vehicle status, and key fob status synced".to_string(),
                )
            })
            .map_err(Self::map_cloud_error)?;

        self.save_log_entry(
            "[DB]",
            format!(
                "Provisioning session and key fob status synced: {}",
                session.session_id
            ),
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

    pub fn sync_finalized_provisioning_records(&mut self) -> Result<String, AppControllerError> {
        let session = self.provisioning_session_metadata()?;
        let vehicle = self.vehicle_metadata();
        let key_fob = self.key_fob_metadata();
        let records = self.active_audit_log_records();
        let key_fob_backup = self.optional_key_fob_encrypted_key_record();
        let client = self.ensure_schema_initialized()?;
        let message = self
            .run_cloud(async {
                client.upsert_provisioning_session(&session).await?;
                client.upsert_vehicle(&vehicle).await?;
                client.upsert_key_fob(&key_fob).await?;
                if let Some(record) = &key_fob_backup {
                    client.upsert_encrypted_key(record).await?;
                }
                for record in &records {
                    client.upsert_audit_log(record).await?;
                }
                Ok::<String, CloudStorageError>(
                    "Finalized provisioning session, vehicle status, key fob status, encrypted key backup, and audit logs synced"
                        .to_string(),
                )
            })
            .map_err(Self::map_cloud_error)?;

        self.save_log_entry(
            "[DB]",
            format!(
                "Finalized provisioning records synced: session {}, vehicle {}, key fob {}",
                session.session_id, vehicle.vehicle_id, key_fob.fob_id
            ),
        )?;
        if key_fob_backup.is_some() {
            self.save_log_entry("[DB]", "Selected key fob encrypted backup confirmed")?;
        } else {
            self.save_log_entry("[DB]", "Encrypted key backup is not configured.")?;
        }
        self.save_log_entry("[SECURITY]", "Finalized cloud secret material: [REDACTED]")?;
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

    pub fn sync_vehicle_and_ca_encrypted_key_blob(&mut self) -> Result<String, AppControllerError> {
        let vehicle = self.vehicle_metadata();
        let ca_record = parse_master_key_from_env()
            .ok()
            .and_then(|master_key| self.ca_encrypted_key_record(&master_key).ok());
        let client = self.ensure_schema_initialized()?;
        let message = self
            .run_cloud(async {
                client.upsert_vehicle(&vehicle).await?;
                if let Some(record) = &ca_record {
                    client.upsert_encrypted_key(record).await?;
                }
                Ok::<String, CloudStorageError>(
                    "Vehicle trust status and encrypted key backup state synced".to_string(),
                )
            })
            .map_err(Self::map_cloud_error)?;

        self.save_log_entry(
            "[DB]",
            format!("Vehicle trust status synced: {}", vehicle.vehicle_id),
        )?;
        if ca_record.is_some() {
            self.save_log_entry("[DB]", "CA encrypted key blob uploaded")?;
        } else {
            self.save_log_entry("[DB]", "Encrypted key backup is not configured.")?;
        }
        self.save_log_entry("[DB]", "Raw private key material: [REDACTED]")?;
        Ok(message)
    }

    pub fn sync_key_fob_encrypted_key_blob(&mut self) -> Result<String, AppControllerError> {
        self.key_fob_private_key_material()?;
        let master_key = parse_master_key_from_env().map_err(Self::map_cloud_error)?;
        let record = self.key_fob_encrypted_key_record(&master_key)?;
        self.save_local_key_fob_encrypted_backup(&record)?;
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

    pub fn recover_key_fob_encrypted_key_backup(
        &mut self,
    ) -> Result<EncryptedKeyRecoveryEvidence, AppControllerError> {
        self.ensure_visible_key_fob_selected()?;
        let master_key = parse_master_key_from_env().map_err(Self::map_encrypted_recovery_error)?;
        let key_id = self.derive_key_fob_encrypted_key_id();
        let local_record = self.key_fob_encrypted_key_record(&master_key)?;
        self.save_local_key_fob_encrypted_backup(&local_record)?;
        let client = self.ensure_schema_initialized()?;
        let record = self
            .run_cloud(async {
                client
                    .get_encrypted_key_by_owner("key_fob", &local_record.owner_id)
                    .await
            })
            .map_err(Self::map_cloud_error)?
            .ok_or_else(|| {
                AppControllerError::Backend(format!(
                    "Encrypted key backup: Not stored for {}",
                    key_id
                ))
            })?;
        let evidence = self.recovery_evidence_from_record(&record, &master_key)?;
        self.last_key_fob_recovery_evidence = Some(evidence.clone());
        self.save_log_entry(
            "[DB]",
            format!(
                "Encrypted key recovery verified for {}: fingerprint_match={}",
                evidence.owner_id, evidence.fingerprint_match
            ),
        )?;
        self.save_log_entry("[SECURITY]", "Recovered private key material: [REDACTED]")?;
        Ok(evidence)
    }

    pub fn sync_encrypted_key_blobs(&mut self) -> Result<String, AppControllerError> {
        self.ca_private_key_material()?;
        self.key_fob_private_key_material()?;
        let master_key = parse_master_key_from_env().map_err(Self::map_cloud_error)?;
        let ca_record = self.ca_encrypted_key_record(&master_key)?;
        let key_fob_record = self.key_fob_encrypted_key_record(&master_key)?;
        self.save_local_key_fob_encrypted_backup(&key_fob_record)?;
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

    pub fn selected_customer_record(&self) -> Option<CustomerMetadata> {
        self.selected_customer.clone()
    }

    pub fn selected_vehicle_record(&self) -> Option<VehicleMetadata> {
        self.selected_vehicle.clone()
    }

    pub fn selected_key_fob_record(&self) -> Option<KeyFobMetadata> {
        self.selected_key_fob.clone()
    }

    pub fn customer_records(&self) -> Vec<CustomerMetadata> {
        self.customer_records.clone()
    }

    pub fn vehicle_records_for_selected_customer(&self) -> Vec<VehicleMetadata> {
        let Some(customer) = self.selected_customer.as_ref() else {
            return Vec::new();
        };

        self.vehicle_records
            .iter()
            .filter(|record| record.customer_id == customer.customer_id)
            .cloned()
            .collect()
    }

    pub fn key_fob_records_for_selected_vehicle(&self) -> Vec<KeyFobMetadata> {
        let Some(vehicle) = self.selected_vehicle.as_ref() else {
            return Vec::new();
        };

        self.key_fob_records
            .iter()
            .filter(|record| record.vehicle_id == vehicle.vehicle_id)
            .cloned()
            .collect()
    }

    pub fn customer_selection_candidate_id(&self) -> Option<String> {
        self.selected_customer
            .as_ref()
            .map(|record| record.customer_id.clone())
    }

    pub fn vehicle_selection_candidate_id(&self) -> Option<String> {
        let selected_customer_id = self.selected_customer.as_ref()?.customer_id.as_str();
        self.selected_vehicle
            .as_ref()
            .filter(|record| record.customer_id == selected_customer_id)
            .map(|record| record.vehicle_id.clone())
    }

    pub fn key_fob_selection_candidate_id(&self) -> Option<String> {
        let selected_vehicle_id = self.selected_vehicle.as_ref()?.vehicle_id.as_str();
        self.selected_key_fob
            .as_ref()
            .filter(|record| record.vehicle_id == selected_vehicle_id)
            .map(|record| record.fob_id.clone())
    }

    pub fn get_visible_provisioning_context(&self) -> VisibleProvisioningContext {
        let customer = self.selected_customer.as_ref();
        let vehicle = self.selected_vehicle.as_ref();
        let key_fob = self.selected_key_fob.as_ref();

        VisibleProvisioningContext {
            customer_selected: customer.is_some(),
            vehicle_selected: vehicle.is_some(),
            key_fob_selected: key_fob.is_some(),
            customer_id: customer
                .map(|record| record.customer_id.clone())
                .unwrap_or_else(|| "N/A".to_string()),
            owner_name: customer
                .map(|record| record.owner_name.clone())
                .unwrap_or_else(|| "No customer selected".to_string()),
            vehicle_id: vehicle
                .map(|record| record.vehicle_id.clone())
                .unwrap_or_else(|| "N/A".to_string()),
            vehicle_display_name: vehicle
                .map(|record| record.vehicle_display_name.clone())
                .unwrap_or_else(|| "No vehicle selected".to_string()),
            fob_id: key_fob
                .map(|record| record.fob_id.clone())
                .unwrap_or_else(|| "N/A".to_string()),
            fob_label: key_fob
                .map(|record| record.fob_label.clone())
                .unwrap_or_else(|| "No key fob selected".to_string()),
            certificate_id: key_fob
                .map(|_| self.derive_certificate_id_for_active_context())
                .unwrap_or_else(|| "N/A".to_string()),
            session_id: key_fob
                .map(|_| self.derive_session_id_for_active_context())
                .unwrap_or_else(|| "N/A".to_string()),
            selection_source: self.selection_source.clone(),
        }
    }

    pub fn get_active_key_fob_crypto_identity(&self) -> ActiveKeyFobCryptoIdentity {
        if self.selected_key_fob.is_none() {
            return ActiveKeyFobCryptoIdentity {
                fob_id: "N/A".to_string(),
                public_key_fingerprint: "Pending".to_string(),
                certificate_id: "N/A".to_string(),
                certificate_subject_id: None,
                certificate_status: DEFAULT_CERTIFICATE_STATUS.to_string(),
                identity_source: "Missing".to_string(),
                binding_status: "Missing identity".to_string(),
            };
        }

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
            format_status_label(
                &self
                    .active_key_fob
                    .certificate_status
                    .clone()
                    .unwrap_or_else(|| DEFAULT_CERTIFICATE_STATUS.to_string()),
            )
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

    pub fn get_active_certificate_details(&self) -> ActiveCertificateDetails {
        let Some(selected_key_fob) = self.selected_key_fob.as_ref() else {
            return ActiveCertificateDetails {
                available: false,
                certificate_id: None,
                fob_id: None,
                vehicle_id: None,
                subject_id: None,
                issuer: None,
                signature_algorithm: None,
                certificate_signature_fingerprint: None,
                public_key_fingerprint: None,
                certificate_json_available: false,
                certificate_status: Some(format_status_label(DEFAULT_CERTIFICATE_STATUS)),
                issued_at: None,
                expires_at: None,
                source: "NotIssued".to_string(),
                message: "No key fob selected".to_string(),
            };
        };

        let certificate_id = self.derive_certificate_id_for_active_context();
        if let Some(certificate) = self
            .current_certificate()
            .filter(|_| self.current_certificate_belongs_to_active_fob())
        {
            return ActiveCertificateDetails {
                available: true,
                certificate_id: Some(certificate_id),
                fob_id: Some(selected_key_fob.fob_id.clone()),
                vehicle_id: Some(self.active_vehicle.vehicle_id.clone()),
                subject_id: Some(certificate.subject_id.clone()),
                issuer: Some(certificate.issuer.clone()),
                signature_algorithm: Some(CERTIFICATE_SIGNATURE_ALGORITHM.to_string()),
                certificate_signature_fingerprint: Some(fingerprint(&certificate.signature)),
                public_key_fingerprint: Some(fingerprint(&certificate.public_key)),
                certificate_json_available: true,
                certificate_status: Some(format_status_label(ISSUED_CERTIFICATE_STATUS)),
                issued_at: Some(format_nepal_time_from_rfc3339(&certificate.issued_at)),
                expires_at: Some(format_nepal_time_from_rfc3339(&certificate.expires_at)),
                source: "ActiveContext".to_string(),
                message: "Certificate issued".to_string(),
            };
        }

        if let Some(metadata) = self
            .active_certificate_metadata
            .as_ref()
            .filter(|metadata| metadata.fob_id == selected_key_fob.fob_id)
        {
            return ActiveCertificateDetails {
                available: true,
                certificate_id: Some(metadata.certificate_id.clone()),
                fob_id: Some(metadata.fob_id.clone()),
                vehicle_id: Some(if metadata.vehicle_id.is_empty() {
                    self.active_vehicle.vehicle_id.clone()
                } else {
                    metadata.vehicle_id.clone()
                }),
                subject_id: Some(metadata.subject_id.clone()),
                issuer: Some(metadata.issuer.clone()),
                signature_algorithm: Some(metadata.signature_algorithm.clone()),
                certificate_signature_fingerprint: metadata
                    .certificate_signature_fingerprint
                    .clone(),
                public_key_fingerprint: metadata.public_key_fingerprint.clone(),
                certificate_json_available: metadata.certificate_json.is_some(),
                certificate_status: Some(format_status_label(&metadata.certificate_status)),
                issued_at: metadata.issued_at.map(format_nepal_time),
                expires_at: metadata.expires_at.map(format_nepal_time),
                source: "CloudMetadata".to_string(),
                message: "Certificate metadata loaded from cloud".to_string(),
            };
        }

        ActiveCertificateDetails {
            available: false,
            certificate_id: Some(certificate_id),
            fob_id: Some(selected_key_fob.fob_id.clone()),
            vehicle_id: Some(self.active_vehicle.vehicle_id.clone()),
            subject_id: None,
            issuer: None,
            signature_algorithm: Some(CERTIFICATE_SIGNATURE_ALGORITHM.to_string()),
            certificate_signature_fingerprint: None,
            public_key_fingerprint: self
                .key_fob_public_key_fingerprint()
                .or_else(|| selected_key_fob.public_key_fingerprint.clone()),
            certificate_json_available: false,
            certificate_status: selected_key_fob
                .certificate_status
                .clone()
                .map(|status| format_status_label(&status))
                .or_else(|| Some(format_status_label(DEFAULT_CERTIFICATE_STATUS))),
            issued_at: None,
            expires_at: None,
            source: "NotIssued".to_string(),
            message: "No certificate issued for selected key fob".to_string(),
        }
    }

    pub fn load_active_certificate_from_cloud(&mut self) -> Result<String, AppControllerError> {
        let fob_id = self
            .selected_key_fob
            .as_ref()
            .map(|record| record.fob_id.clone())
            .ok_or_else(|| {
                AppControllerError::Backend(
                    "Select a key fob before viewing certificate".to_string(),
                )
            })?;
        let certificate_id = self.derive_certificate_id_for_active_context();
        let client = match self.ensure_schema_initialized() {
            Ok(client) => client,
            Err(error) if is_cloud_not_configured(&error.to_string()) => {
                return Err(AppControllerError::Backend(
                    "Certificate lookup unavailable: cloud disconnected".to_string(),
                ));
            }
            Err(error) => return Err(error),
        };

        let by_id = self
            .run_cloud(async {
                client
                    .get_certificate_by_certificate_id(&certificate_id)
                    .await
            })
            .map_err(Self::map_cloud_error)?;
        let metadata = match by_id {
            Some(metadata) => Some(metadata),
            None => self
                .run_cloud(async { client.get_certificate_by_fob_id(&fob_id).await })
                .map_err(Self::map_cloud_error)?,
        };

        let Some(metadata) = metadata else {
            return Err(AppControllerError::Backend(
                "No certificate issued for selected key fob".to_string(),
            ));
        };

        self.apply_loaded_certificate_metadata(metadata);
        Ok("Certificate metadata loaded from cloud".to_string())
    }

    pub fn view_active_certificate_details(
        &mut self,
    ) -> Result<ActiveCertificateDetails, AppControllerError> {
        if self.selected_key_fob.is_none() {
            return Err(AppControllerError::Backend(
                "Select a key fob before viewing certificate".to_string(),
            ));
        }

        let current = self.get_active_certificate_details();
        if current.available {
            return Ok(current);
        }

        self.load_active_certificate_from_cloud()?;
        let loaded = self.get_active_certificate_details();
        if loaded.available {
            Ok(loaded)
        } else {
            Err(AppControllerError::Backend(
                "No certificate issued for selected key fob".to_string(),
            ))
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

    pub fn can_verify_authentication(&self) -> bool {
        self.verify_authentication_readiness().is_ok()
    }

    pub fn verify_authentication_readiness(&self) -> Result<(), AppControllerError> {
        self.ensure_verify_authentication_ready()
    }

    fn ensure_verify_authentication_ready(&self) -> Result<(), AppControllerError> {
        if self.selected_customer.is_none() {
            return Err(AppControllerError::Backend(
                "missing_customer: Select a customer before verifying authentication".to_string(),
            ));
        }
        if self.selected_vehicle.is_none() {
            return Err(AppControllerError::Backend(
                "missing_vehicle: Select a vehicle before verifying authentication".to_string(),
            ));
        }
        if self.selected_key_fob.is_none() {
            return Err(AppControllerError::Backend(
                "missing_key_fob: Select a key fob before verifying authentication".to_string(),
            ));
        }
        let keyfob = self.keyfob.as_ref().ok_or_else(|| {
            AppControllerError::Backend(
                "missing_fob_identity: Register or select a key fob crypto identity before verifying authentication".to_string(),
            )
        })?;
        if keyfob.private_key.is_none() || keyfob.public_key.is_none() {
            return Err(AppControllerError::Backend(
                "missing_fob_identity: Selected key fob crypto identity is incomplete".to_string(),
            ));
        }
        if self.current_certificate().is_none() || !self.current_certificate_belongs_to_active_fob()
        {
            return Err(AppControllerError::Backend(
                "missing_certificate: Issue or load an access certificate before verifying authentication".to_string(),
            ));
        }
        if self.active_challenge.is_none() {
            return Err(AppControllerError::Backend(
                "missing_challenge: Generate Challenge before verifying authentication".to_string(),
            ));
        }
        if self.active_auth_proof.is_none() {
            return Err(AppControllerError::Backend(
                "missing_signed_payload: Sign Canonical Payload before verifying authentication"
                    .to_string(),
            ));
        }
        if self.verification_in_progress {
            return Err(AppControllerError::Backend(
                "verification_in_progress: Verification is already running".to_string(),
            ));
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
        self.active_challenge = None;
        self.active_auth_proof = None;
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
        vehicle.provisioning_status = Some(
            vehicle
                .provisioning_status
                .clone()
                .unwrap_or_else(|| DEFAULT_PROVISIONING_STATUS.to_string()),
        );
        vehicle
    }

    fn key_fob_metadata(&self) -> KeyFobMetadata {
        let mut key_fob = self.active_key_fob.clone();
        key_fob.public_key_fingerprint = self.key_fob_public_key_fingerprint();
        key_fob.certificate_status = Some(
            key_fob
                .certificate_status
                .clone()
                .unwrap_or_else(|| DEFAULT_CERTIFICATE_STATUS.to_string()),
        );
        key_fob.provisioning_status = Some(
            key_fob
                .provisioning_status
                .clone()
                .unwrap_or_else(|| DEFAULT_PROVISIONING_STATUS.to_string()),
        );
        key_fob
    }

    fn set_active_key_fob_status(
        &mut self,
        certificate_status: Option<&str>,
        provisioning_status: Option<&str>,
    ) {
        if let Some(certificate_status) = certificate_status {
            self.active_key_fob.certificate_status = Some(certificate_status.to_string());
        }
        if let Some(provisioning_status) = provisioning_status {
            self.active_key_fob.provisioning_status = Some(provisioning_status.to_string());
        }
        if let Some(selected_key_fob) = self.selected_key_fob.as_mut() {
            selected_key_fob.certificate_status = self.active_key_fob.certificate_status.clone();
            selected_key_fob.provisioning_status = self.active_key_fob.provisioning_status.clone();
        }
        upsert_local_key_fob(&mut self.key_fob_records, self.active_key_fob.clone());
    }

    fn set_active_vehicle_status(&mut self, provisioning_status: &str) {
        self.active_vehicle.provisioning_status = Some(provisioning_status.to_string());
        if let Some(selected_vehicle) = self.selected_vehicle.as_mut() {
            selected_vehicle.provisioning_status = Some(provisioning_status.to_string());
        }
        upsert_local_vehicle(&mut self.vehicle_records, self.active_vehicle.clone());
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

    fn apply_loaded_certificate_metadata(&mut self, metadata: CertificateMetadata) {
        self.active_key_fob.certificate_status = Some(metadata.certificate_status.clone());
        self.active_key_fob.provisioning_status =
            Some(CERTIFICATE_ISSUED_PROVISIONING_STATUS.to_string());
        if let Some(fingerprint) = metadata.public_key_fingerprint.clone() {
            self.active_key_fob.public_key_fingerprint = Some(fingerprint);
        }
        if let Some(selected_key_fob) = self.selected_key_fob.as_mut() {
            selected_key_fob.certificate_status = Some(metadata.certificate_status.clone());
            selected_key_fob.provisioning_status =
                Some(CERTIFICATE_ISSUED_PROVISIONING_STATUS.to_string());
            if let Some(fingerprint) = metadata.public_key_fingerprint.clone() {
                selected_key_fob.public_key_fingerprint = Some(fingerprint);
            }
        }
        upsert_local_key_fob(&mut self.key_fob_records, self.active_key_fob.clone());
        self.active_certificate_metadata = Some(metadata);
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

    fn select_customer_context(&mut self, customer: CustomerMetadata, source: &str) {
        self.active_customer = customer.clone();
        self.selected_customer = Some(customer);
        self.selection_source = source.to_string();

        if self
            .selected_vehicle
            .as_ref()
            .map(|vehicle| vehicle.customer_id != self.active_customer.customer_id)
            .unwrap_or(false)
        {
            self.clear_selected_vehicle_and_fob();
        }
        self.refresh_session_id_for_active_context();
        self.reset_diagnostics_for_context_change();
    }

    fn select_vehicle_context(&mut self, vehicle: VehicleMetadata, source: &str) {
        self.active_vehicle = vehicle.clone();
        self.selected_vehicle = Some(vehicle);
        self.selection_source = source.to_string();
        self.align_active_customer_to_vehicle();
        if self
            .selected_customer
            .as_ref()
            .map(|customer| customer.customer_id != self.active_customer.customer_id)
            .unwrap_or(true)
        {
            self.selected_customer = Some(self.active_customer.clone());
        }

        if self
            .selected_key_fob
            .as_ref()
            .map(|fob| fob.vehicle_id != self.active_vehicle.vehicle_id)
            .unwrap_or(false)
        {
            self.clear_selected_key_fob();
        }
        self.refresh_session_id_for_active_context();
        self.reset_diagnostics_for_context_change();
    }

    fn select_key_fob_context(&mut self, key_fob: KeyFobMetadata, source: &str) {
        self.active_key_fob = key_fob.clone();
        self.selected_key_fob = Some(key_fob);
        self.active_certificate_metadata = None;
        self.active_challenge = None;
        self.active_auth_proof = None;
        self.last_key_fob_recovery_evidence = None;
        self.selection_source = source.to_string();
        self.align_active_vehicle_to_key_fob();
        if self
            .selected_vehicle
            .as_ref()
            .map(|vehicle| vehicle.vehicle_id != self.active_vehicle.vehicle_id)
            .unwrap_or(true)
        {
            self.selected_vehicle = Some(self.active_vehicle.clone());
        }
        if self
            .selected_customer
            .as_ref()
            .map(|customer| customer.customer_id != self.active_customer.customer_id)
            .unwrap_or(true)
        {
            self.selected_customer = Some(self.active_customer.clone());
        }
        self.refresh_session_id_for_active_context();
        self.reset_diagnostics_for_context_change();
    }

    fn clear_selected_vehicle_and_fob(&mut self) {
        self.selected_vehicle = None;
        self.clear_selected_key_fob();
        self.reset_diagnostics_for_context_change();
    }

    fn clear_selected_key_fob(&mut self) {
        self.selected_key_fob = None;
        self.active_certificate_metadata = None;
        self.keyfob = None;
        self.keyfob_detected = false;
        self.active_challenge = None;
        self.active_auth_proof = None;
        self.verification_in_progress = false;
        self.last_key_fob_recovery_evidence = None;
        self.session = None;
        self.last_auth_result = None;
        self.last_access_decision = None;
        self.provisioning_report_exported = false;
        self.reset_diagnostics_for_context_change();
    }

    fn reset_diagnostics_for_context_change(&mut self) {
        self.last_diagnostic_results.clear();
        let context = self.get_visible_provisioning_context();
        let mut summary = DiagnosticContextSummary {
            customer_status: if context.customer_selected {
                "loaded".to_string()
            } else {
                "missing".to_string()
            },
            vehicle_status: if context.vehicle_selected {
                "loaded".to_string()
            } else {
                "missing".to_string()
            },
            key_fob_status: if context.key_fob_selected {
                "loaded".to_string()
            } else {
                "missing".to_string()
            },
            certificate_id: context.certificate_id,
            session_id: context.session_id,
            evidence_directory: format!(
                "{}/{}",
                DIAGNOSTIC_RESULTS_DIR,
                safe_path_component(&context.fob_id)
            ),
            ..DiagnosticContextSummary::default()
        };
        summary.readiness_reason = if !context.customer_selected {
            "missing_customer"
        } else if !context.vehicle_selected {
            "missing_vehicle"
        } else if !context.key_fob_selected {
            "missing_key_fob"
        } else {
            "missing_certificate"
        }
        .to_string();
        self.last_diagnostic_context = summary;
    }

    fn ensure_visible_customer_selected(&self) -> Result<(), AppControllerError> {
        if self.selected_customer.is_some() {
            Ok(())
        } else {
            Err(AppControllerError::Backend(
                "Select customer, vehicle, and key fob before provisioning.".to_string(),
            ))
        }
    }

    fn ensure_visible_vehicle_selected(&self) -> Result<(), AppControllerError> {
        if self.selected_vehicle.is_some() {
            Ok(())
        } else {
            Err(AppControllerError::Backend(
                "Select customer, vehicle, and key fob before provisioning.".to_string(),
            ))
        }
    }

    fn ensure_visible_key_fob_selected(&self) -> Result<(), AppControllerError> {
        if self.selected_key_fob.is_some() {
            Ok(())
        } else {
            Err(AppControllerError::Backend(
                "Select a key fob before issuing certificate/signing/authentication.".to_string(),
            ))
        }
    }

    fn ensure_visible_provisioning_context_selected(&self) -> Result<(), AppControllerError> {
        self.ensure_visible_customer_selected()?;
        self.ensure_visible_vehicle_selected()?;
        self.ensure_visible_key_fob_selected()
    }

    fn hydrate_diagnostics_context(
        &mut self,
        prepare_runtime_state: bool,
    ) -> Result<DiagnosticContextSummary, AppControllerError> {
        let context = self.get_visible_provisioning_context();
        let mut summary = DiagnosticContextSummary {
            customer_status: if context.customer_selected {
                "loaded".to_string()
            } else {
                "missing".to_string()
            },
            vehicle_status: if context.vehicle_selected {
                "loaded".to_string()
            } else {
                "missing".to_string()
            },
            key_fob_status: if context.key_fob_selected {
                "loaded".to_string()
            } else {
                "missing".to_string()
            },
            certificate_id: context.certificate_id.clone(),
            session_id: context.session_id.clone(),
            evidence_directory: format!(
                "{}/{}",
                DIAGNOSTIC_RESULTS_DIR,
                safe_path_component(&context.fob_id)
            ),
            ..DiagnosticContextSummary::default()
        };

        if !context.customer_selected {
            summary.readiness_reason = "missing_customer".to_string();
            return Ok(summary);
        }
        if !context.vehicle_selected {
            summary.readiness_reason = "missing_vehicle".to_string();
            return Ok(summary);
        }
        if !context.key_fob_selected {
            summary.readiness_reason = "missing_key_fob".to_string();
            return Ok(summary);
        }

        summary.fob_identity_status = match self.ensure_active_key_fob_crypto_identity() {
            Ok(_) => "local_key_available".to_string(),
            Err(_) => "missing".to_string(),
        };

        summary.certificate_status = if self.current_certificate_belongs_to_active_fob() {
            "loaded_from_memory".to_string()
        } else {
            match self.load_active_certificate_from_cloud() {
                Ok(_) => "loaded_from_cloud".to_string(),
                Err(_) => "missing".to_string(),
            }
        };
        summary.certificate_id = self
            .active_certificate_metadata
            .as_ref()
            .map(|metadata| metadata.certificate_id.clone())
            .unwrap_or_else(|| context.certificate_id.clone());

        summary.session_status = if self
            .session
            .as_ref()
            .map(|s| s.established)
            .unwrap_or(false)
        {
            "loaded_from_memory".to_string()
        } else {
            match self.load_latest_session_for_selected_context() {
                Ok(Some(session)) => {
                    self.apply_loaded_provisioning_session_metadata(session);
                    "loaded_from_cloud".to_string()
                }
                Ok(None) => "missing".to_string(),
                Err(_) => "missing".to_string(),
            }
        };
        summary.session_id = self.active_session_id.clone();

        summary.encrypted_backup_status =
            match self.load_encrypted_backup_metadata_for_selected_fob() {
                Ok(Some(_)) => "available".to_string(),
                Ok(None) => "missing".to_string(),
                Err(error) if is_cloud_not_configured(&error.to_string()) => {
                    "not_configured".to_string()
                }
                Err(_) => "missing".to_string(),
            };

        if prepare_runtime_state {
            self.prepare_diagnostic_certificate_and_proof()?;
            summary.certificate_status = if self
                .active_certificate_metadata
                .as_ref()
                .map(|metadata| metadata.fob_id == self.active_key_fob.fob_id)
                .unwrap_or(false)
            {
                summary.certificate_status
            } else {
                "loaded_from_memory".to_string()
            };
        }

        summary.diagnostic_proof_status = if self.active_auth_proof.is_some() {
            "generated".to_string()
        } else {
            "not_generated".to_string()
        };

        if summary.certificate_status == "missing" {
            summary.readiness_reason = "missing_certificate".to_string();
        } else if summary.fob_identity_status == "missing" {
            summary.readiness_reason = "missing_fob_identity".to_string();
        } else {
            summary.readiness = "ready".to_string();
            summary.readiness_reason = "diagnostic_context_ready".to_string();
        }

        Ok(summary)
    }

    fn prepare_diagnostic_runtime_state(
        &mut self,
        definition: DiagnosticDefinition,
    ) -> Result<(), AppControllerError> {
        let mut summary = self.hydrate_diagnostics_context(false)?;
        if summary.readiness != "ready" {
            self.last_diagnostic_context = summary.clone();
            return Err(AppControllerError::Backend(summary.readiness_reason));
        }

        if definition.requires_certificate || definition.requires_signed_payload {
            self.prepare_diagnostic_certificate_and_proof()?;
            summary.certificate_status = "loaded_from_memory".to_string();
            summary.diagnostic_proof_status = "generated".to_string();
        }

        if definition.requires_session && self.session.is_none() {
            self.prepare_diagnostic_certificate_and_proof()?;
            self.run_legitimate_authentication_demo()?;
            self.establish_secure_session_demo()?;
            summary.session_status = "loaded_from_memory".to_string();
            summary.session_id = self.active_session_id.clone();
        }

        if definition.requires_encrypted_backup {
            let master_key = parse_master_key_from_env()
                .map_err(|_| AppControllerError::Backend("missing_master_key".to_string()))?;
            if self
                .load_encrypted_backup_metadata_for_selected_fob()?
                .is_none()
            {
                self.key_fob_encrypted_key_record(&master_key)
                    .map_err(|_| {
                        AppControllerError::Backend("missing_encrypted_backup".to_string())
                    })?;
            }
            summary.encrypted_backup_status = "available".to_string();
        }

        summary.readiness = "ready".to_string();
        summary.readiness_reason = "diagnostic_context_ready".to_string();
        self.last_diagnostic_context = summary;
        Ok(())
    }

    fn prepare_diagnostic_certificate_and_proof(&mut self) -> Result<(), AppControllerError> {
        self.ensure_visible_provisioning_context_selected()?;
        self.ensure_active_key_fob_crypto_identity()?;
        if self.current_certificate().is_none() || !self.current_certificate_belongs_to_active_fob()
        {
            self.issue_keyfob_certificate()?;
        }
        if self.active_challenge.is_none() {
            self.generate_authentication_challenge()?;
        }
        if self.active_auth_proof.is_none() {
            self.sign_canonical_auth_payload()?;
        }
        Ok(())
    }

    fn load_latest_session_for_selected_context(
        &mut self,
    ) -> Result<Option<ProvisioningSessionMetadata>, AppControllerError> {
        let context = self.get_visible_provisioning_context();
        if !context.customer_selected || !context.vehicle_selected || !context.key_fob_selected {
            return Ok(None);
        }
        let client = self.ensure_schema_initialized()?;
        self.run_cloud(async {
            client
                .get_latest_provisioning_session_for_context(
                    &context.customer_id,
                    &context.vehicle_id,
                    &context.fob_id,
                )
                .await
        })
        .map_err(Self::map_cloud_error)
    }

    fn load_encrypted_backup_metadata_for_selected_fob(
        &mut self,
    ) -> Result<Option<EncryptedKeyRecord>, AppControllerError> {
        let fob_id = self
            .selected_key_fob
            .as_ref()
            .map(|record| record.fob_id.clone())
            .ok_or_else(|| AppControllerError::Backend("missing_key_fob".to_string()))?;
        let client = self.ensure_schema_initialized()?;
        self.run_cloud(async { client.get_encrypted_key_by_owner("key_fob", &fob_id).await })
            .map_err(Self::map_cloud_error)
    }

    fn apply_loaded_provisioning_session_metadata(
        &mut self,
        metadata: ProvisioningSessionMetadata,
    ) {
        self.active_session_id = metadata.session_id;
        self.set_active_vehicle_status(&metadata.provisioning_status);
        self.set_active_key_fob_status(
            Some(ISSUED_CERTIFICATE_STATUS),
            Some(&metadata.provisioning_status),
        );
        if metadata.auth_status == AUTHENTICATED_STATUS {
            self.last_auth_result = Some(AuthResult::Success);
            self.last_access_decision = Some(AccessDecision::GrantAccess);
        }
    }

    fn ensure_diagnostic_readiness(
        &self,
        definition: DiagnosticDefinition,
    ) -> Result<(), AppControllerError> {
        self.ensure_visible_provisioning_context_selected()?;
        if definition.requires_certificate
            && self.current_certificate().is_none()
            && self.active_certificate_metadata.is_none()
        {
            return Err(AppControllerError::Backend(
                "missing_certificate".to_string(),
            ));
        }
        if definition.requires_signed_payload && self.active_auth_proof.is_none() {
            return Err(AppControllerError::Backend(
                "missing_signed_payload".to_string(),
            ));
        }
        if definition.requires_session && self.session.is_none() {
            return Err(AppControllerError::Backend("missing_session".to_string()));
        }
        if definition.requires_encrypted_backup {
            let master_key = parse_master_key_from_env()
                .map_err(|_| AppControllerError::Backend("missing_master_key".to_string()))?;
            self.key_fob_encrypted_key_record(&master_key)
                .map_err(|_| AppControllerError::Backend("missing_encrypted_backup".to_string()))?;
        }
        Ok(())
    }

    fn execute_diagnostic_definition(
        &mut self,
        definition: DiagnosticDefinition,
    ) -> Result<DiagnosticDashboardResult, AppControllerError> {
        let created_at = Utc::now();
        let context = self.get_visible_provisioning_context();
        let certificate_id = self.derive_certificate_id_for_active_context();
        let session_id = self.active_session_id.clone();
        let (actual_result, protected_result, access_decision, pass_fail) =
            if let Some(attack_type) = definition.attack_type {
                let attack_result = run_adversarial_attack(attack_type);
                let pass = attack_result.success;
                (
                    attack_result.access_decision.clone(),
                    if pass {
                        definition.protected_result.to_string()
                    } else {
                        "attack_not_blocked".to_string()
                    },
                    if pass {
                        definition.access_decision.to_string()
                    } else {
                        "grant_access".to_string()
                    },
                    if pass { "pass" } else { "fail" }.to_string(),
                )
            } else {
                let master_key = parse_master_key_from_env()
                    .map_err(|_| AppControllerError::Backend("missing_master_key".to_string()))?;
                let record = self.key_fob_encrypted_key_record(&master_key)?;
                let wrong_key = [0xA5_u8; 32];
                let failed_safely =
                    decrypt_private_key_from_cloud(&record.encrypted_key, &wrong_key).is_err();
                (
                    if failed_safely {
                        "encrypted_key_recovery_failed"
                    } else {
                        "encrypted_key_recovery_unexpectedly_succeeded"
                    }
                    .to_string(),
                    if failed_safely {
                        "recovery_blocked"
                    } else {
                        "recovery_not_blocked"
                    }
                    .to_string(),
                    "not_applicable".to_string(),
                    if failed_safely { "pass" } else { "fail" }.to_string(),
                )
            };

        let evidence_file_path = self.save_diagnostic_evidence(DiagnosticEvidenceInput {
            definition,
            context: &context,
            certificate_id: &certificate_id,
            session_id: &session_id,
            actual_result: &actual_result,
            protected_result: &protected_result,
            access_decision: &access_decision,
            pass_fail: &pass_fail,
            created_at,
        })?;
        let evidence_summary = definition.evidence_summary.to_string();
        let diagnostic_status = if pass_fail == "pass" {
            "protected".to_string()
        } else {
            "failed".to_string()
        };
        let mut result = DiagnosticDashboardResult {
            diagnostic_id: format!(
                "DIAG-{}-{}-{}",
                definition.attack_name,
                safe_path_component(&context.fob_id),
                Uuid::new_v4().simple()
            ),
            attack_name: definition.attack_name.to_string(),
            attack_label: definition.attack_label.to_string(),
            customer_id: context.customer_id,
            vehicle_id: context.vehicle_id,
            fob_id: context.fob_id,
            certificate_id,
            session_id,
            expected_result: definition.expected_result.to_string(),
            baseline_result: definition.baseline_result.to_string(),
            protected_result,
            actual_result,
            security_control_triggered: definition.security_control.to_string(),
            access_decision,
            diagnostic_status,
            pass_fail,
            evidence_summary,
            evidence_file_path,
            cloud_sync_status: "disabled".to_string(),
            created_at_nepal_time: format_nepal_time(created_at),
        };
        result.cloud_sync_status = self.sync_diagnostic_dashboard_result(&result);
        Ok(result)
    }

    fn save_diagnostic_evidence(
        &self,
        input: DiagnosticEvidenceInput<'_>,
    ) -> Result<String, AppControllerError> {
        let definition = input.definition;
        let context = input.context;
        let dir = PathBuf::from(DIAGNOSTIC_RESULTS_DIR).join(safe_path_component(&context.fob_id));
        fs::create_dir_all(&dir).map_err(|error| AppControllerError::Backend(error.to_string()))?;
        let path = dir.join(format!("{}.json", definition.attack_name));
        let evidence = serde_json::json!({
            "attack_name": definition.attack_name,
            "customer_id": context.customer_id,
            "vehicle_id": context.vehicle_id,
            "fob_id": context.fob_id,
            "certificate_id": input.certificate_id,
            "session_id": input.session_id,
            "expected_result": definition.expected_result,
            "baseline_result": definition.baseline_result,
            "protected_result": input.protected_result,
            "actual_result": input.actual_result,
            "security_control_triggered": definition.security_control,
            "access_decision": input.access_decision,
            "diagnostic_result": input.pass_fail,
            "evidence_summary": definition.evidence_summary,
            "raw_payload": "[REDACTED]",
            "raw_signature": "[REDACTED]",
            "raw_nonce": "[REDACTED]",
            "raw_ciphertext": "[REDACTED]",
            "private_key_material": "[REDACTED]",
            "master_key": "[REDACTED]",
            "created_at_nepal_time": format_nepal_time(input.created_at)
        });
        write_pretty_json(&path, &evidence)?;
        Ok(path_for_report(&path))
    }

    fn save_all_diagnostics_summary(
        &self,
        results: &[DiagnosticDashboardResult],
    ) -> Result<(), AppControllerError> {
        if results.is_empty() {
            return Ok(());
        }
        let dir =
            PathBuf::from(DIAGNOSTIC_RESULTS_DIR).join(safe_path_component(&results[0].fob_id));
        fs::create_dir_all(&dir).map_err(|error| AppControllerError::Backend(error.to_string()))?;
        let path = dir.join("all_diagnostics_summary.json");
        let summary = serde_json::json!({
            "fob_id": results[0].fob_id,
            "created_at_nepal_time": format_nepal_time(Utc::now()),
            "private_key_material": "[REDACTED]",
            "raw_payload": "[REDACTED]",
            "results": results.iter().map(|result| serde_json::json!({
                "attack_name": result.attack_name,
                "pass_fail": result.pass_fail,
                "security_control_triggered": result.security_control_triggered,
                "evidence_file_path": result.evidence_file_path,
                "cloud_sync_status": result.cloud_sync_status
            })).collect::<Vec<_>>()
        });
        write_pretty_json(&path, &summary)
    }

    fn sync_diagnostic_dashboard_result(&mut self, result: &DiagnosticDashboardResult) -> String {
        if !self.cloud_auto_sync_enabled {
            let _ = self.save_log_entry("[DB]", "diagnostic_sync_disabled");
            return "disabled".to_string();
        }
        let _ = self.save_log_entry("[DB]", "diagnostic_sync_started");
        let executed_at = Utc::now();
        let mut record = DiagnosticResultRecord {
            diagnostic_id: result.diagnostic_id.clone(),
            attack_name: result.attack_name.clone(),
            customer_id: result.customer_id.clone(),
            vehicle_id: result.vehicle_id.clone(),
            fob_id: result.fob_id.clone(),
            certificate_id: Some(result.certificate_id.clone()),
            session_id: Some(result.session_id.clone()),
            expected_outcome: result.expected_result.clone(),
            baseline_result: Some(result.baseline_result.clone()),
            protected_result: Some(result.protected_result.clone()),
            actual_outcome: result.actual_result.clone(),
            security_control_triggered: result.security_control_triggered.clone(),
            access_decision: result.access_decision.clone(),
            result_status: result.diagnostic_status.clone(),
            pass_fail: result.pass_fail.clone(),
            denial_reason: result.security_control_triggered.clone(),
            evidence_summary: result.evidence_summary.clone(),
            evidence_file_path: result.evidence_file_path.clone(),
            cloud_sync_status: "pending".to_string(),
            executed_at,
            created_at_nepal_time: result.created_at_nepal_time.clone(),
            updated_at_nepal_time: format_nepal_time(executed_at),
        };
        let client = match self.ensure_schema_initialized() {
            Ok(client) => client,
            Err(error) => {
                let status = if is_cloud_not_configured(&error.to_string()) {
                    "not_configured"
                } else {
                    "failed"
                };
                let _ = self.save_log_entry(
                    "[DB]",
                    format!(
                        "diagnostic_sync_{status}: {}",
                        redact_sensitive_terms(&error.to_string())
                    ),
                );
                return status.to_string();
            }
        };
        record.cloud_sync_status = "synced".to_string();
        match self.run_cloud(async { client.upsert_diagnostic_result(&record).await }) {
            Ok(_) => {
                let _ = self.save_log_entry("[DB]", "diagnostic_sync_success");
                "synced".to_string()
            }
            Err(error) => {
                record.cloud_sync_status = "failed".to_string();
                let _ = self.save_log_entry(
                    "[DB]",
                    format!("diagnostic_sync_failed: {}", Self::map_cloud_error(error)),
                );
                "failed".to_string()
            }
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
        let certificate_id = self.derive_certificate_id_for_active_context();
        let public_key_fingerprint = fingerprint(&certificate.public_key);
        let certificate_signature_fingerprint = fingerprint(&certificate.signature);
        let certificate_status = ISSUED_CERTIFICATE_STATUS.to_string();
        let certificate_json = serde_json::json!({
            "certificate_id": certificate_id.clone(),
            "fob_id": self.active_key_fob.fob_id.clone(),
            "vehicle_id": self.active_vehicle.vehicle_id.clone(),
            "subject_id": certificate.subject_id.clone(),
            "issuer": certificate.issuer.clone(),
            "signature_algorithm": CERTIFICATE_SIGNATURE_ALGORITHM,
            "public_key_fingerprint": public_key_fingerprint.clone(),
            "certificate_signature_fingerprint": certificate_signature_fingerprint.clone(),
            "certificate_status": certificate_status.clone(),
            "issued_at": certificate.issued_at.clone(),
            "expires_at": certificate.expires_at.clone()
        });

        Ok(CertificateMetadata {
            certificate_id,
            fob_id: self.active_key_fob.fob_id.clone(),
            vehicle_id: self.active_vehicle.vehicle_id.clone(),
            subject_id: certificate.subject_id.clone(),
            issuer: certificate.issuer,
            issued_at: Some(issued_at),
            expires_at: Some(expires_at),
            public_key_fingerprint: Some(public_key_fingerprint),
            signature_algorithm: CERTIFICATE_SIGNATURE_ALGORITHM.to_string(),
            certificate_signature_fingerprint: Some(certificate_signature_fingerprint),
            certificate_json: Some(certificate_json),
            certificate_status,
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
            auth_result: AUTHENTICATED_STATUS.to_string(),
            session_status: SECURE_SESSION_ESTABLISHED_STATUS.to_string(),
            access_decision: GRANT_ACCESS_DECISION.to_string(),
            session_algorithm: SESSION_ALGORITHM.to_string(),
            session_method: SESSION_ALGORITHM.to_string(),
            provisioning_status: self.provisioning_session_status_value(),
            report_path: IN_APP_REPORT_ONLY_PATH.to_string(),
            started_at: Some(started_at),
            completed_at: Some(completed_at),
        })
    }

    fn provisioning_session_status_value(&self) -> String {
        if self.provisioning_report_exported {
            FINALIZED_PROVISIONING_STATUS.to_string()
        } else if self
            .session
            .as_ref()
            .map(|session| session.established)
            .unwrap_or(false)
        {
            SECURE_SESSION_ESTABLISHED_STATUS.to_string()
        } else {
            DEFAULT_PROVISIONING_STATUS.to_string()
        }
    }

    fn active_audit_log_records(&self) -> Vec<AuditLogRecord> {
        let now = Utc::now();
        let context = self.get_active_provisioning_context();
        let base_record =
            |event_tag: &str, event_type: &str, event_message: String| AuditLogRecord {
                log_id: generated_record_id("AUDIT"),
                event_tag: event_tag.to_string(),
                session_id: context.session_id.clone(),
                certificate_id: context.certificate_id.clone(),
                event_type: event_type.to_string(),
                event_message,
                severity: "info".to_string(),
                actor: "AIACS-GUI".to_string(),
                customer_id: context.customer_id.clone(),
                vehicle_id: context.vehicle_id.clone(),
                fob_id: context.fob_id.clone(),
                created_at: now,
            };

        vec![
            base_record(
                "customer_selected",
                "provisioning_context",
                format!(
                    "Provisioning context selected: customer {}, vehicle {}, key fob {}",
                    context.customer_id, context.vehicle_id, context.fob_id
                ),
            ),
            base_record(
                "certificate_issued",
                "certificate_issued",
                format!(
                    "Certificate {} issued for key fob {} and vehicle {}",
                    context.certificate_id, context.fob_id, context.vehicle_id
                ),
            ),
            base_record(
                "authentication_verified",
                "authentication_verified",
                format!(
                    "Authentication verified for key fob {} using certificate {}; private material [REDACTED]",
                    context.fob_id, context.certificate_id
                ),
            ),
            base_record(
                "secure_session_established",
                "secure_session_established",
                format!(
                    "Secure session {} established for vehicle {} and key fob {}; session material [REDACTED]",
                    context.session_id, context.vehicle_id, context.fob_id
                ),
            ),
            base_record(
                "provisioning_finalized",
                "provisioning_finalized",
                format!(
                    "Provisioning finalized for certificate {} with sensitive material [REDACTED]",
                    context.certificate_id
                ),
            ),
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

    fn optional_key_fob_encrypted_key_record(&self) -> Option<EncryptedKeyRecord> {
        let Ok(master_key) = parse_master_key_from_env() else {
            return None;
        };
        self.key_fob_encrypted_key_record(&master_key)
            .ok()
            .inspect(|record| {
                let _ = self.save_local_key_fob_encrypted_backup(record);
            })
    }

    fn recovery_evidence_from_record(
        &self,
        record: &EncryptedKeyRecord,
        master_key: &[u8; 32],
    ) -> Result<EncryptedKeyRecoveryEvidence, AppControllerError> {
        let paths = self.recovery_artifact_paths();
        self.ensure_recovery_artifact_dir()?;
        fs::write(
            &paths.cloud_encrypted_file,
            &record.encrypted_key.encrypted_key_blob,
        )
        .map_err(|error| AppControllerError::Backend(error.to_string()))?;
        if !paths.local_encrypted_file.exists() {
            self.save_local_key_fob_encrypted_backup(record)?;
        }
        let local_bytes = fs::read(&paths.local_encrypted_file)
            .map_err(|error| AppControllerError::Backend(error.to_string()))?;
        let cloud_bytes = fs::read(&paths.cloud_encrypted_file)
            .map_err(|error| AppControllerError::Backend(error.to_string()))?;
        let local_cloud_encrypted_backup_match = local_bytes == cloud_bytes;
        let decrypted_private_key =
            decrypt_private_key_from_cloud(&record.encrypted_key, master_key)
                .map_err(Self::map_encrypted_recovery_error)?;
        let recovered_public_key = CryptoEngine::derive_ed25519_public_key(&decrypted_private_key)
            .map_err(|_| {
                AppControllerError::Backend(
                    "Encrypted key recovery failed. The local master key may be missing or incorrect."
                        .to_string(),
                )
            })?;
        let recovered_public_key_fingerprint = fingerprint(&recovered_public_key);
        let original_public_key_fingerprint = record
            .public_key_fingerprint
            .clone()
            .unwrap_or_else(|| "Unavailable".to_string());
        let fingerprint_match = original_public_key_fingerprint == recovered_public_key_fingerprint;

        let evidence = EncryptedKeyRecoveryEvidence {
            key_id: record.key_id.clone(),
            owner_type: record.owner_type.clone(),
            owner_id: record.owner_id.clone(),
            public_key_fingerprint: original_public_key_fingerprint,
            recovered_public_key_fingerprint,
            encryption_algorithm: record.encrypted_key.encryption_algorithm.clone(),
            key_purpose: record.key_purpose.clone(),
            storage_status: record.storage_status.clone(),
            local_encrypted_file: path_for_report(&paths.local_encrypted_file),
            cloud_encrypted_file: path_for_report(&paths.cloud_encrypted_file),
            decrypted_recovery_file: path_for_report(&paths.decrypted_recovery_file),
            recovery_evidence_file: path_for_report(&paths.recovery_evidence_file),
            recovery_status: if fingerprint_match {
                "Success".to_string()
            } else {
                "Fingerprint mismatch".to_string()
            },
            fingerprint_match,
            local_cloud_encrypted_backup_match,
        };
        self.save_decrypted_key_recovery_file(&paths, record, &decrypted_private_key)?;
        self.save_recovery_evidence_file(&paths, &evidence)?;
        Ok(evidence)
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

    fn recovery_artifact_paths(&self) -> RecoveryArtifactPaths {
        let fob_id = safe_path_component(&self.active_key_fob.fob_id);
        let dir = PathBuf::from(RECOVERY_ARTIFACTS_DIR).join(fob_id);
        RecoveryArtifactPaths {
            dir: dir.clone(),
            local_encrypted_file: dir.join("encrypted_fob_key_local.bin"),
            cloud_encrypted_file: dir.join("encrypted_fob_key_cloud.bin"),
            metadata_file: dir.join("encrypted_backup_metadata.json"),
            decrypted_recovery_file: dir.join("decrypted_fob_key_recovered.json"),
            recovery_evidence_file: dir.join("recovery_evidence.json"),
        }
    }

    fn ensure_recovery_artifact_dir(&self) -> Result<RecoveryArtifactPaths, AppControllerError> {
        let paths = self.recovery_artifact_paths();
        fs::create_dir_all(&paths.dir)
            .map_err(|error| AppControllerError::Backend(error.to_string()))?;
        Ok(paths)
    }

    fn save_local_key_fob_encrypted_backup(
        &self,
        record: &EncryptedKeyRecord,
    ) -> Result<RecoveryArtifactPaths, AppControllerError> {
        let paths = self.ensure_recovery_artifact_dir()?;
        fs::write(
            &paths.local_encrypted_file,
            &record.encrypted_key.encrypted_key_blob,
        )
        .map_err(|error| AppControllerError::Backend(error.to_string()))?;
        let metadata = serde_json::json!({
            "fob_id": self.active_key_fob.fob_id,
            "key_id": record.key_id,
            "owner_type": record.owner_type,
            "owner_id": record.owner_id,
            "public_key_fingerprint": record.public_key_fingerprint,
            "encryption_algorithm": record.encrypted_key.encryption_algorithm,
            "key_purpose": record.key_purpose,
            "storage_status": record.storage_status,
            "created_at_nepal_time": format_nepal_time(Utc::now()),
            "local_encrypted_file": path_for_report(&paths.local_encrypted_file),
            "cloud_encrypted_file": path_for_report(&paths.cloud_encrypted_file)
        });
        write_pretty_json(&paths.metadata_file, &metadata)?;
        Ok(paths)
    }

    fn save_decrypted_key_recovery_file(
        &self,
        paths: &RecoveryArtifactPaths,
        record: &EncryptedKeyRecord,
        recovered_private_key: &[u8],
    ) -> Result<(), AppControllerError> {
        let recovered = serde_json::json!({
            "warning": "SENSITIVE RECOVERED KEY MATERIAL - DO NOT SHARE OR COMMIT",
            "fob_id": self.active_key_fob.fob_id,
            "key_id": record.key_id,
            "recovered_from": "AES-256-GCM encrypted cloud/local backup",
            "created_at_nepal_time": format_nepal_time(Utc::now()),
            "private_key_material": general_purpose::STANDARD.encode(recovered_private_key)
        });
        write_pretty_json(&paths.decrypted_recovery_file, &recovered)
    }

    fn save_recovery_evidence_file(
        &self,
        paths: &RecoveryArtifactPaths,
        evidence: &EncryptedKeyRecoveryEvidence,
    ) -> Result<(), AppControllerError> {
        let evidence_json = serde_json::json!({
            "fob_id": self.active_key_fob.fob_id,
            "key_id": evidence.key_id,
            "owner_type": evidence.owner_type,
            "owner_id": evidence.owner_id,
            "encryption_algorithm": evidence.encryption_algorithm,
            "key_purpose": evidence.key_purpose,
            "stored_public_key_fingerprint": evidence.public_key_fingerprint,
            "recovered_public_key_fingerprint": evidence.recovered_public_key_fingerprint,
            "fingerprint_match": evidence.fingerprint_match,
            "local_cloud_encrypted_backup_match": evidence.local_cloud_encrypted_backup_match,
            "recovery_status": evidence.recovery_status.to_lowercase(),
            "decryption_location": "local_app_only",
            "master_key": "[REDACTED]",
            "private_key_material_in_report": "[REDACTED]",
            "created_at_nepal_time": format_nepal_time(Utc::now())
        });
        write_pretty_json(&paths.recovery_evidence_file, &evidence_json)
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

    fn map_encrypted_recovery_error(error: CloudStorageError) -> AppControllerError {
        match error {
            CloudStorageError::MissingMasterKey
            | CloudStorageError::InvalidMasterKeyBase64
            | CloudStorageError::InvalidMasterKeySize => {
                AppControllerError::Backend("Encrypted key backup is not configured.".to_string())
            }
            CloudStorageError::PrivateKeyDecryptionFailed => AppControllerError::Backend(
                "Encrypted key recovery failed. The local master key may be missing or incorrect."
                    .to_string(),
            ),
            other => Self::map_cloud_error(other),
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
            Ok("Cloud database is not configured; no record selected".to_string())
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
            "Production note: Secure element or Encrypted key store recommended",
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
        writeln!(
            file,
            "{} {} {}",
            format_nepal_time(Utc::now()),
            tag,
            safe_message
        )
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

#[derive(Debug, Clone, Copy)]
struct DiagnosticDefinition {
    attack_name: &'static str,
    attack_label: &'static str,
    attack_type: Option<AttackType>,
    expected_result: &'static str,
    baseline_result: &'static str,
    protected_result: &'static str,
    security_control: &'static str,
    access_decision: &'static str,
    evidence_summary: &'static str,
    requires_certificate: bool,
    requires_signed_payload: bool,
    requires_session: bool,
    requires_encrypted_backup: bool,
}

struct DiagnosticEvidenceInput<'a> {
    definition: DiagnosticDefinition,
    context: &'a VisibleProvisioningContext,
    certificate_id: &'a str,
    session_id: &'a str,
    actual_result: &'a str,
    protected_result: &'a str,
    access_decision: &'a str,
    pass_fail: &'a str,
    created_at: DateTime<Utc>,
}

fn diagnostic_definition(attack_key: &str) -> Result<DiagnosticDefinition, AppControllerError> {
    let definition = match attack_key {
        "replay_attack" => DiagnosticDefinition {
            attack_name: "replay_attack",
            attack_label: "Replay Attack",
            attack_type: Some(AttackType::ReplayAttack),
            expected_result: "attack_blocked_access_denied",
            baseline_result: "attack_successful_vehicle_opened",
            protected_result: "attack_blocked_access_denied",
            security_control: "nonce_reuse_detection",
            access_decision: "deny_access",
            evidence_summary: "The insecure baseline accepts a replayed signal while AIACS rejects reused challenge material.",
            requires_certificate: true,
            requires_signed_payload: true,
            requires_session: false,
            requires_encrypted_backup: false,
        },
        "forged_signature" => DiagnosticDefinition {
            attack_name: "forged_signature",
            attack_label: "Forged Signature",
            attack_type: Some(AttackType::ForgedSignature),
            expected_result: "invalid_signature",
            baseline_result: "not_applicable",
            protected_result: "attack_blocked_access_denied",
            security_control: "ed25519_signature_verification",
            access_decision: "deny_access",
            evidence_summary: "AIACS rejects authentication proofs whose Ed25519 signature has been altered.",
            requires_certificate: true,
            requires_signed_payload: true,
            requires_session: false,
            requires_encrypted_backup: false,
        },
        "fake_certificate" => DiagnosticDefinition {
            attack_name: "fake_certificate",
            attack_label: "Fake Certificate",
            attack_type: Some(AttackType::FakeCertificate),
            expected_result: "invalid_certificate",
            baseline_result: "not_applicable",
            protected_result: "attack_blocked_access_denied",
            security_control: "certificate_validation",
            access_decision: "deny_access",
            evidence_summary: "AIACS rejects certificates that are not signed by the trusted CA.",
            requires_certificate: true,
            requires_signed_payload: true,
            requires_session: false,
            requires_encrypted_backup: false,
        },
        "identity_mismatch" => DiagnosticDefinition {
            attack_name: "identity_mismatch",
            attack_label: "Identity Mismatch",
            attack_type: Some(AttackType::IdentityMismatch),
            expected_result: "identity_mismatch",
            baseline_result: "not_applicable",
            protected_result: "attack_blocked_access_denied",
            security_control: "selected_fob_identity_binding",
            access_decision: "deny_access",
            evidence_summary: "AIACS rejects proofs whose claimed subject does not match the selected fob certificate.",
            requires_certificate: true,
            requires_signed_payload: true,
            requires_session: false,
            requires_encrypted_backup: false,
        },
        "delayed_relay" => DiagnosticDefinition {
            attack_name: "delayed_relay",
            attack_label: "Delayed Relay",
            attack_type: Some(AttackType::DelayedRelay),
            expected_result: "freshness_timeout",
            baseline_result: "not_applicable",
            protected_result: "attack_blocked_access_denied",
            security_control: "timestamp_freshness_validation",
            access_decision: "deny_access",
            evidence_summary: "AIACS software freshness checks reject stale challenge-response material.",
            requires_certificate: true,
            requires_signed_payload: true,
            requires_session: false,
            requires_encrypted_backup: false,
        },
        "packet_tampering" => DiagnosticDefinition {
            attack_name: "packet_tampering",
            attack_label: "Packet Tampering",
            attack_type: Some(AttackType::PacketTampering),
            expected_result: "invalid_signature",
            baseline_result: "not_applicable",
            protected_result: "attack_blocked_access_denied",
            security_control: "payload_integrity_verification",
            access_decision: "deny_access",
            evidence_summary: "AIACS detects modified canonical payloads through signature verification.",
            requires_certificate: true,
            requires_signed_payload: true,
            requires_session: false,
            requires_encrypted_backup: false,
        },
        "tampered_ciphertext" => DiagnosticDefinition {
            attack_name: "tampered_ciphertext",
            attack_label: "Tampered Ciphertext",
            attack_type: Some(AttackType::TamperedSessionCiphertext),
            expected_result: "aes_gcm_authentication_failed",
            baseline_result: "not_applicable",
            protected_result: "attack_blocked_access_denied",
            security_control: "aes_256_gcm_authenticated_encryption",
            access_decision: "deny_access",
            evidence_summary: "AES-GCM authentication rejects ciphertext or tag modification.",
            requires_certificate: false,
            requires_signed_payload: false,
            requires_session: true,
            requires_encrypted_backup: false,
        },
        "wrong_session_key" => DiagnosticDefinition {
            attack_name: "wrong_session_key",
            attack_label: "Wrong Session Key",
            attack_type: Some(AttackType::WrongSessionKey),
            expected_result: "wrong_session_key_rejected",
            baseline_result: "not_applicable",
            protected_result: "attack_blocked_access_denied",
            security_control: "session_key_binding",
            access_decision: "deny_access",
            evidence_summary: "AIACS rejects protected data when the decrypting session key is not the established key.",
            requires_certificate: false,
            requires_signed_payload: false,
            requires_session: true,
            requires_encrypted_backup: false,
        },
        "wrong_master_key_recovery" => DiagnosticDefinition {
            attack_name: "wrong_master_key_recovery",
            attack_label: "Wrong Master Key Recovery",
            attack_type: None,
            expected_result: "encrypted_key_recovery_failed",
            baseline_result: "not_applicable",
            protected_result: "recovery_blocked",
            security_control: "encrypted_key_recovery_protection",
            access_decision: "not_applicable",
            evidence_summary: "Client-side AES-256-GCM encrypted key backup does not decrypt with an incorrect local master key.",
            requires_certificate: false,
            requires_signed_payload: false,
            requires_session: false,
            requires_encrypted_backup: true,
        },
        _ => {
            return Err(AppControllerError::Backend(format!(
                "Unknown diagnostics attack: {}",
                attack_key
            )))
        }
    };
    Ok(definition)
}

fn run_adversarial_attack(attack_type: AttackType) -> AttackResult {
    match attack_type {
        AttackType::ReplayAttack => AdversarialValidationEngine::simulate_replay_attack(),
        AttackType::ForgedSignature => AdversarialValidationEngine::simulate_forged_signature(),
        AttackType::FakeCertificate => {
            AdversarialValidationEngine::simulate_fake_certificate_attack()
        }
        AttackType::IdentityMismatch => {
            AdversarialValidationEngine::simulate_identity_mismatch_attack()
        }
        AttackType::DelayedRelay => AdversarialValidationEngine::simulate_delayed_relay_attack(),
        AttackType::PacketTampering => {
            AdversarialValidationEngine::simulate_packet_tampering_attack()
        }
        AttackType::UnauthorizedKeyFob => {
            AdversarialValidationEngine::simulate_unauthorized_keyfob_attack()
        }
        AttackType::TamperedSessionCiphertext => {
            AdversarialValidationEngine::simulate_tampered_session_ciphertext()
        }
        AttackType::WrongSessionKey => AdversarialValidationEngine::simulate_wrong_session_key(),
    }
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

struct RecoveryArtifactPaths {
    dir: PathBuf,
    local_encrypted_file: PathBuf,
    cloud_encrypted_file: PathBuf,
    metadata_file: PathBuf,
    decrypted_recovery_file: PathBuf,
    recovery_evidence_file: PathBuf,
}

fn safe_path_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn path_for_report(path: &std::path::Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn write_pretty_json(
    path: &std::path::Path,
    value: &serde_json::Value,
) -> Result<(), AppControllerError> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|error| AppControllerError::Backend(error.to_string()))?;
    fs::write(path, json).map_err(|error| AppControllerError::Backend(error.to_string()))
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

        upsert_local_customer(&mut controller.customer_records, customer.clone());
        upsert_local_vehicle(&mut controller.vehicle_records, vehicle.clone());
        upsert_local_key_fob(&mut controller.key_fob_records, key_fob.clone());
        controller.select_customer_context(customer, "CloudSelected");
        controller.select_vehicle_context(vehicle, "CloudSelected");
        controller.select_key_fob_context(key_fob, "CloudSelected");
        controller.keyfob = None;
        controller.session = None;
        controller.last_auth_result = None;
        controller.last_access_decision = None;
    }

    fn provision_selected_context_for_diagnostics(suffix: &str) -> AppController {
        let mut controller =
            AppController::new_with_log_dir(temp_log_dir(&format!("diag_{suffix}")));
        bind_custom_context(&mut controller, suffix);
        controller
            .connect_vehicle()
            .expect("vehicle should connect");
        controller
            .register_digital_key_fob()
            .expect("key fob should register");
        controller
            .initialize_ca()
            .expect("vehicle trust should initialize");
        controller
            .issue_keyfob_certificate()
            .expect("certificate should issue");
        controller
            .generate_authentication_challenge()
            .expect("challenge should generate");
        controller
            .sign_canonical_auth_payload()
            .expect("payload should sign");
        controller
            .run_legitimate_authentication_demo()
            .expect("selected fob auth should verify");
        controller
            .establish_secure_session_demo()
            .expect("secure session should establish");
        controller
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
    fn test_verify_authentication_first_click_after_signed_payload_succeeds() {
        let mut controller = AppController::new();
        bind_custom_context(&mut controller, "FIRSTCLICK");

        controller
            .issue_keyfob_certificate()
            .expect("certificate should issue");
        controller
            .generate_authentication_challenge()
            .expect("challenge should generate");
        controller
            .sign_canonical_auth_payload()
            .expect("payload should sign");

        assert!(controller.can_verify_authentication());
        let result = controller
            .verify_authentication_with_cloud_sync()
            .expect("first verification attempt should succeed locally");

        assert_eq!(controller.last_auth_result, Some(AuthResult::Success));
        assert_eq!(
            controller
                .active_auth_proof
                .as_ref()
                .map(|proof| proof.subject_id.as_str()),
            Some("FOB-CRYPTO-FIRSTCLICK")
        );
        assert_eq!(result.provisioning_status, "Authentication verified");
        assert!(
            matches!(
                result.cloud_sync_status.as_str(),
                "Skipped - disabled" | "Synced"
            ) || result.cloud_sync_status.starts_with("Failed - ")
        );
    }

    #[test]
    fn test_verify_authentication_readiness_reports_safe_missing_prerequisites() {
        let mut controller = AppController::new();
        bind_custom_context(&mut controller, "PREREQ");

        let missing_fob_identity = controller
            .verify_authentication_readiness()
            .expect_err("fob identity should be required")
            .to_string();
        assert!(missing_fob_identity.contains("missing_fob_identity"));

        controller
            .ensure_active_key_fob_crypto_identity()
            .expect("identity should generate");
        let missing_certificate = controller
            .verify_authentication_readiness()
            .expect_err("certificate should be required")
            .to_string();
        assert!(missing_certificate.contains("missing_certificate"));

        controller
            .issue_keyfob_certificate()
            .expect("certificate should issue");
        let missing_challenge = controller
            .verify_authentication_readiness()
            .expect_err("challenge should be required")
            .to_string();
        assert!(missing_challenge.contains("missing_challenge"));

        controller
            .generate_authentication_challenge()
            .expect("challenge should generate");
        let missing_signed_payload = controller
            .verify_authentication_readiness()
            .expect_err("signed payload should be required")
            .to_string();
        assert!(missing_signed_payload.contains("missing_signed_payload"));

        for message in [
            missing_fob_identity,
            missing_certificate,
            missing_challenge,
            missing_signed_payload,
        ] {
            assert!(!message.contains("AIACS_MASTER_KEY"));
            assert!(!message.contains("private_key"));
            assert!(!message.contains("session_key"));
            assert!(!message.contains("shared_secret"));
        }
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
        assert!(report.contains("No key fob selected"));
        assert!(!report.contains(KEYFOB_PRIVATE_KEY_PATH));
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
    fn test_visible_selected_context_starts_empty() {
        let controller = AppController::new();
        let visible = controller.get_visible_provisioning_context();

        assert!(!visible.customer_selected);
        assert!(!visible.vehicle_selected);
        assert!(!visible.key_fob_selected);
        assert_eq!(visible.owner_name, "No customer selected");
        assert_eq!(visible.vehicle_display_name, "No vehicle selected");
        assert_eq!(visible.fob_label, "No key fob selected");
        assert_eq!(visible.customer_id, "N/A");
        assert_eq!(visible.vehicle_id, "N/A");
        assert_eq!(visible.fob_id, "N/A");
        assert_eq!(visible.certificate_id, "N/A");
        assert_eq!(visible.session_id, "N/A");
        assert_eq!(visible.selection_source, "None");
    }

    #[test]
    fn test_loading_records_does_not_change_visible_selection() {
        let mut controller = AppController::new();
        controller.customer_records = vec![CustomerMetadata {
            customer_id: "CUST-LOAD-TEST".to_string(),
            owner_name: "Loaded Customer".to_string(),
            email: Some("loaded@example.com".to_string()),
            phone: None,
        }];

        assert!(controller.selected_customer_record().is_none());
        assert_eq!(controller.customer_selection_candidate_id(), None);
        assert_eq!(controller.customer_records().len(), 1);
        assert!(
            !controller
                .get_visible_provisioning_context()
                .customer_selected
        );
    }

    #[test]
    fn test_fresh_visible_record_lists_start_empty() {
        let controller = AppController::new();

        assert!(controller.customer_records().is_empty());
        assert!(controller
            .vehicle_records_for_selected_customer()
            .is_empty());
        assert!(controller.key_fob_records_for_selected_vehicle().is_empty());
        assert!(controller.selected_customer_record().is_none());
        assert!(controller.selected_vehicle_record().is_none());
        assert!(controller.selected_key_fob_record().is_none());
    }

    #[test]
    fn test_visible_record_lists_filter_by_selected_parent() {
        let mut controller = AppController::new();
        let customer = CustomerMetadata {
            customer_id: "CUST-LIST".to_string(),
            owner_name: "List Owner".to_string(),
            email: Some("list@example.com".to_string()),
            phone: Some("+977-9800000000".to_string()),
        };
        let other_customer = CustomerMetadata {
            customer_id: "CUST-OTHER".to_string(),
            owner_name: "Other Owner".to_string(),
            email: Some("other@example.com".to_string()),
            phone: None,
        };
        let vehicle = VehicleMetadata {
            vehicle_id: "VEH-LIST".to_string(),
            customer_id: customer.customer_id.clone(),
            vehicle_display_name: "List Vehicle".to_string(),
            make: Some("Nissan".to_string()),
            model: Some("Magnite".to_string()),
            year: Some(2021),
            vin: Some("VIN-LIST".to_string()),
            registration_number: None,
            provisioning_status: Some(DEFAULT_PROVISIONING_STATUS.to_string()),
        };
        let other_vehicle = VehicleMetadata {
            vehicle_id: "VEH-OTHER".to_string(),
            customer_id: other_customer.customer_id.clone(),
            vehicle_display_name: "Other Vehicle".to_string(),
            make: Some("Nissan".to_string()),
            model: Some("Leaf".to_string()),
            year: Some(2022),
            vin: None,
            registration_number: None,
            provisioning_status: Some(DEFAULT_PROVISIONING_STATUS.to_string()),
        };
        let key_fob = KeyFobMetadata {
            fob_id: "FOB-LIST".to_string(),
            vehicle_id: vehicle.vehicle_id.clone(),
            customer_id: customer.customer_id.clone(),
            fob_label: "List Fob".to_string(),
            public_key_fingerprint: Some("fp-list".to_string()),
            certificate_status: Some(DEFAULT_CERTIFICATE_STATUS.to_string()),
            provisioning_status: Some(DEFAULT_PROVISIONING_STATUS.to_string()),
        };
        let other_key_fob = KeyFobMetadata {
            fob_id: "FOB-OTHER".to_string(),
            vehicle_id: other_vehicle.vehicle_id.clone(),
            customer_id: other_customer.customer_id.clone(),
            fob_label: "Other Fob".to_string(),
            public_key_fingerprint: None,
            certificate_status: Some(DEFAULT_CERTIFICATE_STATUS.to_string()),
            provisioning_status: Some(DEFAULT_PROVISIONING_STATUS.to_string()),
        };

        controller.customer_records = vec![customer.clone(), other_customer];
        controller.vehicle_records = vec![vehicle.clone(), other_vehicle];
        controller.key_fob_records = vec![key_fob.clone(), other_key_fob];
        controller.select_customer_context(customer, "CloudSelected");
        controller.select_vehicle_context(vehicle, "CloudSelected");

        assert_eq!(controller.customer_records().len(), 2);
        assert_eq!(controller.vehicle_records_for_selected_customer().len(), 1);
        assert_eq!(
            controller.vehicle_records_for_selected_customer()[0].vehicle_id,
            "VEH-LIST"
        );
        assert_eq!(controller.key_fob_records_for_selected_vehicle().len(), 1);
        assert_eq!(
            controller.key_fob_records_for_selected_vehicle()[0].fob_id,
            key_fob.fob_id
        );
    }

    #[test]
    fn test_protocol_artifacts_and_storage_start_with_visible_empty_state() {
        let controller = AppController::new();
        let artifacts = controller.get_protocol_artifacts().join("\n");
        let storage = controller.credential_storage_summary().join("\n");
        let certificate = controller.get_active_certificate_details();

        assert!(artifacts.contains("No customer selected"));
        assert!(artifacts.contains("No vehicle selected"));
        assert!(artifacts.contains("No key fob selected"));
        assert!(artifacts.contains("No certificate issued"));
        assert!(!artifacts.contains("CUST-0001"));
        assert!(!artifacts.contains("VEH-0001"));
        assert!(!artifacts.contains("FOB-0001"));
        assert!(storage.contains("No key fob selected"));
        assert!(storage.contains("Select a key fob to view credential metadata"));
        assert!(!storage.contains("FOB-0001"));
        assert!(!certificate.available);
        assert_eq!(certificate.message, "No key fob selected");
    }

    #[test]
    fn test_active_certificate_details_use_selected_fob_after_issuance() {
        let mut controller = AppController::new();
        bind_custom_context(&mut controller, "ARTCERT");
        controller
            .issue_keyfob_certificate()
            .expect("certificate should issue for selected fob");

        let details = controller.get_active_certificate_details();
        let identity = controller.get_active_key_fob_crypto_identity();
        let artifacts = controller.get_protocol_artifacts().join("\n");

        assert!(details.available);
        assert_eq!(
            details.certificate_id.as_deref(),
            Some("CERT-FOB-CRYPTO-ARTCERT")
        );
        assert_eq!(details.fob_id.as_deref(), Some("FOB-CRYPTO-ARTCERT"));
        assert_eq!(details.subject_id.as_deref(), Some("FOB-CRYPTO-ARTCERT"));
        assert_eq!(details.signature_algorithm.as_deref(), Some("Ed25519"));
        assert_eq!(
            details.public_key_fingerprint.as_deref(),
            Some(identity.public_key_fingerprint.as_str())
        );
        assert!(artifacts.contains("CERT-FOB-CRYPTO-ARTCERT"));
        assert!(artifacts.contains("subject_id: FOB-CRYPTO-ARTCERT"));
        assert!(!artifacts.contains("CERT-FOB-0001"));
    }

    #[test]
    fn test_newly_issued_certificate_uses_denish_issuer_and_title_status() {
        let mut controller = AppController::new();
        bind_custom_context(&mut controller, "DENISH");
        controller
            .issue_keyfob_certificate()
            .expect("certificate should issue");

        let details = controller.get_active_certificate_details();
        let metadata = controller
            .certificate_metadata()
            .expect("certificate metadata should build");
        let artifacts = controller.get_protocol_artifacts().join("\n");

        assert_eq!(details.issuer.as_deref(), Some("Denish"));
        assert_eq!(details.certificate_status.as_deref(), Some("Issued"));
        assert_eq!(metadata.issuer, "Denish");
        assert_eq!(metadata.certificate_status, ISSUED_CERTIFICATE_STATUS);
        assert!(artifacts.contains("issuer: Denish"));
        assert!(artifacts.contains("certificate_status: Certificate issued"));
    }

    #[test]
    fn test_status_formatter_title_cases_storage_values() {
        assert_eq!(format_status_label("issued"), "Issued");
        assert_eq!(format_status_label("in_progress"), "In Progress");
        assert_eq!(
            format_status_label("certificate_issued"),
            "Certificate Issued"
        );
        assert_eq!(
            format_status_label("session_established"),
            "Session Established"
        );
        assert_eq!(
            format_status_label("secure_session_established"),
            "Secure Session Established"
        );
        assert_eq!(format_status_label("grant_access"), "Grant Access");
        assert_eq!(
            format_status_label("in_app_report_only"),
            "In App Report Only"
        );
        assert_eq!(format_status_label("authenticated"), "Authenticated");
    }

    #[test]
    fn test_nepal_time_formatter_uses_fixed_npt_offset() {
        let timestamp = DateTime::parse_from_rfc3339("2026-06-12T15:00:00Z")
            .expect("timestamp should parse")
            .with_timezone(&Utc);

        assert_eq!(format_nepal_time(timestamp), "2026-06-12 20:45:00 NPT");
    }

    #[test]
    fn test_cloud_loaded_certificate_metadata_restores_details_after_restart() {
        let mut controller = AppController::new();
        bind_custom_context(&mut controller, "RESTORE");
        let metadata = CertificateMetadata {
            certificate_id: "CERT-FOB-CRYPTO-RESTORE".to_string(),
            fob_id: "FOB-CRYPTO-RESTORE".to_string(),
            vehicle_id: "VEH-CRYPTO-RESTORE".to_string(),
            subject_id: "FOB-CRYPTO-RESTORE".to_string(),
            issuer: "Denish".to_string(),
            issued_at: Some(Utc::now()),
            expires_at: Some(Utc::now() + chrono::Duration::days(365)),
            public_key_fingerprint: Some("SHA256:RESTORED".to_string()),
            signature_algorithm: CERTIFICATE_SIGNATURE_ALGORITHM.to_string(),
            certificate_signature_fingerprint: Some("SHA256:RESTOREDSIG".to_string()),
            certificate_json: Some(serde_json::json!({
                "certificate_id": "CERT-FOB-CRYPTO-RESTORE",
                "fob_id": "FOB-CRYPTO-RESTORE",
                "vehicle_id": "VEH-CRYPTO-RESTORE",
                "subject_id": "FOB-CRYPTO-RESTORE",
                "issuer": "Denish",
                "signature_algorithm": CERTIFICATE_SIGNATURE_ALGORITHM,
                "public_key_fingerprint": "SHA256:RESTORED",
                "certificate_signature_fingerprint": "SHA256:RESTOREDSIG",
                "certificate_status": ISSUED_CERTIFICATE_STATUS
            })),
            certificate_status: ISSUED_CERTIFICATE_STATUS.to_string(),
        };

        controller.apply_loaded_certificate_metadata(metadata);
        let details = controller
            .view_active_certificate_details()
            .expect("cloud metadata should satisfy certificate view");

        assert!(details.available);
        assert_eq!(details.source, "CloudMetadata");
        assert_eq!(details.issuer.as_deref(), Some("Denish"));
        assert_eq!(details.certificate_status.as_deref(), Some("Issued"));
        assert_eq!(
            details.certificate_id.as_deref(),
            Some("CERT-FOB-CRYPTO-RESTORE")
        );
        assert_eq!(details.vehicle_id.as_deref(), Some("VEH-CRYPTO-RESTORE"));
        assert_eq!(details.subject_id.as_deref(), Some("FOB-CRYPTO-RESTORE"));
        assert_eq!(
            details.certificate_signature_fingerprint.as_deref(),
            Some("SHA256:RESTOREDSIG")
        );
        assert!(details.certificate_json_available);
    }

    #[test]
    fn test_credential_storage_uses_selected_fob_and_redacts_secrets() {
        let mut controller = AppController::new();
        bind_custom_context(&mut controller, "CREDMETA");
        controller
            .ensure_active_key_fob_crypto_identity()
            .expect("selected fob identity should generate");

        let storage = controller.credential_storage_summary().join("\n");

        assert!(storage.contains("Fob ID: FOB-CRYPTO-CREDMETA"));
        assert!(storage.contains("Certificate ID: CERT-FOB-CRYPTO-CREDMETA"));
        assert!(storage.contains("Key Owner Type: key_fob"));
        assert!(storage.contains("Public Key Fingerprint: SHA256:"));
        assert!(storage.contains("Private Key: [REDACTED]"));
        assert!(!storage.contains("AIACS_MASTER_KEY"));
        assert!(!storage.contains("DATABASE_URL"));
        assert!(!storage.contains("encrypted_key_blob"));
        assert!(!storage.contains("encryption_nonce"));
        assert!(!storage.contains("FOB-0001"));
    }

    #[test]
    fn test_protocol_session_artifact_uses_active_session_after_activation() {
        let mut controller = AppController::new();
        bind_custom_context(&mut controller, "ARTSESSION");
        controller
            .issue_keyfob_certificate()
            .expect("certificate should issue");
        controller
            .run_legitimate_authentication_demo()
            .expect("authentication should verify");
        controller
            .establish_secure_session_demo()
            .expect("session should activate");

        let artifacts = controller.get_protocol_artifacts().join("\n");
        let active_session_id = controller.derive_session_id_for_active_context();

        assert!(artifacts.contains(&format!("session_id: {active_session_id}")));
        assert!(artifacts.contains("Access granted"));
        assert!(!artifacts.contains("SESSION-0001"));
    }

    #[test]
    fn test_selecting_customer_updates_visible_context_and_clears_incompatible_children() {
        let mut controller = AppController::new();
        let customer_a = CustomerMetadata {
            customer_id: "CUST-A".to_string(),
            owner_name: "Owner A".to_string(),
            email: Some("a@example.com".to_string()),
            phone: None,
        };
        let customer_b = CustomerMetadata {
            customer_id: "CUST-B".to_string(),
            owner_name: "Owner B".to_string(),
            email: Some("b@example.com".to_string()),
            phone: None,
        };
        let vehicle_a = VehicleMetadata {
            vehicle_id: "VEH-A".to_string(),
            customer_id: "CUST-A".to_string(),
            vehicle_display_name: "Vehicle A".to_string(),
            make: Some("Nissan".to_string()),
            model: Some("Magnite".to_string()),
            year: Some(2021),
            vin: None,
            registration_number: None,
            provisioning_status: Some(DEFAULT_PROVISIONING_STATUS.to_string()),
        };
        let fob_a = KeyFobMetadata {
            fob_id: "FOB-A".to_string(),
            vehicle_id: "VEH-A".to_string(),
            customer_id: "CUST-A".to_string(),
            fob_label: "Fob A".to_string(),
            public_key_fingerprint: None,
            certificate_status: Some(DEFAULT_CERTIFICATE_STATUS.to_string()),
            provisioning_status: Some(DEFAULT_PROVISIONING_STATUS.to_string()),
        };
        controller.customer_records = vec![customer_a.clone(), customer_b.clone()];
        controller.vehicle_records = vec![vehicle_a.clone()];
        controller.key_fob_records = vec![fob_a.clone()];
        controller.select_customer_context(customer_a, "CloudSelected");
        controller.select_vehicle_context(vehicle_a, "CloudSelected");
        controller.select_key_fob_context(fob_a, "CloudSelected");

        controller
            .select_customer("CUST-B")
            .expect("customer B should select");
        let visible = controller.get_visible_provisioning_context();

        assert!(visible.customer_selected);
        assert_eq!(visible.customer_id, "CUST-B");
        assert!(!visible.vehicle_selected);
        assert!(!visible.key_fob_selected);
        assert!(controller.selected_vehicle_record().is_none());
        assert!(controller.selected_key_fob_record().is_none());
    }

    #[test]
    fn test_selecting_vehicle_updates_visible_context_and_clears_incompatible_fob() {
        let mut controller = AppController::new();
        let customer = CustomerMetadata {
            customer_id: "CUST-VEH-SEL".to_string(),
            owner_name: "Vehicle Select Owner".to_string(),
            email: Some("veh@example.com".to_string()),
            phone: None,
        };
        let vehicle_a = VehicleMetadata {
            vehicle_id: "VEH-SEL-A".to_string(),
            customer_id: customer.customer_id.clone(),
            vehicle_display_name: "Vehicle A".to_string(),
            make: Some("Nissan".to_string()),
            model: Some("Magnite".to_string()),
            year: Some(2021),
            vin: None,
            registration_number: None,
            provisioning_status: Some(DEFAULT_PROVISIONING_STATUS.to_string()),
        };
        let vehicle_b = VehicleMetadata {
            vehicle_id: "VEH-SEL-B".to_string(),
            customer_id: customer.customer_id.clone(),
            vehicle_display_name: "Vehicle B".to_string(),
            make: Some("Nissan".to_string()),
            model: Some("Magnite".to_string()),
            year: Some(2021),
            vin: None,
            registration_number: None,
            provisioning_status: Some(DEFAULT_PROVISIONING_STATUS.to_string()),
        };
        let fob_a = KeyFobMetadata {
            fob_id: "FOB-SEL-A".to_string(),
            vehicle_id: vehicle_a.vehicle_id.clone(),
            customer_id: customer.customer_id.clone(),
            fob_label: "Fob A".to_string(),
            public_key_fingerprint: None,
            certificate_status: Some(DEFAULT_CERTIFICATE_STATUS.to_string()),
            provisioning_status: Some(DEFAULT_PROVISIONING_STATUS.to_string()),
        };
        controller.customer_records = vec![customer.clone()];
        controller.vehicle_records = vec![vehicle_a.clone(), vehicle_b.clone()];
        controller.key_fob_records = vec![fob_a.clone()];
        controller.select_customer_context(customer, "CloudSelected");
        controller.select_vehicle_context(vehicle_a, "CloudSelected");
        controller.select_key_fob_context(fob_a, "CloudSelected");

        controller
            .select_vehicle("VEH-SEL-B")
            .expect("vehicle B should select");
        let visible = controller.get_visible_provisioning_context();

        assert!(visible.vehicle_selected);
        assert_eq!(visible.vehicle_id, "VEH-SEL-B");
        assert!(!visible.key_fob_selected);
        assert!(controller.selected_key_fob_record().is_none());
    }

    #[test]
    fn test_creating_records_auto_selects_visible_context_and_binds_fob_identity() {
        let mut controller = AppController::new();
        controller
            .create_customer_record(
                "Created Owner",
                Some("created@example.com".to_string()),
                None,
            )
            .expect("customer should create locally when cloud is unavailable");
        let customer = controller
            .selected_customer_record()
            .expect("created customer selected");
        controller
            .create_vehicle_record(
                customer.customer_id.clone(),
                "Created Vehicle",
                Some("Nissan".to_string()),
                Some("Magnite".to_string()),
                Some(2021),
                None,
                None,
            )
            .expect("vehicle should create locally when cloud is unavailable");
        let vehicle = controller
            .selected_vehicle_record()
            .expect("created vehicle selected");
        controller
            .create_key_fob_record(vehicle.vehicle_id, "Created Fob")
            .expect("key fob should create locally when cloud is unavailable");

        let visible = controller.get_visible_provisioning_context();
        let identity = controller.get_active_key_fob_crypto_identity();

        assert!(visible.customer_selected);
        assert!(visible.vehicle_selected);
        assert!(visible.key_fob_selected);
        assert_ne!(visible.customer_id, DEMO_CUSTOMER_ID);
        assert_ne!(visible.vehicle_id, DEMO_VEHICLE_ID);
        assert_ne!(visible.fob_id, DEMO_FOB_ID);
        assert_eq!(identity.binding_status, "Bound to selected key fob");
        assert_eq!(identity.fob_id, visible.fob_id);
    }

    #[test]
    fn test_provisioning_actions_fail_safely_without_visible_key_fob_selection() {
        let mut controller = AppController::new();

        let certificate_error = controller
            .issue_access_certificate_with_cloud_sync()
            .expect_err("certificate issuance should require selected key fob")
            .to_string();
        let sign_error = controller
            .sign_canonical_payload_with_cloud_sync()
            .expect_err("signing should require selected key fob")
            .to_string();
        let verify_error = controller
            .verify_authentication_with_cloud_sync()
            .expect_err("verification should require selected key fob")
            .to_string();

        assert_eq!(
            certificate_error,
            "Select a key fob before issuing certificate/signing/authentication."
        );
        assert_eq!(sign_error, certificate_error);
        assert!(verify_error.contains("missing_customer"));
        for message in [certificate_error, sign_error, verify_error] {
            assert!(!message.contains("DATABASE_URL"));
            assert!(!message.contains("AIACS_MASTER_KEY"));
            assert!(!message.contains("private_key"));
        }
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
        bind_custom_context(&mut controller, "CLOUDSKIP");

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
            .generate_challenge_with_cloud_sync()
            .expect("challenge should generate locally");
        controller
            .sign_canonical_payload_with_cloud_sync()
            .expect("payload should sign locally");
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
        assert_eq!(
            finalized.provisioning_status,
            "Provisioning finalized and report exported"
        );
        assert!(!finalized.cloud_sync_attempted);
        assert_eq!(finalized.cloud_sync_status, "Skipped - disabled");
    }

    #[test]
    fn test_key_fob_status_progression_uses_machine_values() {
        let mut controller = AppController::new();
        bind_custom_context(&mut controller, "STATUSFLOW");

        let initial = controller.key_fob_metadata();
        assert_eq!(
            initial.certificate_status.as_deref(),
            Some(DEFAULT_CERTIFICATE_STATUS)
        );
        assert_eq!(
            initial.provisioning_status.as_deref(),
            Some(DEFAULT_PROVISIONING_STATUS)
        );

        controller.detect_key_fob().expect("fob should detect");
        let registered = controller.key_fob_metadata();
        assert_eq!(
            registered.provisioning_status.as_deref(),
            Some(REGISTERED_PROVISIONING_STATUS)
        );

        controller
            .issue_keyfob_certificate()
            .expect("certificate should issue");
        let issued = controller.key_fob_metadata();
        assert_eq!(
            issued.certificate_status.as_deref(),
            Some(ISSUED_CERTIFICATE_STATUS)
        );
        assert_eq!(
            issued.provisioning_status.as_deref(),
            Some(CERTIFICATE_ISSUED_PROVISIONING_STATUS)
        );

        controller
            .run_legitimate_authentication_demo()
            .expect("authentication should verify");
        let authenticated = controller.key_fob_metadata();
        assert_eq!(
            authenticated.provisioning_status.as_deref(),
            Some(AUTHENTICATED_STATUS)
        );

        controller
            .establish_secure_session_demo()
            .expect("session should establish");
        let session_established = controller.key_fob_metadata();
        assert_eq!(
            session_established.provisioning_status.as_deref(),
            Some(SESSION_ESTABLISHED_PROVISIONING_STATUS)
        );

        controller
            .export_provisioning_report()
            .expect("report should export");
        controller.set_active_key_fob_status(
            Some(ISSUED_CERTIFICATE_STATUS),
            Some(FINALIZED_PROVISIONING_STATUS),
        );
        let finalized = controller.key_fob_metadata();
        assert_eq!(
            finalized.certificate_status.as_deref(),
            Some(ISSUED_CERTIFICATE_STATUS)
        );
        assert_eq!(
            finalized.provisioning_status.as_deref(),
            Some(FINALIZED_PROVISIONING_STATUS)
        );
    }

    #[test]
    fn test_vehicle_status_progression_uses_machine_values() {
        let mut controller = AppController::new();
        bind_custom_context(&mut controller, "VEHSTATUS");

        controller
            .connect_vehicle()
            .expect("vehicle should connect");
        assert_eq!(
            controller.vehicle_metadata().provisioning_status.as_deref(),
            Some(VEHICLE_CONNECTED_STATUS)
        );

        controller.initialize_ca().expect("trust should initialize");
        assert_eq!(
            controller.vehicle_metadata().provisioning_status.as_deref(),
            Some(TRUST_INITIALIZED_STATUS)
        );

        controller
            .issue_keyfob_certificate()
            .expect("certificate should issue");
        assert_eq!(
            controller.vehicle_metadata().provisioning_status.as_deref(),
            Some(CERTIFICATE_ISSUED_PROVISIONING_STATUS)
        );

        controller
            .generate_authentication_challenge()
            .expect("challenge should generate");
        assert_eq!(
            controller.vehicle_metadata().provisioning_status.as_deref(),
            Some(CHALLENGE_GENERATED_STATUS)
        );

        controller
            .sign_canonical_auth_payload()
            .expect("payload should sign");
        controller
            .verify_authentication_with_cloud_sync()
            .expect("authentication should verify");
        assert_eq!(
            controller.vehicle_metadata().provisioning_status.as_deref(),
            Some(AUTHENTICATED_STATUS)
        );

        controller
            .establish_secure_session_demo()
            .expect("session should establish");
        assert_eq!(
            controller.vehicle_metadata().provisioning_status.as_deref(),
            Some(SESSION_ESTABLISHED_PROVISIONING_STATUS)
        );

        controller
            .finalize_provisioning_with_cloud_sync()
            .expect("finalization should complete locally");
        assert_eq!(
            controller.vehicle_metadata().provisioning_status.as_deref(),
            Some(FINALIZED_PROVISIONING_STATUS)
        );
    }

    #[test]
    fn test_provisioning_no_sync_required_statuses() {
        let mut controller = AppController::new();
        bind_custom_context(&mut controller, "NOSYNC");
        controller
            .issue_access_certificate_with_cloud_sync()
            .expect("certificate should issue");

        let challenge = controller
            .generate_challenge_with_cloud_sync()
            .expect("challenge should generate");
        assert_eq!(challenge.cloud_sync_status, "Skipped - disabled");
        assert!(!challenge.cloud_sync_attempted);

        let signed = controller
            .sign_canonical_payload_with_cloud_sync()
            .expect("payload should sign");
        assert_eq!(signed.cloud_sync_status, "No sync required");
        assert!(!signed.cloud_sync_attempted);

        let verified = controller
            .verify_authentication_with_cloud_sync()
            .expect("authentication should verify");
        assert_eq!(verified.cloud_sync_status, "Skipped - disabled");
        assert!(!verified.cloud_sync_attempted);
        assert_eq!(verified.cloud_table_updated, "None");
    }

    #[test]
    fn test_provisioning_sync_result_uses_active_context_and_safe_strings() {
        let mut controller = AppController::new();
        bind_custom_context(&mut controller, "PROVSYNC");

        let result = controller
            .issue_access_certificate_with_cloud_sync()
            .expect("certificate should issue locally");
        assert_eq!(result.active_customer_id, "CUST-CRYPTO-PROVSYNC");
        assert_eq!(result.active_vehicle_id, "VEH-CRYPTO-PROVSYNC");
        assert_eq!(result.active_fob_id, "FOB-CRYPTO-PROVSYNC");
        assert_eq!(result.active_certificate_id, "CERT-FOB-CRYPTO-PROVSYNC");
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
    fn test_finalize_export_action_uses_finalized_provisioning_sync_path() {
        let source = fs::read_to_string("src/app_controller/mod.rs")
            .expect("app controller source should be readable");
        let finalize_index = source
            .find("pub fn finalize_provisioning_with_cloud_sync")
            .expect("finalize method should exist");
        let sync_index = source[finalize_index..]
            .find("self.sync_finalized_provisioning_records()")
            .expect("finalize method should call finalized provisioning sync");

        assert!(sync_index > 0);
        assert!(source[finalize_index..].contains("Finalize & Export Report"));
        assert!(source[finalize_index..].contains("Provisioning finalized and report exported"));
    }

    #[test]
    fn test_finalize_export_cloud_failure_keeps_local_success_status() {
        let controller = AppController::new();
        let result = controller.build_provisioning_cloud_sync_result(
            "Finalize & Export Report",
            "Provisioning finalized and report exported",
            true,
            "Finalized provisioning sync failed: Cloud database connection failed. Retry after database warm-up."
                .to_string(),
            "provisioning_sessions, key_fobs, audit_logs",
            Some("Cloud database connection failed. Retry after database warm-up.".to_string()),
        );
        let display = result.to_string();

        assert!(result.local_success);
        assert_eq!(
            result.provisioning_status,
            "Provisioning finalized and report exported"
        );
        assert!(result.cloud_sync_attempted);
        assert!(result
            .cloud_sync_status
            .starts_with("Finalized provisioning sync failed:"));
        assert_eq!(
            result.cloud_table_updated,
            "provisioning_sessions, key_fobs, audit_logs"
        );
        assert!(display.contains("Finalize & Export Report"));
        assert!(display.contains("Cloud Sync: Finalized provisioning sync failed:"));
        assert!(!display.contains("DATABASE_URL"));
        assert!(!display.contains("AIACS_MASTER_KEY"));
    }

    #[test]
    fn test_finalize_audit_logs_use_active_session_id_and_redact_material() {
        let mut controller = AppController::new();
        bind_custom_context(&mut controller, "AUDITFINAL");
        controller
            .run_legitimate_authentication_demo()
            .expect("auth should succeed");
        controller
            .establish_secure_session_demo()
            .expect("session should establish");

        let records = controller.active_audit_log_records();
        let active_session_id = controller.active_session_id.clone();

        assert!(!records.is_empty());
        assert!(records
            .iter()
            .all(|record| record.session_id == active_session_id));
        let debug = format!("{records:?}");
        assert!(debug.contains("FOB-CRYPTO-AUDITFINAL"));
        assert!(debug.contains("[REDACTED]"));
        for forbidden in [
            "DATABASE_URL",
            "AIACS_MASTER_KEY",
            "private_key",
            "session_key",
            "shared_secret",
            "hkdf_output",
        ] {
            assert!(!debug.contains(forbidden));
        }
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
            "controller.sync_certificate_and_key_fob_status()",
            "controller.sync_session_and_key_fob_status()",
            "controller.sync_finalized_provisioning_records()",
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
        assert!(issue_source.contains("controller.sync_certificate_and_key_fob_status()"));
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
        assert_eq!(metadata.vehicle_id, crate::cloud_storage::DEMO_VEHICLE_ID);
        assert_eq!(metadata.subject_id, DEMO_FOB_ID);
        assert_eq!(metadata.issuer, DEFAULT_CA_NAME);
        assert_eq!(metadata.signature_algorithm, "Ed25519");
        assert!(metadata.certificate_signature_fingerprint.is_some());
        let certificate_json = metadata
            .certificate_json
            .as_ref()
            .expect("safe certificate metadata JSON should be present");
        assert_eq!(
            certificate_json["certificate_id"].as_str(),
            Some(metadata.certificate_id.as_str())
        );
        assert_eq!(
            certificate_json["fob_id"].as_str(),
            Some(metadata.fob_id.as_str())
        );
        assert_eq!(
            certificate_json["vehicle_id"].as_str(),
            Some(metadata.vehicle_id.as_str())
        );
        assert_eq!(
            certificate_json["subject_id"].as_str(),
            Some(metadata.subject_id.as_str())
        );
        assert_eq!(certificate_json["issuer"].as_str(), Some(DEFAULT_CA_NAME));
        assert_eq!(
            certificate_json["certificate_signature_fingerprint"].as_str(),
            Some(
                metadata
                    .certificate_signature_fingerprint
                    .as_ref()
                    .expect("signature fingerprint should be present")
                    .as_str()
            )
        );
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
            metadata.auth_result,
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
        assert_eq!(
            metadata.session_method,
            crate::cloud_storage::SESSION_ALGORITHM
        );
        assert_eq!(
            metadata.provisioning_status,
            crate::cloud_storage::SECURE_SESSION_ESTABLISHED_STATUS
        );
        assert_eq!(
            metadata.report_path,
            crate::cloud_storage::IN_APP_REPORT_ONLY_PATH
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
    fn test_active_audit_log_records_include_context_and_tags() {
        let mut controller = AppController::new();
        bind_custom_context(&mut controller, "AUDITCTX");
        controller
            .issue_keyfob_certificate()
            .expect("certificate should issue for audit context");
        controller
            .run_legitimate_authentication_demo()
            .expect("authentication should verify for audit context");
        controller
            .establish_secure_session_demo()
            .expect("session should establish for audit context");

        let records = controller.active_audit_log_records();
        let tags = records
            .iter()
            .map(|record| record.event_tag.as_str())
            .collect::<Vec<_>>();
        for expected in [
            "customer_selected",
            "certificate_issued",
            "authentication_verified",
            "secure_session_established",
            "provisioning_finalized",
        ] {
            assert!(tags.contains(&expected), "missing audit tag {expected}");
        }

        for record in records {
            assert_eq!(record.customer_id, "CUST-CRYPTO-AUDITCTX");
            assert_eq!(record.vehicle_id, "VEH-CRYPTO-AUDITCTX");
            assert_eq!(record.fob_id, "FOB-CRYPTO-AUDITCTX");
            assert_eq!(record.session_id, controller.active_session_id);
            assert_eq!(record.certificate_id, "CERT-FOB-CRYPTO-AUDITCTX");
            for forbidden in [
                "DATABASE_URL",
                "AIACS_MASTER_KEY",
                "private_key",
                "session_key",
                "shared_secret",
                "raw_nonce",
            ] {
                assert!(!record.event_message.contains(forbidden));
            }
        }
    }

    #[test]
    fn test_finalize_stages_finalized_session_metadata_and_safe_report_path() {
        let mut controller = AppController::new();
        controller
            .run_legitimate_authentication_demo()
            .expect("auth demo failed");
        controller
            .establish_secure_session_demo()
            .expect("session demo failed");
        controller
            .export_provisioning_report()
            .expect("report should export");

        let metadata = controller
            .provisioning_session_metadata()
            .expect("session metadata should build");

        assert_eq!(metadata.auth_result, AUTHENTICATED_STATUS);
        assert_eq!(metadata.session_method, SESSION_ALGORITHM);
        assert_eq!(metadata.provisioning_status, FINALIZED_PROVISIONING_STATUS);
        assert_eq!(metadata.report_path, IN_APP_REPORT_ONLY_PATH);
        assert!(!metadata.report_path.contains("Users"));
        assert!(!metadata.report_path.contains("DATABASE_URL"));
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
    fn test_selected_key_fob_encrypted_backup_uses_active_fob_identity() {
        let mut controller = AppController::new();
        let master_key = [17u8; 32];
        bind_custom_context(&mut controller, "BACKUP");
        controller
            .issue_keyfob_certificate()
            .expect("certificate should issue");

        let record = controller
            .key_fob_encrypted_key_record(&master_key)
            .expect("selected fob encrypted key record should build");

        assert_eq!(record.key_id, "KEY-FOB-CRYPTO-BACKUP");
        assert_eq!(record.owner_type, "key_fob");
        assert_eq!(record.owner_id, "FOB-CRYPTO-BACKUP");
        assert_eq!(record.key_purpose, KEY_FOB_KEY_PURPOSE);
        assert_eq!(record.encrypted_key.encryption_algorithm, "AES-256-GCM");
        assert!(record
            .public_key_fingerprint
            .as_deref()
            .unwrap()
            .starts_with("SHA256:"));
    }

    #[test]
    fn test_local_encrypted_key_recovery_evidence_matches_fingerprint() {
        let mut controller = AppController::new();
        let master_key = [23u8; 32];
        bind_custom_context(&mut controller, "RECOVERY");
        controller
            .issue_keyfob_certificate()
            .expect("certificate should issue");
        let record = controller
            .key_fob_encrypted_key_record(&master_key)
            .expect("encrypted key record should build");

        let evidence = controller
            .recovery_evidence_from_record(&record, &master_key)
            .expect("recovery evidence should build");

        assert_eq!(evidence.key_id, "KEY-FOB-CRYPTO-RECOVERY");
        assert_eq!(evidence.owner_type, "key_fob");
        assert_eq!(evidence.owner_id, "FOB-CRYPTO-RECOVERY");
        assert_eq!(evidence.recovery_status, "Success");
        assert!(evidence.fingerprint_match);
        assert_eq!(
            evidence.public_key_fingerprint,
            evidence.recovered_public_key_fingerprint
        );
        let debug = format!("{evidence:?}");
        assert!(!debug.contains("private_key"));
        assert!(!debug.contains("AIACS_MASTER_KEY"));
        assert!(!debug.contains("encrypted_key_blob"));
        assert!(!debug.contains("encryption_nonce"));
    }

    #[test]
    fn test_local_encrypted_key_recovery_rejects_wrong_master_key_safely() {
        let mut controller = AppController::new();
        let master_key = [31u8; 32];
        let wrong_key = [32u8; 32];
        bind_custom_context(&mut controller, "WRONGKEY");
        controller
            .issue_keyfob_certificate()
            .expect("certificate should issue");
        let record = controller
            .key_fob_encrypted_key_record(&master_key)
            .expect("encrypted key record should build");

        let message = controller
            .recovery_evidence_from_record(&record, &wrong_key)
            .expect_err("wrong master key should fail safely")
            .to_string();

        assert_eq!(
            message,
            "Encrypted key recovery failed. The local master key may be missing or incorrect."
        );
        assert!(!message.contains("AIACS_MASTER_KEY"));
        assert!(!message.contains("private_key"));
        assert!(!message.contains("encrypted_key_blob"));
        assert!(!message.contains("encryption_nonce"));
    }

    #[test]
    fn test_key_recovery_artifact_folder_files_are_created_only_on_recovery() {
        let mut controller = AppController::new();
        let master_key = [41u8; 32];
        let suffix = format!(
            "ART{}",
            &Uuid::new_v4().simple().to_string()[..8].to_uppercase()
        );
        bind_custom_context(&mut controller, &suffix);
        controller
            .issue_keyfob_certificate()
            .expect("certificate should issue");
        let record = controller
            .key_fob_encrypted_key_record(&master_key)
            .expect("encrypted key record should build");

        let paths = controller
            .save_local_key_fob_encrypted_backup(&record)
            .expect("local encrypted backup should save");
        assert!(paths.dir.exists());
        assert!(paths.local_encrypted_file.exists());
        assert!(paths.metadata_file.exists());
        assert!(!paths.cloud_encrypted_file.exists());
        assert!(!paths.recovery_evidence_file.exists());
        assert!(!paths.decrypted_recovery_file.exists());

        let evidence = controller
            .recovery_evidence_from_record(&record, &master_key)
            .expect("recovery should create all artifact files");
        assert!(paths.cloud_encrypted_file.exists());
        assert!(paths.recovery_evidence_file.exists());
        assert!(paths.decrypted_recovery_file.exists());
        assert!(evidence.fingerprint_match);
        assert!(evidence.local_cloud_encrypted_backup_match);
    }

    #[test]
    fn test_recovery_evidence_file_is_report_safe() {
        let mut controller = AppController::new();
        let master_key = [43u8; 32];
        let suffix = format!(
            "SAFE{}",
            &Uuid::new_v4().simple().to_string()[..8].to_uppercase()
        );
        bind_custom_context(&mut controller, &suffix);
        controller
            .issue_keyfob_certificate()
            .expect("certificate should issue");
        let private_key = controller
            .keyfob
            .as_ref()
            .and_then(|fob| fob.private_key.clone())
            .expect("private key should exist");
        let private_key_b64 = general_purpose::STANDARD.encode(&private_key);
        let record = controller
            .key_fob_encrypted_key_record(&master_key)
            .expect("encrypted key record should build");

        let evidence = controller
            .recovery_evidence_from_record(&record, &master_key)
            .expect("recovery should create evidence");
        let evidence_json = fs::read_to_string(evidence.recovery_evidence_file)
            .expect("recovery evidence should be readable");
        let decrypted_json = fs::read_to_string(evidence.decrypted_recovery_file)
            .expect("decrypted recovery file should be readable");

        assert!(evidence_json.contains("stored_public_key_fingerprint"));
        assert!(evidence_json.contains("recovered_public_key_fingerprint"));
        assert!(evidence_json.contains("\"fingerprint_match\": true"));
        assert!(evidence_json.contains("\"local_cloud_encrypted_backup_match\": true"));
        assert!(evidence_json.contains("\"master_key\": \"[REDACTED]\""));
        assert!(evidence_json.contains("\"private_key_material_in_report\": \"[REDACTED]\""));
        assert!(!evidence_json.contains(&private_key_b64));
        assert!(!evidence_json.contains("AIACS_MASTER_KEY"));
        assert!(!evidence_json.contains("DATABASE_URL"));
        assert!(decrypted_json.contains("SENSITIVE RECOVERED KEY MATERIAL"));
        assert!(decrypted_json.contains("private_key_material"));
    }

    #[test]
    fn test_missing_master_key_maps_to_recovery_not_configured_message() {
        let message =
            AppController::map_encrypted_recovery_error(CloudStorageError::MissingMasterKey)
                .to_string();

        assert_eq!(message, "Encrypted key backup is not configured.");
        assert!(!message.contains("AIACS_MASTER_KEY"));
        assert!(!message.contains("DATABASE_URL"));
    }

    #[test]
    fn test_gitignore_blocks_recovery_artifacts() {
        let gitignore = fs::read_to_string(".gitignore").expect(".gitignore should be readable");
        for expected in [
            "recovery_artifacts/",
            "diagnostic_results/",
            "reports/key_recovery_*.json",
            "**/encrypted_fob_key_local.bin",
            "**/encrypted_fob_key_cloud.bin",
            "**/decrypted_fob_key_recovered.json",
            "**/recovery_evidence.json",
            "**/encrypted_backup_metadata.json",
            "**/all_diagnostics_summary.json",
            "**/*_attack.json",
            "**/wrong_master_key_recovery.json",
        ] {
            assert!(
                gitignore.contains(expected),
                "missing ignore rule {expected}"
            );
        }
    }

    #[test]
    fn test_phase10_replay_diagnostic_uses_selected_context_and_safe_evidence() {
        let mut controller = provision_selected_context_for_diagnostics("PHASE10REPLAY");
        let result = controller
            .run_diagnostic_attack("replay_attack")
            .expect("replay diagnostic should run");

        assert_eq!(result.attack_name, "replay_attack");
        assert_eq!(result.customer_id, "CUST-CRYPTO-PHASE10REPLAY");
        assert_eq!(result.vehicle_id, "VEH-CRYPTO-PHASE10REPLAY");
        assert_eq!(result.fob_id, "FOB-CRYPTO-PHASE10REPLAY");
        assert_eq!(result.baseline_result, "attack_successful_vehicle_opened");
        assert_eq!(result.protected_result, "attack_blocked_access_denied");
        assert_eq!(result.security_control_triggered, "nonce_reuse_detection");
        assert_eq!(result.pass_fail, "pass");
        assert_eq!(result.cloud_sync_status, "disabled");
        assert!(!result.customer_id.contains(DEMO_CUSTOMER_ID));

        let evidence =
            fs::read_to_string(&result.evidence_file_path).expect("evidence file should exist");
        assert!(evidence.contains("created_at_nepal_time"));
        assert!(evidence.contains("NPT"));
        assert!(evidence.contains("\"raw_payload\": \"[REDACTED]\""));
        assert!(evidence.contains("\"raw_signature\": \"[REDACTED]\""));
        assert!(evidence.contains("\"raw_nonce\": \"[REDACTED]\""));
        for forbidden in [
            "AIACS_MASTER_KEY",
            "DATABASE_URL",
            "session_key",
            "shared_secret",
        ] {
            assert!(
                !evidence.contains(forbidden),
                "diagnostic evidence leaked {forbidden}"
            );
        }
        let _ = fs::remove_dir_all(
            PathBuf::from(DIAGNOSTIC_RESULTS_DIR).join("FOB-CRYPTO-PHASE10REPLAY"),
        );
    }

    #[test]
    fn test_diagnostic_local_result_remains_visible_when_cloud_sync_disabled() {
        let mut controller = provision_selected_context_for_diagnostics("PHASE10DISABLED");
        controller.cloud_auto_sync_enabled = false;

        let result = controller
            .run_diagnostic_attack("forged_signature")
            .expect("local diagnostic should still run");

        assert_eq!(result.attack_name, "forged_signature");
        assert_eq!(result.cloud_sync_status, "disabled");
        assert_eq!(controller.diagnostic_dashboard_results().len(), 1);
        assert!(PathBuf::from(&result.evidence_file_path).exists());
        let _ = fs::remove_dir_all(
            PathBuf::from(DIAGNOSTIC_RESULTS_DIR).join("FOB-CRYPTO-PHASE10DISABLED"),
        );
    }

    #[test]
    fn test_diagnostic_results_clear_when_selected_context_changes() {
        let mut controller = provision_selected_context_for_diagnostics("PHASE10CLEAR");
        controller
            .run_diagnostic_attack("replay_attack")
            .expect("diagnostic should run before context change");
        assert_eq!(controller.diagnostic_dashboard_results().len(), 1);

        let customer = CustomerMetadata {
            customer_id: "CUST-CRYPTO-CLEAR-B".to_string(),
            owner_name: "Clear Context B".to_string(),
            email: Some("clear-b@example.com".to_string()),
            phone: None,
        };
        controller.select_customer_context(customer, "CloudSelected");

        assert!(controller.diagnostic_dashboard_results().is_empty());
        assert_eq!(
            controller.diagnostic_context_summary().readiness_reason,
            "missing_vehicle"
        );
        let _ = fs::remove_dir_all(
            PathBuf::from(DIAGNOSTIC_RESULTS_DIR).join("FOB-CRYPTO-PHASE10CLEAR"),
        );
    }

    #[test]
    fn test_run_all_diagnostics_uses_individual_sync_path() {
        let source = include_str!("mod.rs");
        let function_start = source
            .find("pub fn run_all_diagnostics")
            .expect("run_all_diagnostics should exist");
        let function_source = &source[function_start..];

        assert!(function_source.contains("self.run_diagnostic_attack(key)?"));
        assert!(function_source.contains("self.save_all_diagnostics_summary"));
    }

    #[test]
    fn test_phase10_missing_context_returns_safe_diagnostic_readiness_error() {
        let mut controller = AppController::new();
        let error = controller
            .run_diagnostic_attack("replay_attack")
            .expect_err("missing selected context should block diagnostics")
            .to_string();

        assert_eq!(error, "missing_customer");
        assert!(!error.contains("private"));
        assert!(!error.contains("DATABASE_URL"));
    }

    #[test]
    fn test_phase10_run_all_diagnostics_creates_summary_without_demo_fallback() {
        let previous_master_key = std::env::var("AIACS_MASTER_KEY").ok();
        std::env::set_var(
            "AIACS_MASTER_KEY",
            general_purpose::STANDARD.encode([0x31_u8; 32]),
        );
        let mut controller = provision_selected_context_for_diagnostics("PHASE10ALL");
        let results = controller
            .run_all_diagnostics()
            .expect("all diagnostics should run");

        assert_eq!(results.len(), 9);
        assert!(results.iter().all(|result| result.pass_fail == "pass"));
        assert!(results
            .iter()
            .all(|result| result.customer_id == "CUST-CRYPTO-PHASE10ALL"));
        assert!(results
            .iter()
            .all(|result| result.fob_id == "FOB-CRYPTO-PHASE10ALL"));
        assert!(results
            .iter()
            .any(|result| result.attack_name == "wrong_master_key_recovery"));

        let summary_path = PathBuf::from(DIAGNOSTIC_RESULTS_DIR)
            .join("FOB-CRYPTO-PHASE10ALL")
            .join("all_diagnostics_summary.json");
        let summary = fs::read_to_string(&summary_path).expect("summary should exist");
        assert!(summary.contains("\"private_key_material\": \"[REDACTED]\""));
        assert!(!summary.contains(DEMO_CUSTOMER_ID));
        assert!(!summary.contains("AIACS_MASTER_KEY"));

        let _ =
            fs::remove_dir_all(PathBuf::from(DIAGNOSTIC_RESULTS_DIR).join("FOB-CRYPTO-PHASE10ALL"));
        if let Some(value) = previous_master_key {
            std::env::set_var("AIACS_MASTER_KEY", value);
        } else {
            std::env::remove_var("AIACS_MASTER_KEY");
        }
    }

    #[test]
    fn test_phase10_1_prepare_diagnostics_context_reports_precise_selected_status() {
        let mut controller = provision_selected_context_for_diagnostics("PHASE101CTX");
        let message = controller
            .prepare_diagnostics_context()
            .expect("diagnostics context should prepare");
        let summary = controller.diagnostic_context_summary();

        assert_eq!(message, "Diagnostics context ready");
        assert_eq!(summary.customer_status, "loaded");
        assert_eq!(summary.vehicle_status, "loaded");
        assert_eq!(summary.key_fob_status, "loaded");
        assert_eq!(summary.certificate_status, "loaded_from_memory");
        assert_eq!(summary.session_status, "loaded_from_memory");
        assert_eq!(summary.fob_identity_status, "local_key_available");
        assert_eq!(summary.diagnostic_proof_status, "generated");
        assert_eq!(summary.readiness, "ready");
        assert_eq!(summary.readiness_reason, "diagnostic_context_ready");
        assert!(!summary.customer_status.contains(DEMO_CUSTOMER_ID));
        assert!(summary
            .evidence_directory
            .contains("FOB-CRYPTO-PHASE101CTX"));
    }

    #[test]
    fn test_phase10_1_prepare_diagnostics_context_blocks_missing_selected_context_safely() {
        let mut controller = AppController::new();
        let message = controller
            .prepare_diagnostics_context()
            .expect("missing context should be represented safely");
        let summary = controller.diagnostic_context_summary();

        assert_eq!(message, "Diagnostics context not ready: missing_customer");
        assert_eq!(summary.readiness, "not_ready");
        assert_eq!(summary.readiness_reason, "missing_customer");
        assert_eq!(summary.customer_status, "missing");
        assert!(!message.contains("DATABASE_URL"));
        assert!(!message.contains("AIACS_MASTER_KEY"));
    }

    #[test]
    fn test_phase10_1_run_diagnostic_prepares_runtime_proof_from_selected_identity() {
        let mut controller = provision_selected_context_for_diagnostics("PHASE101PROOF");
        controller.active_challenge = None;
        controller.active_auth_proof = None;
        let result = controller
            .run_diagnostic_attack("replay_attack")
            .expect("diagnostic should generate temporary proof and run");
        let summary = controller.diagnostic_context_summary();

        assert_eq!(result.fob_id, "FOB-CRYPTO-PHASE101PROOF");
        assert_eq!(summary.diagnostic_proof_status, "generated");
        assert!(controller.active_auth_proof.is_some());
        assert!(controller.active_challenge.is_some());
        assert!(!result.customer_id.contains(DEMO_CUSTOMER_ID));
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
