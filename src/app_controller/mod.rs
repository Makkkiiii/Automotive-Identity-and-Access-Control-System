use crate::access::{AccessDecision, AccessDecisionEngine};
use crate::attacks::{AdversarialValidationEngine, AttackResult, AttackType};
use crate::auth::{AuthResult, AuthenticationEngine};
use crate::ca::{CAError, Certificate, CertificateAuthority};
use crate::keyfob::{DigitalKeyFob, KeyFobError};
use crate::session::{SessionState, SessionValidationEngine};
use crate::vehicle::{VehicleControlModule, VehicleError};
use std::fmt;

const DEFAULT_CA_NAME: &str = "AIACS-Demo-CA";
const DEFAULT_FOB_ID: &str = "FOB-GUI-001";
const DEFAULT_VEHICLE_ID: &str = "VEH-GUI-001";
const DEFAULT_SESSION_ID: &str = "SESSION-GUI-001";
const DEFAULT_TIMEOUT_SECONDS: i64 = 60;

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
            .finish()
    }
}

impl AppController {
    pub fn new() -> Self {
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
        }
    }

    pub fn initialize_ca(&mut self) -> Result<String, AppControllerError> {
        let mut ca = CertificateAuthority::new(DEFAULT_CA_NAME.to_string());
        ca.initialize()?;

        let message = format!("Certificate authority initialized: {}", ca.name);
        self.ca = Some(ca);
        self.log(message.clone());
        Ok(message)
    }

    pub fn issue_keyfob_certificate(&mut self) -> Result<String, AppControllerError> {
        if self.ca.is_none() {
            self.initialize_ca()?;
        }

        let ca = self.ca.as_ref().expect("CA initialized above");
        let mut keyfob = DigitalKeyFob::new(DEFAULT_FOB_ID.to_string());
        keyfob.initialize()?;
        keyfob.request_certificate(ca)?;

        let cert = Self::certificate_from_keyfob(&keyfob)?;
        let message = format!(
            "Certificate issued: subject {} by issuer {}",
            cert.subject_id, cert.issuer
        );

        self.keyfob = Some(keyfob);
        self.log(message.clone());
        Ok(message)
    }

    pub fn run_legitimate_authentication_demo(&mut self) -> Result<String, AppControllerError> {
        self.ensure_ready_for_authentication()?;

        let ca = self.ca.as_ref().expect("CA ready");
        let keyfob = self.keyfob.as_ref().expect("Key fob ready");

        let challenge =
            AuthenticationEngine::generate_challenge(&mut self.vehicle, DEFAULT_VEHICLE_ID)
                .map_err(|e| AppControllerError::Backend(e.to_string()))?;
        let proof = keyfob.create_auth_proof(DEFAULT_VEHICLE_ID, &challenge.nonce)?;
        let auth_result = AuthenticationEngine::verify_response(
            &proof,
            ca,
            &mut self.vehicle,
            DEFAULT_TIMEOUT_SECONDS,
        )
        .map_err(|e| AppControllerError::Backend(e.to_string()))?;

        let session = SessionValidationEngine::create_session(
            DEFAULT_SESSION_ID.to_string(),
            DEFAULT_VEHICLE_ID.to_string(),
            keyfob.subject_id.clone(),
            300,
        )?;
        let access_decision = AccessDecisionEngine::evaluate_access(auth_result, &session);

        self.session = Some(session);
        self.last_auth_result = Some(auth_result);
        self.last_access_decision = Some(access_decision);

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
            "Secure session established: {} for subject {}; key material lengths {:?}",
            DEFAULT_SESSION_ID, keyfob.subject_id, key_lengths
        );
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
        self.log(message.clone());
        Ok(message)
    }

    pub fn run_all_attacks(&mut self) -> Result<Vec<String>, AppControllerError> {
        let messages: Vec<String> = AdversarialValidationEngine::run_all_attacks()
            .iter()
            .map(Self::format_attack_result)
            .collect();

        for message in &messages {
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
        format!(
            "{}: {} ({})",
            result.attack_type, result.access_decision, result.explanation
        )
    }

    fn log(&mut self, message: String) {
        self.event_log.push(message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
