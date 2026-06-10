use aiacs::app_controller::{AppController, AppControllerError};
use chrono::Local;
use iced::alignment;
use iced::theme;
use iced::widget::{button, column, container, row, scrollable, text, Svg};
use iced::{
    application, Alignment, Background, Border, Color, Element, Font, Length, Sandbox, Settings,
    Theme,
};

const OWNER_NAME: &str = "Dennis Maharjan";
const CUSTOMER_ID: &str = "CUST-0001";
const CUSTOMER_EMAIL: &str = "dennis.m@example.com";
const CUSTOMER_PHONE: &str = "+977-9800000000";
const VEHICLE_DISPLAY_NAME: &str = "Nissan Magnite 2021";
const TECH_VEHICLE_ID: &str = "VEH-0001";
const VEHICLE_MAKE: &str = "Nissan";
const VEHICLE_MODEL: &str = "Magnite";
const VEHICLE_YEAR: &str = "2021";
const VEHICLE_VIN: &str = "VIN-DEMO-001";
const VEHICLE_REGISTRATION: &str = "BA-00-PA-0001";
const KEY_FOB_LABEL: &str = "Primary Key Fob";
const TECH_KEY_FOB_ID: &str = "FOB-0001";
const ICON_DIR: &str = "assets/icons";

const WINDOW_BG: Color = Color::from_rgb(0.105, 0.09, 0.11);
const STATUS_PANEL_BG: Color = Color::from_rgb(0.13, 0.112, 0.14);
const PANEL_BG: Color = Color::from_rgb(0.142, 0.126, 0.153);
const ELEVATED_BG: Color = Color::from_rgb(0.184, 0.16, 0.192);
const LOG_BG: Color = Color::from_rgb(0.102, 0.09, 0.106);
const BUTTON_BG: Color = Color::from_rgb(0.2, 0.17, 0.204);
const BUTTON_HOVER_BG: Color = Color::from_rgb(0.25, 0.212, 0.25);
const BORDER: Color = Color::from_rgb(0.294, 0.255, 0.298);
const BUTTON_BORDER: Color = Color::from_rgb(0.353, 0.294, 0.337);
const PRIMARY_TEXT: Color = Color::from_rgb(0.91, 0.847, 0.831);
const SECONDARY_TEXT: Color = Color::from_rgb(0.725, 0.659, 0.651);
const MUTED_TEXT: Color = Color::from_rgb(0.561, 0.498, 0.51);
const ACCENT_PINK: Color = Color::from_rgb(0.827, 0.525, 0.608);
const ACCENT_BLUE: Color = Color::from_rgb(0.49, 0.663, 0.847);
const SUCCESS_GREEN: Color = Color::from_rgb(0.655, 0.824, 0.553);
const WARNING_YELLOW: Color = Color::from_rgb(0.902, 0.765, 0.518);
const DANGER_RED: Color = Color::from_rgb(0.878, 0.424, 0.459);
const PENDING_BG: Color = Color::from_rgb(0.165, 0.153, 0.176);
const PENDING_BORDER: Color = Color::from_rgb(0.353, 0.325, 0.361);
const PENDING_TEXT: Color = Color::from_rgb(0.725, 0.659, 0.651);
const PENDING_DOT: Color = Color::from_rgb(0.561, 0.522, 0.533);
const AUDIT_SYNC_REDACTION_LINE: &str =
    "Sensitive material: [REDACTED] | Raw session key: [REDACTED] | Private key material: [REDACTED]";
const DIAGNOSTIC_SYNC_REDACTION_LINE: &str =
    "Sensitive material: [REDACTED] | Raw attack payloads: [REDACTED]";

pub fn main() -> iced::Result {
    AIACSApp::run(Settings::default())
}

struct AIACSApp {
    controller: AppController,
    status: SystemStatus,
    workflow_state: WorkflowState,
    management_state: ManagementState,
    selected_tab: MainTab,
    selected_artifact: ArtifactSection,
    cloud_status: String,
    last_metadata_sync_status: String,
    last_metadata_sync_time: String,
    last_certificate_sync_status: String,
    last_certificate_sync_time: String,
    last_provisioning_session_sync_status: String,
    last_provisioning_session_sync_time: String,
    last_audit_log_sync_status: String,
    last_audit_log_sync_time: String,
    last_diagnostic_result_sync_status: String,
    last_diagnostic_result_sync_time: String,
    last_encrypted_key_sync_status: String,
    last_encrypted_key_sync_time: String,
    selected_detail: String,
    event_log: Vec<String>,
}

#[derive(Debug, Clone)]
struct SystemStatus {
    top_badge: String,
    trust_status: String,
    key_fob_status: String,
    certificate_status: String,
    authentication_status: String,
    session_status: String,
    access_decision: String,
}

impl Default for SystemStatus {
    fn default() -> Self {
        Self {
            top_badge: "Not Initialized".to_string(),
            trust_status: "Not Initialized".to_string(),
            key_fob_status: "Not Registered".to_string(),
            certificate_status: "Not Issued".to_string(),
            authentication_status: "Not Run".to_string(),
            session_status: "Not Established".to_string(),
            access_decision: "N/A".to_string(),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct WorkflowState {
    vehicle_connected: bool,
    keyfob_detected: bool,
    keyfob_registered: bool,
    trust_initialized: bool,
    certificate_issued: bool,
    certificate_viewed: bool,
    challenge_generated: bool,
    payload_signed: bool,
    authentication_verified: bool,
    session_active: bool,
    report_exported: bool,
}

#[derive(Debug, Clone)]
struct ManagementState {
    customer_note: String,
    vehicle_note: String,
    keyfob_note: String,
}

impl Default for ManagementState {
    fn default() -> Self {
        Self {
            customer_note: "Demo customer selected".to_string(),
            vehicle_note: "Demo vehicle selected".to_string(),
            keyfob_note: "Primary key fob ready for provisioning".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MainTab {
    Dashboard,
    Customers,
    Vehicles,
    KeyFobs,
    Provisioning,
    ProtocolArtifacts,
    CredentialStorage,
    CloudStorage,
    LogsReport,
    Diagnostics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtifactSection {
    ChallengeMessage,
    AuthenticationProof,
    CertificateDetails,
    SessionSummary,
    AccessDecision,
}

#[derive(Debug, Clone)]
enum Message {
    SelectTab(MainTab),
    SelectArtifact(ArtifactSection),
    AddCustomer,
    SelectCustomer,
    EditCustomer,
    AddVehicle,
    SelectVehicle,
    LinkVehicleToOwner,
    RotateCredential,
    ConnectVehicle,
    DetectKeyFob,
    InitializeVehicleTrust,
    RegisterDigitalKeyFob,
    IssueCertificate,
    ViewCertificateDetails,
    GenerateChallenge,
    SignCanonicalPayload,
    VerifyAuthentication,
    ActivateSecureChannel,
    LaunchDiagnosticsTool,
    CheckCloudConnection,
    SyncCustomerMetadata,
    SyncVehicleMetadata,
    SyncKeyFobMetadata,
    SyncDemoMetadata,
    SyncCertificateMetadata,
    SyncProvisioningSession,
    SyncAuditLogs,
    SyncDiagnosticResults,
    SyncCaEncryptedKeyBlob,
    SyncKeyFobEncryptedKeyBlob,
    SyncEncryptedKeyBlobs,
    ClearLog,
    ExportLogs,
    ExportProvisioningReport,
}

impl Sandbox for AIACSApp {
    type Message = Message;

    fn new() -> Self {
        let mut controller = AppController::new();
        let initial_messages = [
            "AIACS provisioning console initialized",
            "Vehicle Access Provisioning Console ready",
            "Awaiting vehicle trust initialization",
            "Backend controller ready",
        ];
        for message in initial_messages {
            let _ = controller.save_log_entry("[INFO]", message);
        }

        Self {
            controller,
            status: SystemStatus::default(),
            workflow_state: WorkflowState::default(),
            management_state: ManagementState::default(),
            selected_tab: MainTab::Dashboard,
            selected_artifact: ArtifactSection::ChallengeMessage,
            cloud_status: "Disconnected".to_string(),
            last_metadata_sync_status: "Not synced".to_string(),
            last_metadata_sync_time: "N/A".to_string(),
            last_certificate_sync_status: "Not synced".to_string(),
            last_certificate_sync_time: "N/A".to_string(),
            last_provisioning_session_sync_status: "Ready".to_string(),
            last_provisioning_session_sync_time: "N/A".to_string(),
            last_audit_log_sync_status: "Ready".to_string(),
            last_audit_log_sync_time: "N/A".to_string(),
            last_diagnostic_result_sync_status: "Ready".to_string(),
            last_diagnostic_result_sync_time: "N/A".to_string(),
            last_encrypted_key_sync_status: "Not uploaded".to_string(),
            last_encrypted_key_sync_time: "N/A".to_string(),
            selected_detail: "Provisioning console ready. Initialize vehicle trust to begin."
                .to_string(),
            event_log: initial_messages
                .iter()
                .map(|message| timestamped("[INFO]", message))
                .collect(),
        }
    }

    fn title(&self) -> String {
        "AIACS - Vehicle Access Provisioning Console".to_string()
    }

    fn theme(&self) -> Theme {
        Theme::custom(
            "AIACS Dark".to_string(),
            theme::Palette {
                background: WINDOW_BG,
                text: PRIMARY_TEXT,
                primary: ACCENT_PINK,
                success: SUCCESS_GREEN,
                danger: DANGER_RED,
            },
        )
    }

    fn style(&self) -> theme::Application {
        theme::Application::custom(|_: &Theme| application::Appearance {
            background_color: WINDOW_BG,
            text_color: PRIMARY_TEXT,
        })
    }

    fn update(&mut self, message: Message) {
        match message {
            Message::SelectTab(tab) => {
                self.selected_tab = tab;
            }
            Message::SelectArtifact(section) => {
                self.selected_artifact = section;
            }
            Message::AddCustomer => {
                self.management_state.customer_note =
                    "Add Customer is staged as a GUI-only demo action.".to_string();
                self.selected_detail = self.management_state.customer_note.clone();
                self.push_log("[INFO]", "Customer add placeholder selected");
            }
            Message::SelectCustomer => {
                self.management_state.customer_note =
                    format!("Active customer selected: {}", OWNER_NAME);
                self.selected_detail = self.management_state.customer_note.clone();
                self.push_log("[INFO]", format!("Customer selected: {}", OWNER_NAME));
            }
            Message::EditCustomer => {
                self.management_state.customer_note =
                    "Edit Customer is staged as a GUI-only demo action.".to_string();
                self.selected_detail = self.management_state.customer_note.clone();
                self.push_log("[INFO]", "Customer edit placeholder selected");
            }
            Message::AddVehicle => {
                self.management_state.vehicle_note =
                    "Add Vehicle is staged as a GUI-only demo action.".to_string();
                self.selected_detail = self.management_state.vehicle_note.clone();
                self.push_log("[INFO]", "Vehicle add placeholder selected");
            }
            Message::SelectVehicle => {
                self.management_state.vehicle_note =
                    format!("Selected vehicle: {}", VEHICLE_DISPLAY_NAME);
                self.selected_detail = self.management_state.vehicle_note.clone();
                self.push_log(
                    "[INFO]",
                    format!("Vehicle selected: {}", VEHICLE_DISPLAY_NAME),
                );
            }
            Message::LinkVehicleToOwner => {
                self.management_state.vehicle_note =
                    format!("{} linked to {}", VEHICLE_DISPLAY_NAME, OWNER_NAME);
                self.selected_detail = self.management_state.vehicle_note.clone();
                self.push_log(
                    "[INFO]",
                    format!(
                        "Vehicle linked to owner: {} -> {}",
                        VEHICLE_DISPLAY_NAME, OWNER_NAME
                    ),
                );
            }
            Message::RotateCredential => {
                self.management_state.keyfob_note =
                    "Credential rotation is a placeholder; no keys were changed.".to_string();
                self.selected_detail = self.management_state.keyfob_note.clone();
                self.push_log("[INFO]", "Credential rotation placeholder selected");
            }
            Message::ConnectVehicle => match self.controller.connect_vehicle() {
                Ok(message) => {
                    self.workflow_state.vehicle_connected = true;
                    self.status.top_badge = "Vehicle Connected".to_string();
                    self.selected_detail = message.clone();
                    self.push_log("[INFO]", message);
                }
                Err(error) => {
                    self.selected_detail = format!("Vehicle connection failed: {}", error);
                    self.push_log("[ERROR]", format!("Vehicle connection failed: {}", error));
                }
            },
            Message::DetectKeyFob => match self.controller.detect_key_fob() {
                Ok(message) => {
                    self.workflow_state.keyfob_detected = true;
                    self.management_state.keyfob_note = format!("{} detected", KEY_FOB_LABEL);
                    self.selected_detail = message.clone();
                    self.push_log("[INFO]", message);
                }
                Err(error) => {
                    self.selected_detail = format!("Key fob detection failed: {}", error);
                    self.push_log("[ERROR]", format!("Key fob detection failed: {}", error));
                }
            },
            Message::InitializeVehicleTrust => match self.controller.initialize_ca() {
                Ok(message) => {
                    self.workflow_state.trust_initialized = true;
                    self.status.trust_status = "Initialized".to_string();
                    self.status.top_badge = "Trust Ready".to_string();
                    self.selected_detail = message.clone();
                    self.push_log("[INFO]", format!("Vehicle trust initialized: {}", message));
                }
                Err(error) => {
                    self.status.trust_status = "Error".to_string();
                    self.selected_detail =
                        format!("Vehicle trust initialization failed: {}", error);
                    self.push_log(
                        "[WARN]",
                        format!("Vehicle trust initialization failed: {}", error),
                    );
                }
            },
            Message::RegisterDigitalKeyFob => match self.controller.register_digital_key_fob() {
                Ok(message) => {
                    self.workflow_state.keyfob_registered = true;
                    self.management_state.keyfob_note = format!("{} registered", KEY_FOB_LABEL);
                    self.status.key_fob_status = "Registered".to_string();
                    self.status.top_badge = "Key Fob Registered".to_string();
                    self.selected_detail = message.clone();
                    self.push_log("[INFO]", format!("Digital key fob registered: {}", message));
                }
                Err(error) => {
                    self.status.key_fob_status = "Error".to_string();
                    self.selected_detail =
                        format!("Digital key fob registration failed: {}", error);
                    self.push_log(
                        "[WARN]",
                        format!("Digital key fob registration failed: {}", error),
                    );
                }
            },
            Message::IssueCertificate => match self.controller.issue_keyfob_certificate() {
                Ok(message) => {
                    self.workflow_state.trust_initialized = true;
                    self.workflow_state.keyfob_registered = true;
                    self.workflow_state.certificate_issued = true;
                    self.status.trust_status = "Initialized".to_string();
                    self.status.key_fob_status = "Registered".to_string();
                    self.status.certificate_status = "Issued".to_string();
                    self.status.top_badge = "Access Certificate Issued".to_string();
                    self.selected_detail = message.clone();
                    self.push_log("[INFO]", format!("Access certificate issued: {}", message));
                }
                Err(error) => {
                    self.status.certificate_status = "Error".to_string();
                    self.selected_detail = format!("Access certificate issuance failed: {}", error);
                    self.push_log(
                        "[WARN]",
                        format!("Access certificate issuance failed: {}", error),
                    );
                }
            },
            Message::ViewCertificateDetails => {
                self.workflow_state.certificate_viewed = true;
                self.management_state.keyfob_note =
                    "Certificate details available for selected key fob".to_string();
                self.selected_detail =
                    "Certificate details are shown in the Protocol Artifact Viewer.".to_string();
                self.push_log("[INFO]", "Certificate details viewed");
            }
            Message::GenerateChallenge => {
                self.workflow_state.challenge_generated = true;
                self.selected_detail =
                    "Challenge generation staged. Nonce material is redacted; safe hash appears after authentication verification."
                        .to_string();
                let _ = self
                    .controller
                    .append_protocol_trace("[AUTH]", "Operator staged: Generate Challenge");
                self.push_log("[AUTH]", "Generate Challenge staged");
            }
            Message::SignCanonicalPayload => {
                self.workflow_state.payload_signed = true;
                self.selected_detail =
                    "Canonical payload signing staged with Ed25519; private key remains [REDACTED]."
                        .to_string();
                let _ = self.controller.append_protocol_trace(
                    "[AUTH]",
                    "Operator staged: Sign Canonical Payload using Ed25519",
                );
                self.push_log("[AUTH]", "Canonical payload signing staged");
            }
            Message::VerifyAuthentication => {
                match self.controller.run_legitimate_authentication_demo() {
                    Ok(message) => {
                        self.workflow_state.trust_initialized = true;
                        self.workflow_state.keyfob_registered = true;
                        self.workflow_state.certificate_issued = true;
                        self.workflow_state.authentication_verified = true;
                        self.status.trust_status = "Initialized".to_string();
                        self.status.key_fob_status = "Registered".to_string();
                        self.status.certificate_status = "Issued".to_string();
                        self.status.authentication_status = "Verified".to_string();
                        self.status.access_decision = "Access Granted".to_string();
                        self.status.top_badge = "Key Verified".to_string();
                        self.selected_detail = message.clone();
                        self.push_log(
                            "[AUTH]",
                            format!("Key authentication verified: {}", message),
                        );
                    }
                    Err(error) => {
                        self.status.authentication_status = "Failed".to_string();
                        self.status.access_decision = "Error".to_string();
                        self.selected_detail = format!("Key authentication failed: {}", error);
                        self.push_log("[WARN]", format!("Key authentication failed: {}", error));
                    }
                }
            }
            Message::ActivateSecureChannel => {
                match self.controller.establish_secure_session_demo() {
                    Ok(_message) => {
                        self.workflow_state.trust_initialized = true;
                        self.workflow_state.keyfob_registered = true;
                        self.workflow_state.certificate_issued = true;
                        self.workflow_state.session_active = true;
                        self.status.trust_status = "Initialized".to_string();
                        self.status.key_fob_status = "Registered".to_string();
                        self.status.certificate_status = "Issued".to_string();
                        self.status.session_status = "Active".to_string();
                        self.status.top_badge = "Session Active".to_string();
                        self.selected_detail =
                            "Secure access session activated for the provisioned key fob."
                                .to_string();
                        self.push_log(
                            "[SESSION]",
                            "Secure access session activated for provisioned key fob",
                        );
                    }
                    Err(error) => {
                        self.status.session_status = "Error".to_string();
                        self.selected_detail =
                            format!("Secure session activation failed: {}", error);
                        self.push_log(
                            "[WARN]",
                            format!("Secure session activation failed: {}", error),
                        );
                    }
                }
            }
            Message::LaunchDiagnosticsTool => match self.controller.launch_diagnostics_tool() {
                Ok(message) => {
                    self.selected_detail = message.clone();
                    self.push_log("[INFO]", message);
                }
                Err(error) => {
                    self.selected_detail = format!("Diagnostics launch failed: {}", error);
                    self.push_log("[ERROR]", format!("Diagnostics launch failed: {}", error));
                }
            },
            Message::CheckCloudConnection => match self.controller.check_cloud_connection() {
                Ok(message) => {
                    self.cloud_status = "Connected".to_string();
                    self.selected_detail = message.clone();
                    self.push_log("[DB]", message);
                }
                Err(error) => {
                    self.cloud_status = "Error".to_string();
                    self.selected_detail = format!("Cloud connection check failed: {}", error);
                    self.push_log("[DB]", format!("Cloud connection check failed: {}", error));
                }
            },
            Message::SyncCustomerMetadata => match self.controller.sync_customer_metadata() {
                Ok(message) => {
                    self.record_metadata_sync(message.clone());
                    self.push_log("[DB]", format!("Customer metadata synced: {}", CUSTOMER_ID));
                }
                Err(error) => self.record_metadata_sync_error(error),
            },
            Message::SyncVehicleMetadata => match self.controller.sync_vehicle_metadata() {
                Ok(message) => {
                    self.record_metadata_sync(message.clone());
                    self.push_log(
                        "[DB]",
                        format!("Vehicle metadata synced: {}", VEHICLE_DISPLAY_NAME),
                    );
                }
                Err(error) => self.record_metadata_sync_error(error),
            },
            Message::SyncKeyFobMetadata => match self.controller.sync_key_fob_metadata() {
                Ok(message) => {
                    self.record_metadata_sync(message.clone());
                    self.push_log(
                        "[DB]",
                        format!("Key fob metadata synced: {}", KEY_FOB_LABEL),
                    );
                }
                Err(error) => self.record_metadata_sync_error(error),
            },
            Message::SyncDemoMetadata => match self.controller.sync_demo_cloud_metadata() {
                Ok(message) => {
                    self.record_metadata_sync(message.clone());
                    self.push_log("[DB]", "Demo metadata synced to company cloud database");
                }
                Err(error) => self.record_metadata_sync_error(error),
            },
            Message::SyncCertificateMetadata => match self.controller.sync_certificate_metadata() {
                Ok(message) => {
                    self.record_certificate_sync(message.clone());
                    self.push_log("[DB]", "Certificate metadata synced: CERT-FOB-0001");
                    self.push_log("[DB]", "Certificate private material: [REDACTED]");
                }
                Err(error) => self.record_certificate_sync_error(error),
            },
            Message::SyncProvisioningSession => {
                match self.controller.sync_provisioning_session_record() {
                    Ok(message) => {
                        self.record_provisioning_session_sync(message.clone());
                        self.push_log("[DB]", "Provisioning session synced: SESSION-0001");
                        self.push_log(
                            "[DB]",
                            "Session algorithm: X25519 + HKDF-SHA256 + AES-256-GCM",
                        );
                        self.push_log("[SECURITY]", "Raw session key: [REDACTED]");
                        self.push_log("[SECURITY]", "Shared secret: [REDACTED]");
                        self.push_log("[SECURITY]", "HKDF output: [REDACTED]");
                    }
                    Err(error) => self.record_provisioning_session_sync_error(error),
                }
            }
            Message::SyncAuditLogs => match self.controller.sync_audit_log_records() {
                Ok(message) => {
                    self.record_audit_log_sync(message.clone());
                    self.push_log("[DB]", "Audit log records synced");
                    self.push_log("[DB]", "Audit event synced: AUDIT-0001");
                    self.push_log("[DB]", "Audit event synced: AUDIT-0007");
                    self.push_log("[SECURITY]", "Sensitive audit material: [REDACTED]");
                }
                Err(error) => self.record_audit_log_sync_error(error),
            },
            Message::SyncDiagnosticResults => {
                match self.controller.sync_diagnostic_result_records() {
                    Ok(message) => {
                        self.record_diagnostic_result_sync(message.clone());
                        self.push_log("[DB]", "Diagnostic result records synced");
                        self.push_log("[DB]", "Diagnostic result synced: DIAG-REPLAY-0001");
                        self.push_log(
                            "[DB]",
                            "Diagnostic result synced: DIAG-WRONG-SESSION-KEY-0001",
                        );
                        self.push_log("[SECURITY]", "Raw attack payload material: [REDACTED]");
                    }
                    Err(error) => self.record_diagnostic_result_sync_error(error),
                }
            }
            Message::SyncCaEncryptedKeyBlob => match self.controller.sync_ca_encrypted_key_blob() {
                Ok(message) => {
                    self.record_encrypted_key_sync(message.clone());
                    self.push_log("[DB]", "CA encrypted key blob uploaded: KEY-CA-0001");
                    self.push_log("[DB]", "Raw private key material: [REDACTED]");
                    self.push_log(
                        "[DB]",
                        "Protection: Client-side AES-256-GCM encryption before upload",
                    );
                }
                Err(error) => self.record_encrypted_key_sync_error(error),
            },
            Message::SyncKeyFobEncryptedKeyBlob => {
                match self.controller.sync_key_fob_encrypted_key_blob() {
                    Ok(message) => {
                        self.record_encrypted_key_sync(message.clone());
                        self.push_log("[DB]", "Key fob encrypted key blob uploaded: KEY-FOB-0001");
                        self.push_log("[DB]", "Raw private key material: [REDACTED]");
                        self.push_log(
                            "[DB]",
                            "Protection: Client-side AES-256-GCM encryption before upload",
                        );
                    }
                    Err(error) => self.record_encrypted_key_sync_error(error),
                }
            }
            Message::SyncEncryptedKeyBlobs => match self.controller.sync_encrypted_key_blobs() {
                Ok(message) => {
                    self.record_encrypted_key_sync(message.clone());
                    self.push_log(
                        "[DB]",
                        "Encrypted key blobs synced to company cloud database",
                    );
                    self.push_log("[DB]", "Raw private key material: [REDACTED]");
                    self.push_log(
                        "[DB]",
                        "Protection: Client-side AES-256-GCM encryption before upload",
                    );
                }
                Err(error) => self.record_encrypted_key_sync_error(error),
            },
            Message::ClearLog => match self.controller.clear_logs() {
                Ok(message) => {
                    self.event_log.clear();
                    self.event_log.push(timestamped("[INFO]", message.as_str()));
                    self.selected_detail = message;
                }
                Err(error) => {
                    self.push_log("[ERROR]", format!("Clear Log failed: {}", error));
                    self.selected_detail = format!("Clear Log failed: {}", error);
                }
            },
            Message::ExportLogs => match self.controller.export_logs() {
                Ok(message) => {
                    self.selected_detail = message.clone();
                    self.push_log("[INFO]", message);
                }
                Err(error) => {
                    self.selected_detail = format!("Save / Export Logs failed: {}", error);
                    self.push_log("[ERROR]", format!("Save / Export Logs failed: {}", error));
                }
            },
            Message::ExportProvisioningReport => match self.controller.export_provisioning_report()
            {
                Ok(message) => {
                    self.workflow_state.report_exported = true;
                    self.selected_detail = message.clone();
                    self.push_log("[INFO]", message);
                }
                Err(error) => {
                    self.selected_detail = format!("Provisioning report export failed: {}", error);
                    self.push_log(
                        "[ERROR]",
                        format!("Provisioning report export failed: {}", error),
                    );
                }
            },
        }
    }

    fn view(&self) -> Element<'_, Message> {
        container(self.view_core_system())
            .width(Length::Fill)
            .height(Length::Fill)
            .padding(12)
            .style(container_style(PanelKind::Window))
            .into()
    }
}

impl AIACSApp {
    fn view_core_system(&self) -> Element<'_, Message> {
        column![
            self.view_core_header(),
            self.view_tab_bar(),
            self.view_selected_tab(),
        ]
        .spacing(10)
        .height(Length::Fill)
        .into()
    }

    fn view_tab_bar(&self) -> Element<'_, Message> {
        container(
            column![
                row![
                    tab_button("gear", "Dashboard", MainTab::Dashboard, self.selected_tab),
                    tab_button("auth", "Customers", MainTab::Customers, self.selected_tab),
                    tab_button("vehicle", "Vehicles", MainTab::Vehicles, self.selected_tab),
                    tab_button("key", "Key Fobs", MainTab::KeyFobs, self.selected_tab),
                    tab_button(
                        "shield",
                        "Provisioning",
                        MainTab::Provisioning,
                        self.selected_tab,
                    ),
                ]
                .spacing(8)
                .align_items(Alignment::Center),
                row![
                    tab_button(
                        "certificate",
                        "Protocol Artifacts",
                        MainTab::ProtocolArtifacts,
                        self.selected_tab,
                    ),
                    tab_button(
                        "key",
                        "Credential Storage",
                        MainTab::CredentialStorage,
                        self.selected_tab,
                    ),
                    tab_button(
                        "shield",
                        "Cloud Storage",
                        MainTab::CloudStorage,
                        self.selected_tab,
                    ),
                    tab_button(
                        "terminal",
                        "Logs / Report",
                        MainTab::LogsReport,
                        self.selected_tab,
                    ),
                    tab_button(
                        "diagnostics",
                        "Diagnostics",
                        MainTab::Diagnostics,
                        self.selected_tab,
                    ),
                ]
                .spacing(8)
                .align_items(Alignment::Center),
            ]
            .spacing(8),
        )
        .width(Length::Fill)
        .padding(8)
        .style(container_style(PanelKind::Panel))
        .into()
    }

    fn view_selected_tab(&self) -> Element<'_, Message> {
        match self.selected_tab {
            MainTab::Dashboard => self.view_dashboard_tab(),
            MainTab::Customers => self.view_customers_tab(),
            MainTab::Vehicles => self.view_vehicles_tab(),
            MainTab::KeyFobs => self.view_keyfobs_tab(),
            MainTab::Provisioning => self.view_provisioning_tab(),
            MainTab::ProtocolArtifacts => self.view_protocol_artifacts_tab(),
            MainTab::CredentialStorage => self.view_credential_storage_tab(),
            MainTab::CloudStorage => self.view_cloud_storage_tab(),
            MainTab::LogsReport => self.view_logs_report_tab(),
            MainTab::Diagnostics => self.view_diagnostics_tab(),
        }
    }

    fn view_provisioning_tab(&self) -> Element<'_, Message> {
        row![
            self.view_provisioning_context_panel(),
            self.view_workflow_panel(),
        ]
        .spacing(12)
        .height(Length::Fill)
        .into()
    }

    fn view_dashboard_tab(&self) -> Element<'_, Message> {
        let setup_status = if self.setup_complete() {
            "Complete"
        } else {
            "Provisioning In Progress"
        };

        column![
            row![
                self.dashboard_card("auth", "Active Customer", OWNER_NAME, "Dealer owner record"),
                self.dashboard_card(
                    "vehicle",
                    "Selected Vehicle",
                    VEHICLE_DISPLAY_NAME,
                    TECH_VEHICLE_ID,
                ),
                self.dashboard_card("key", "Registered Key Fob", KEY_FOB_LABEL, TECH_KEY_FOB_ID),
                self.dashboard_card(
                    "certificate",
                    "Certificate Status",
                    &self.status.certificate_status,
                    "Access certificate",
                ),
            ]
            .spacing(10),
            row![
                self.dashboard_card(
                    "verify-auth",
                    "Authentication Status",
                    &self.status.authentication_status,
                    "Challenge-response",
                ),
                self.dashboard_card(
                    "lock",
                    "Secure Session Status",
                    &self.status.session_status,
                    "Encrypted access channel",
                ),
                self.dashboard_card("decision", "Access Setup Status", setup_status, "Provisioning"),
                self.dashboard_card("terminal", "Recent Activity", &self.selected_detail, "Latest event"),
            ]
            .spacing(10),
            container(
                column![
                    text("Provisioning Console Overview")
                        .size(18)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(ACCENT_PINK)),
                    text("Use Customers, Vehicles, and Key Fobs to review dealer records, then complete access provisioning.")
                        .size(12)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(SECONDARY_TEXT)),
                    self.view_provisioning_summary_rows(),
                ]
                .spacing(10),
            )
            .width(Length::Fill)
            .height(Length::Fill)
            .padding(14)
            .style(container_style(PanelKind::Panel)),
        ]
        .spacing(10)
        .height(Length::Fill)
        .into()
    }

    fn view_customers_tab(&self) -> Element<'_, Message> {
        row![
            self.management_details_panel(
                "Customer / Owner",
                "Selected customer record used for access provisioning.",
                vec![
                    ("Owner Name", OWNER_NAME.to_string()),
                    ("Customer ID", CUSTOMER_ID.to_string()),
                    ("Email", CUSTOMER_EMAIL.to_string()),
                    ("Phone", CUSTOMER_PHONE.to_string()),
                    ("Assigned Vehicle", VEHICLE_DISPLAY_NAME.to_string()),
                    ("Provisioning Status", self.setup_status_label().to_string()),
                ],
            ),
            self.management_actions_panel(
                "Customer Actions",
                self.management_state.customer_note.as_str(),
                vec![
                    ("auth", "Add Customer", Message::AddCustomer),
                    ("auth", "Select Customer", Message::SelectCustomer),
                    ("auth", "Edit Customer", Message::EditCustomer),
                ],
            ),
        ]
        .spacing(10)
        .height(Length::Fill)
        .into()
    }

    fn view_vehicles_tab(&self) -> Element<'_, Message> {
        row![
            self.management_details_panel(
                "Vehicle",
                "Selected vehicle for dealer-side digital access setup.",
                vec![
                    ("Vehicle Name", VEHICLE_DISPLAY_NAME.to_string()),
                    ("Vehicle ID", TECH_VEHICLE_ID.to_string()),
                    ("Make", VEHICLE_MAKE.to_string()),
                    ("Model", VEHICLE_MODEL.to_string()),
                    ("Year", VEHICLE_YEAR.to_string()),
                    ("VIN", VEHICLE_VIN.to_string()),
                    ("Registration Number", VEHICLE_REGISTRATION.to_string()),
                    ("Assigned Owner", OWNER_NAME.to_string()),
                    ("Access Status", self.setup_status_label().to_string()),
                ],
            ),
            self.management_actions_panel(
                "Vehicle Actions",
                self.management_state.vehicle_note.as_str(),
                vec![
                    ("vehicle", "Add Vehicle", Message::AddVehicle),
                    ("vehicle", "Select Vehicle", Message::SelectVehicle),
                    (
                        "vehicle",
                        "Link Vehicle to Owner",
                        Message::LinkVehicleToOwner
                    ),
                ],
            ),
        ]
        .spacing(10)
        .height(Length::Fill)
        .into()
    }

    fn view_keyfobs_tab(&self) -> Element<'_, Message> {
        row![
            self.management_details_panel(
                "Digital Key Fob",
                "Selected fob credential used for vehicle access provisioning.",
                vec![
                    ("Fob Label", KEY_FOB_LABEL.to_string()),
                    ("Fob ID", TECH_KEY_FOB_ID.to_string()),
                    ("Assigned Vehicle", VEHICLE_DISPLAY_NAME.to_string()),
                    ("Assigned Owner", OWNER_NAME.to_string()),
                    ("Certificate Status", self.status.certificate_status.clone()),
                    (
                        "Public Key Fingerprint",
                        self.keyfob_public_key_fingerprint()
                    ),
                    ("Private Key", "[REDACTED]".to_string()),
                    (
                        "Credential Storage Status",
                        self.credential_storage_status().to_string()
                    ),
                ],
            ),
            self.management_actions_panel(
                "Key Fob Actions",
                self.management_state.keyfob_note.as_str(),
                vec![
                    ("key", "Detect Key Fob", Message::DetectKeyFob),
                    (
                        "register-key",
                        "Register Key Fob",
                        Message::RegisterDigitalKeyFob
                    ),
                    (
                        "certificate",
                        "View Certificate",
                        Message::ViewCertificateDetails
                    ),
                    (
                        "secure-session",
                        "Rotate Credential",
                        Message::RotateCredential
                    ),
                ],
            ),
        ]
        .spacing(10)
        .height(Length::Fill)
        .into()
    }

    fn view_core_header(&self) -> Element<'_, Message> {
        container(
            row![
                column![
                    text("AIACS")
                        .size(30)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(ACCENT_PINK)),
                    text("Vehicle Access Provisioning Console")
                        .size(13)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(SECONDARY_TEXT)),
                ]
                .spacing(2)
                .width(Length::Fill),
                status_badge(&self.status.top_badge),
            ]
            .spacing(12),
        )
        .width(Length::Fill)
        .padding(12)
        .style(container_style(PanelKind::Elevated))
        .into()
    }

    fn view_workflow_panel(&self) -> Element<'_, Message> {
        let workflow = column![
            text("Operator-controlled workflow for provisioning a buyer's digital key fob.")
                .size(12)
                .font(Font::MONOSPACE)
                .style(theme::Text::Color(SECONDARY_TEXT)),
            self.workflow_group(
                "A. Vehicle Connection",
                "Connect the vehicle endpoint before provisioning starts.",
                column![self.workflow_step_card(WorkflowStep {
                    icon_name: "vehicle",
                    title: "Connect Vehicle",
                    description: "Connect the selected Nissan Magnite using AIACS_AUTH_V1.",
                    status: self.completed_status(
                        self.workflow_state.vehicle_connected,
                        "Connected",
                        false,
                    ),
                    button_label: "Connect Vehicle",
                    message: Message::ConnectVehicle,
                })]
                .spacing(6),
            ),
            self.workflow_group(
                "B. Key Fob Registration",
                "Detect the buyer's fob and register its local credential identity.",
                column![
                    self.workflow_step_card(WorkflowStep {
                        icon_name: "key",
                        title: "Detect Key Fob",
                        description:
                            "Detect the primary key fob and prepare credential registration.",
                        status: self.completed_status(
                            self.workflow_state.keyfob_detected,
                            "Detected",
                            false,
                        ),
                        button_label: "Detect Fob",
                        message: Message::DetectKeyFob,
                    }),
                    self.workflow_step_card(WorkflowStep {
                        icon_name: "register-key",
                        title: "Register Key Fob",
                        description:
                            "Create fob credentials and persist redacted key storage metadata.",
                        status: self.completed_status(
                            self.workflow_state.keyfob_registered,
                            "Registered",
                            self.status.key_fob_status == "Error",
                        ),
                        button_label: "Register Fob",
                        message: Message::RegisterDigitalKeyFob,
                    }),
                ]
                .spacing(6),
            ),
            self.workflow_group(
                "C. Certificate Provisioning",
                "Initialize trust and issue the CA-signed access certificate.",
                column![
                    self.workflow_step_card(WorkflowStep {
                        icon_name: "trust",
                        title: "Initialize Vehicle Trust",
                        description: "Initialize vehicle trust root and certificate authority.",
                        status: self.completed_status(
                            self.workflow_state.trust_initialized,
                            "Initialized",
                            self.status.trust_status == "Error",
                        ),
                        button_label: "Initialize Trust",
                        message: Message::InitializeVehicleTrust,
                    }),
                    self.workflow_step_card(WorkflowStep {
                        icon_name: "issue-cert",
                        title: "Issue Access Certificate",
                        description: "Issue CA-signed access certificate to the key fob.",
                        status: self.completed_status(
                            self.workflow_state.certificate_issued,
                            "Issued",
                            self.status.certificate_status == "Error",
                        ),
                        button_label: "Issue Certificate",
                        message: Message::IssueCertificate,
                    }),
                    self.workflow_step_card(WorkflowStep {
                        icon_name: "certificate",
                        title: "View Certificate Details",
                        description:
                            "Inspect subject, issuer, validity, and public key fingerprint.",
                        status: self.completed_status(
                            self.workflow_state.certificate_viewed,
                            "Viewed",
                            false,
                        ),
                        button_label: "View Certificate",
                        message: Message::ViewCertificateDetails,
                    }),
                ]
                .spacing(6),
            ),
            self.workflow_group(
                "D. Authentication Verification",
                "Run the operator-visible challenge-response authentication steps.",
                column![
                    self.workflow_step_card(WorkflowStep {
                        icon_name: "auth",
                        title: "Generate Challenge",
                        description: "Create vehicle nonce challenge; raw nonce remains redacted.",
                        status: self.completed_status(
                            self.workflow_state.challenge_generated,
                            "Generated",
                            false,
                        ),
                        button_label: "Generate",
                        message: Message::GenerateChallenge,
                    }),
                    self.workflow_step_card(WorkflowStep {
                        icon_name: "verify-auth",
                        title: "Sign Canonical Payload",
                        description: "Stage Ed25519 payload signing; private key stays redacted.",
                        status: self.completed_status(
                            self.workflow_state.payload_signed,
                            "Signed",
                            false,
                        ),
                        button_label: "Sign Payload",
                        message: Message::SignCanonicalPayload,
                    }),
                    self.workflow_step_card(WorkflowStep {
                        icon_name: "auth",
                        title: "Verify Key Authentication",
                        description: "Run the real AIACS authentication and access decision path.",
                        status: self.completed_status(
                            self.workflow_state.authentication_verified,
                            "Verified",
                            matches!(
                                self.status.authentication_status.as_str(),
                                "Failed" | "Error"
                            ),
                        ),
                        button_label: "Verify Authentication",
                        message: Message::VerifyAuthentication,
                    }),
                ]
                .spacing(6),
            ),
            self.workflow_group(
                "E. Secure Session Activation",
                "Activate the secure access channel after authentication succeeds.",
                column![self.workflow_step_card(WorkflowStep {
                    icon_name: "secure-session",
                    title: "Activate Secure Session",
                    description: "Establish encrypted access session for the provisioned key fob.",
                    status: self.completed_status(
                        self.workflow_state.session_active,
                        "Active",
                        self.status.session_status == "Error",
                    ),
                    button_label: "Activate Session",
                    message: Message::ActivateSecureChannel,
                })]
                .spacing(6),
            ),
            self.workflow_group(
                "F. Finalize",
                "Export the safe provisioning report after setup is complete.",
                column![
                    self.provisioning_completion_card(),
                    self.workflow_step_card(WorkflowStep {
                        icon_name: "terminal",
                        title: "Export Provisioning Report",
                        description: "Save safe provisioning report with all secrets redacted.",
                        status: self.completed_status(
                            self.workflow_state.report_exported,
                            "Exported",
                            false,
                        ),
                        button_label: "Export Report",
                        message: Message::ExportProvisioningReport,
                    }),
                ]
                .spacing(6),
            ),
        ]
        .spacing(10);

        container(
            column![
                text("Staged Vehicle Access Provisioning")
                    .size(16)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(ACCENT_PINK)),
                scrollable(workflow).height(Length::Fill),
            ]
            .spacing(10),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(12)
        .style(container_style(PanelKind::Elevated))
        .into()
    }

    fn workflow_group<'a>(
        &self,
        title: &'a str,
        description: &'a str,
        steps: iced::widget::Column<'a, Message>,
    ) -> Element<'a, Message> {
        container(
            column![
                text(title)
                    .size(13)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(ACCENT_BLUE)),
                text(description)
                    .size(11)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(SECONDARY_TEXT)),
                steps,
            ]
            .spacing(6),
        )
        .width(Length::Fill)
        .padding(9)
        .style(container_style(PanelKind::Detail))
        .into()
    }

    fn workflow_step_card<'a>(&self, step: WorkflowStep<'a>) -> Element<'a, Message> {
        container(
            row![
                icon(step.icon_name, 22),
                column![
                    text(step.title)
                        .size(13)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(PRIMARY_TEXT)),
                    text(step.description)
                        .size(11)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(SECONDARY_TEXT)),
                ]
                .spacing(3)
                .width(Length::Fill),
                status_chip(step.status),
                compact_button(
                    step.icon_name,
                    step.button_label,
                    step.message,
                    ButtonKind::StepAction,
                ),
            ]
            .spacing(12)
            .align_items(Alignment::Center),
        )
        .width(Length::Fill)
        .padding([9, 10])
        .style(container_style(PanelKind::StepCard))
        .into()
    }

    fn provisioning_completion_card(&self) -> Element<'_, Message> {
        let complete = self.setup_complete();
        let (title, message, color, kind) = if complete {
            (
                "Vehicle Access Setup Complete",
                "The key fob is authorized and ready for secure vehicle access.",
                SUCCESS_GREEN,
                PanelKind::SuccessCard,
            )
        } else {
            (
                "Provisioning In Progress",
                "Complete the provisioning steps to authorize the digital key fob.",
                PENDING_TEXT,
                PanelKind::ProgressCard,
            )
        };

        container(
            column![
                text(title)
                    .size(14)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(color)),
                text(message)
                    .size(12)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(PRIMARY_TEXT)),
            ]
            .spacing(4)
            .width(Length::Fill),
        )
        .width(Length::Fill)
        .padding(12)
        .style(container_style(kind))
        .into()
    }

    fn core_detail_box(&self) -> Element<'_, Message> {
        container(
            column![
                text("Core Result / Details")
                    .size(12)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(ACCENT_BLUE)),
                self.detail_row("Last Result", self.selected_detail.as_str()),
                self.detail_row("Auth Method", "Ed25519 + PKI"),
                self.detail_row("Session Method", "X25519 + HKDF + AES-GCM"),
                self.detail_row("Certificate Trust", self.certificate_trust_label()),
                self.detail_row("Access Decision", &self.status.access_decision),
            ]
            .spacing(6),
        )
        .width(Length::Fill)
        .padding(10)
        .style(container_style(PanelKind::Detail))
        .into()
    }

    fn view_provisioning_context_panel(&self) -> Element<'_, Message> {
        container(
            column![
                text("Selected Access Setup")
                    .size(16)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(ACCENT_PINK)),
                self.selected_setup_card("auth", "Owner", OWNER_NAME),
                self.selected_setup_card("vehicle", "Vehicle", VEHICLE_DISPLAY_NAME),
                self.selected_setup_card("key", "Digital Key", KEY_FOB_LABEL),
                text("Provisioning Status")
                    .size(16)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(ACCENT_PINK)),
                self.provisioning_completion_card(),
                self.view_compact_status_rows(),
                self.compact_current_result_card(),
            ]
            .spacing(8),
        )
        .width(Length::Fixed(320.0))
        .height(Length::Fill)
        .padding(10)
        .style(container_style(PanelKind::Panel))
        .into()
    }

    fn view_protocol_artifacts_tab(&self) -> Element<'_, Message> {
        row![
            container(
                column![
                    text("Protocol Artifacts")
                        .size(16)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(ACCENT_PINK)),
                    text("Select one safe artifact summary.")
                        .size(11)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(SECONDARY_TEXT)),
                    artifact_button(
                        "auth",
                        "Challenge Message",
                        ArtifactSection::ChallengeMessage,
                        self.selected_artifact,
                    ),
                    artifact_button(
                        "verify-auth",
                        "Authentication Proof",
                        ArtifactSection::AuthenticationProof,
                        self.selected_artifact,
                    ),
                    artifact_button(
                        "certificate",
                        "Certificate Details",
                        ArtifactSection::CertificateDetails,
                        self.selected_artifact,
                    ),
                    artifact_button(
                        "lock",
                        "Session Summary",
                        ArtifactSection::SessionSummary,
                        self.selected_artifact,
                    ),
                    artifact_button(
                        "decision",
                        "Access Decision",
                        ArtifactSection::AccessDecision,
                        self.selected_artifact,
                    ),
                ]
                .spacing(8),
            )
            .width(Length::FillPortion(2))
            .height(Length::Fill)
            .padding(12)
            .style(container_style(PanelKind::Status)),
            self.view_selected_artifact_detail(),
        ]
        .spacing(10)
        .height(Length::Fill)
        .into()
    }

    fn view_selected_artifact_detail(&self) -> Element<'_, Message> {
        let (title, rows) = self.selected_artifact_rows();
        let details = rows.into_iter().fold(
            column![
                text(title)
                    .size(18)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(ACCENT_PINK)),
                text("Only display-safe metadata, fingerprints, and redaction markers are shown.")
                    .size(11)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(SECONDARY_TEXT)),
            ]
            .spacing(8)
            .width(Length::Fill),
            |column, (label, value)| column.push(self.artifact_detail_row(label, value)),
        );

        container(scrollable(details).height(Length::Fill))
            .width(Length::FillPortion(5))
            .height(Length::Fill)
            .padding(14)
            .style(container_style(PanelKind::Panel))
            .into()
    }

    fn view_diagnostics_tab(&self) -> Element<'_, Message> {
        container(
            column![
                text("Diagnostics / Security Validation")
                    .size(20)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(ACCENT_PINK)),
                text("Diagnostics runs separately from normal provisioning.")
                    .size(12)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(SECONDARY_TEXT)),
                text("Attack scenarios are kept in the dedicated diagnostics tool and are not shown in the main dealer console.")
                    .size(12)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(PRIMARY_TEXT)),
                container(self.nav_button(
                    "warning-shield",
                    "Launch Diagnostics Tool",
                    Message::LaunchDiagnosticsTool,
                ))
                .width(Length::Fixed(280.0)),
                self.core_detail_box(),
            ]
            .spacing(12),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(16)
        .style(container_style(PanelKind::Panel))
        .into()
    }

    fn selected_setup_card<'a>(
        &self,
        icon_name: &'static str,
        label: &'a str,
        value: &'a str,
    ) -> Element<'a, Message> {
        container(
            row![
                icon(icon_name, 18),
                column![
                    text(label)
                        .size(11)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(MUTED_TEXT)),
                    text(value)
                        .size(13)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(PRIMARY_TEXT)),
                ]
                .spacing(3)
                .width(Length::Fill),
            ]
            .spacing(9)
            .align_items(Alignment::Center),
        )
        .width(Length::Fill)
        .padding([9, 10])
        .style(container_style(PanelKind::StepCard))
        .into()
    }

    fn dashboard_card<'a>(
        &self,
        icon_name: &'static str,
        title: &'a str,
        value: &'a str,
        detail: &'a str,
    ) -> Element<'a, Message> {
        container(
            column![
                row![
                    icon(icon_name, 18),
                    text(title)
                        .size(12)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(MUTED_TEXT)),
                ]
                .spacing(8)
                .align_items(Alignment::Center),
                text(value)
                    .size(15)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(status_color(value))),
                text(detail)
                    .size(11)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(SECONDARY_TEXT)),
            ]
            .spacing(7),
        )
        .width(Length::Fill)
        .height(Length::Fixed(112.0))
        .padding(12)
        .style(container_style(PanelKind::Elevated))
        .into()
    }

    fn management_details_panel(
        &self,
        title: &'static str,
        subtitle: &'static str,
        rows: Vec<(&'static str, String)>,
    ) -> Element<'static, Message> {
        let details = rows.into_iter().fold(
            column![
                text(title)
                    .size(18)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(ACCENT_PINK)),
                text(subtitle)
                    .size(12)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(SECONDARY_TEXT)),
            ]
            .spacing(8)
            .width(Length::Fill),
            |column, (label, value)| column.push(self.artifact_detail_row(label, value)),
        );

        container(scrollable(details).height(Length::Fill))
            .width(Length::FillPortion(5))
            .height(Length::Fill)
            .padding(14)
            .style(container_style(PanelKind::Panel))
            .into()
    }

    fn management_actions_panel<'a>(
        &self,
        title: &'static str,
        note: &'a str,
        actions: Vec<(&'static str, &'static str, Message)>,
    ) -> Element<'a, Message> {
        let buttons = actions.into_iter().fold(
            column![
                text(title)
                    .size(18)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(ACCENT_PINK)),
                text(note)
                    .size(12)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(SECONDARY_TEXT)),
            ]
            .spacing(8)
            .width(Length::Fill),
            |column, (icon_name, label, message)| {
                column.push(compact_button(icon_name, label, message, ButtonKind::Nav))
            },
        );

        container(buttons)
            .width(Length::FillPortion(2))
            .height(Length::Fill)
            .padding(14)
            .style(container_style(PanelKind::Elevated))
            .into()
    }

    fn view_credential_storage_tab(&self) -> Element<'_, Message> {
        let storage_summary = self.controller.credential_storage_summary();
        let rows = storage_summary.iter().fold(
            column![
                text("Credential Storage")
                    .size(18)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(ACCENT_PINK)),
                text("Dealer-side storage evidence. Secret material remains redacted.")
                    .size(11)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(SECONDARY_TEXT)),
            ]
            .spacing(8)
            .width(Length::Fill),
            |column, line| {
                let (label, value) = split_storage_line(line);
                column.push(self.artifact_detail_row(label, value))
            },
        );

        container(scrollable(rows).height(Length::Fill))
            .width(Length::Fill)
            .height(Length::Fill)
            .padding(14)
            .style(container_style(PanelKind::Panel))
            .into()
    }

    fn view_cloud_storage_tab(&self) -> Element<'_, Message> {
        row![
            container(
                column![
                    text("Cloud Storage")
                        .size(18)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(ACCENT_PINK)),
                    text("Safe customer, vehicle, and key fob metadata sync only.")
                        .size(12)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(SECONDARY_TEXT)),
                    self.artifact_detail_row("Cloud DB Status", self.cloud_status.clone()),
                    self.artifact_detail_row("Provider", "Neon PostgreSQL"),
                    self.artifact_detail_row("Storage Mode", "Company Cloud DB"),
                    self.artifact_detail_row("Sync Scope", "Customer / Vehicle / Key Fob Metadata"),
                    text("Cloud Credential Protection")
                        .size(14)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(ACCENT_PINK)),
                    self.artifact_detail_row(
                        "Private Key Storage",
                        "Client-side encrypted cloud blob"
                    ),
                    self.artifact_detail_row("Encryption", "AES-256-GCM"),
                    self.artifact_detail_row(
                        "Master Key",
                        "Environment variable, external to database"
                    ),
                    self.artifact_detail_row("Raw Private Keys in Cloud", "No"),
                    self.artifact_detail_row("Raw Private Key Material", "[REDACTED]"),
                    self.artifact_detail_row(
                        "Last Metadata Sync Status",
                        self.last_metadata_sync_status.clone()
                    ),
                    self.artifact_detail_row(
                        "Last Metadata Sync Time",
                        self.last_metadata_sync_time.clone()
                    ),
                    self.artifact_detail_row(
                        "Last Certificate Metadata Sync",
                        self.last_certificate_sync_status.clone()
                    ),
                    self.artifact_detail_row(
                        "Last Certificate Metadata Sync Time",
                        self.last_certificate_sync_time.clone()
                    ),
                    self.artifact_detail_row(
                        "Provisioning Session",
                        self.last_provisioning_session_sync_status.clone()
                    ),
                    self.artifact_detail_row(
                        "Provisioning Session Sync Time",
                        self.last_provisioning_session_sync_time.clone()
                    ),
                    self.artifact_detail_row(
                        "Session Algorithm",
                        "X25519 + HKDF-SHA256 + AES-256-GCM"
                    ),
                    self.artifact_detail_row("Raw Session Key", "[REDACTED]"),
                    self.artifact_detail_row("Shared Secret", "[REDACTED]"),
                    self.artifact_detail_row("HKDF Output", "[REDACTED]"),
                    self.artifact_detail_row("Audit Logs", self.last_audit_log_sync_status.clone()),
                    self.artifact_detail_row(
                        "Audit Log Sync Time",
                        self.last_audit_log_sync_time.clone()
                    ),
                    self.artifact_detail_row("Audit Scope", "provisioning workflow events"),
                    self.artifact_detail_row("Sensitive Material", "[REDACTED]"),
                    self.artifact_detail_row("Private Key Material", "[REDACTED]"),
                    self.artifact_detail_row(
                        "Diagnostic Results",
                        self.last_diagnostic_result_sync_status.clone()
                    ),
                    self.artifact_detail_row(
                        "Diagnostic Result Sync Time",
                        self.last_diagnostic_result_sync_time.clone()
                    ),
                    self.artifact_detail_row(
                        "Diagnostic Scope",
                        "adversarial validation outcomes"
                    ),
                    self.artifact_detail_row("Malicious Scenarios", "rejected"),
                    self.artifact_detail_row("Raw Attack Payloads", "[REDACTED]"),
                    self.artifact_detail_row(
                        "Last Encrypted Key Upload",
                        self.last_encrypted_key_sync_status.clone()
                    ),
                    self.artifact_detail_row(
                        "Last Encrypted Key Upload Time",
                        self.last_encrypted_key_sync_time.clone()
                    ),
                ]
                .spacing(8),
            )
            .width(Length::FillPortion(4))
            .height(Length::Fill)
            .padding(14)
            .style(container_style(PanelKind::Panel)),
            container(
                column![
                    text("Metadata Sync Controls")
                        .size(18)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(ACCENT_PINK)),
                    text("Safe metadata sync never uploads plaintext secrets.")
                        .size(12)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(SECONDARY_TEXT)),
                    compact_button(
                        "shield",
                        "Check Cloud Connection",
                        Message::CheckCloudConnection,
                        ButtonKind::Nav
                    ),
                    compact_button(
                        "auth",
                        "Sync Customer Metadata",
                        Message::SyncCustomerMetadata,
                        ButtonKind::Nav
                    ),
                    compact_button(
                        "vehicle",
                        "Sync Vehicle Metadata",
                        Message::SyncVehicleMetadata,
                        ButtonKind::Nav
                    ),
                    compact_button(
                        "key",
                        "Sync Key Fob Metadata",
                        Message::SyncKeyFobMetadata,
                        ButtonKind::Nav
                    ),
                    compact_button(
                        "terminal",
                        "Sync Demo Metadata",
                        Message::SyncDemoMetadata,
                        ButtonKind::Nav
                    ),
                    compact_button(
                        "certificate",
                        "Sync Certificate Metadata",
                        Message::SyncCertificateMetadata,
                        ButtonKind::Nav
                    ),
                    text("Certificate private material: [REDACTED]")
                        .size(11)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(SECONDARY_TEXT)),
                    text("Provisioning Session Sync")
                        .size(18)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(ACCENT_PINK)),
                    text("Stores safe operational session metadata only. Raw session material is never displayed or uploaded.")
                        .size(12)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(SECONDARY_TEXT)),
                    compact_button(
                        "lock",
                        "Sync Provisioning Session",
                        Message::SyncProvisioningSession,
                        ButtonKind::Nav
                    ),
                    text("Raw session key: [REDACTED] | Shared secret: [REDACTED] | HKDF output: [REDACTED]")
                        .size(11)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(SECONDARY_TEXT)),
                    text("Audit Log Sync")
                        .size(18)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(ACCENT_PINK)),
                    text("Stores safe provisioning workflow audit events with sensitive material redacted.")
                        .size(12)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(SECONDARY_TEXT)),
                    compact_button(
                        "terminal",
                        "Sync Audit Logs",
                        Message::SyncAuditLogs,
                        ButtonKind::Nav
                    ),
                    text(AUDIT_SYNC_REDACTION_LINE)
                        .size(11)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(SECONDARY_TEXT)),
                    text("Diagnostic Result Sync")
                        .size(18)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(ACCENT_PINK)),
                    text("Stores safe adversarial validation outcomes only. Raw attack payloads are never displayed or uploaded.")
                        .size(12)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(SECONDARY_TEXT)),
                    compact_button(
                        "warning-shield",
                        "Sync Diagnostic Results",
                        Message::SyncDiagnosticResults,
                        ButtonKind::Nav
                    ),
                    text(DIAGNOSTIC_SYNC_REDACTION_LINE)
                        .size(11)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(SECONDARY_TEXT)),
                    text("Encrypted Key Blob Controls")
                        .size(18)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(ACCENT_PINK)),
                    text("Private key material is encrypted locally before upload. Ciphertext and nonce bytes are never displayed.")
                        .size(12)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(SECONDARY_TEXT)),
                    compact_button(
                        "shield",
                        "Upload CA Encrypted Key Blob",
                        Message::SyncCaEncryptedKeyBlob,
                        ButtonKind::Nav
                    ),
                    compact_button(
                        "key",
                        "Upload Key Fob Encrypted Key Blob",
                        Message::SyncKeyFobEncryptedKeyBlob,
                        ButtonKind::Nav
                    ),
                    compact_button(
                        "lock",
                        "Upload All Encrypted Key Blobs",
                        Message::SyncEncryptedKeyBlobs,
                        ButtonKind::Nav
                    ),
                ]
                .spacing(8),
            )
            .width(Length::FillPortion(2))
            .height(Length::Fill)
            .padding(14)
            .style(container_style(PanelKind::Elevated)),
        ]
        .spacing(10)
        .height(Length::Fill)
        .into()
    }

    fn view_logs_report_tab(&self) -> Element<'_, Message> {
        column![
            row![self.view_event_log(), self.view_protocol_trace_panel(),]
                .spacing(10)
                .height(Length::Fill),
            container(
                row![
                    compact_button("terminal", "Clear Log", Message::ClearLog, ButtonKind::Nav),
                    compact_button(
                        "terminal",
                        "Save / Export Logs",
                        Message::ExportLogs,
                        ButtonKind::Nav
                    ),
                    compact_button(
                        "terminal",
                        "Export Report",
                        Message::ExportProvisioningReport,
                        ButtonKind::Nav
                    ),
                    text(self.selected_detail.as_str())
                        .size(11)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(SECONDARY_TEXT))
                        .width(Length::Fill),
                ]
                .spacing(8)
                .align_items(Alignment::Center),
            )
            .width(Length::Fill)
            .padding(10)
            .style(container_style(PanelKind::Elevated)),
        ]
        .spacing(10)
        .height(Length::Fill)
        .into()
    }

    fn view_protocol_trace_panel(&self) -> Element<'_, Message> {
        let trace_entries = self.controller.get_protocol_trace();
        let entries = if trace_entries.is_empty() {
            column![text("Awaiting protocol activity. Run provisioning steps to populate cryptographic evidence.")
                .size(12)
                .font(Font::MONOSPACE)
                .style(theme::Text::Color(SECONDARY_TEXT))]
        } else {
            trace_entries
                .iter()
                .fold(column![].spacing(4).width(Length::Fill), |column, entry| {
                    let (tag, message) = trace_parts(entry);
                    column.push(
                        row![
                            text(tag)
                                .size(12)
                                .font(Font::MONOSPACE)
                                .style(theme::Text::Color(log_tag_color(tag)))
                                .width(Length::Fixed(104.0)),
                            text(message)
                                .size(12)
                                .font(Font::MONOSPACE)
                                .style(theme::Text::Color(PRIMARY_TEXT))
                                .width(Length::Fill),
                        ]
                        .spacing(8)
                        .align_items(Alignment::Center),
                    )
                })
        };

        container(
            column![
                row![
                    icon("shield", 20),
                    text("Protocol Trace / Cryptographic Evidence")
                        .size(16)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(ACCENT_PINK)),
                ]
                .spacing(8)
                .align_items(Alignment::Center),
                scrollable(entries).height(Length::Fill),
            ]
            .spacing(8),
        )
        .width(Length::Fill)
        .height(Length::FillPortion(2))
        .padding(10)
        .style(container_style(PanelKind::Panel))
        .into()
    }

    fn view_event_log(&self) -> Element<'_, Message> {
        let entries = self.event_log.iter().fold(
            column![row![row![
                icon("terminal", 20),
                text("Event Log")
                    .size(16)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(ACCENT_PINK))
            ]
            .spacing(8)
            .align_items(Alignment::Center)
            .width(Length::Fill),]
            .spacing(8)
            .align_items(Alignment::Center)]
            .spacing(5)
            .width(Length::Fill),
            |log, entry| {
                let (timestamp, tag, message) = log_parts(entry);

                log.push(
                    row![
                        text(timestamp)
                            .size(12)
                            .font(Font::MONOSPACE)
                            .style(theme::Text::Color(MUTED_TEXT))
                            .width(Length::Fixed(70.0)),
                        text(tag)
                            .size(12)
                            .font(Font::MONOSPACE)
                            .style(theme::Text::Color(log_tag_color(tag)))
                            .width(Length::Fixed(78.0)),
                        text(message)
                            .size(12)
                            .font(Font::MONOSPACE)
                            .style(theme::Text::Color(PRIMARY_TEXT))
                            .width(Length::Fill),
                    ]
                    .spacing(8)
                    .align_items(Alignment::Center),
                )
            },
        );

        container(scrollable(entries).width(Length::Fill).height(Length::Fill))
            .width(Length::Fill)
            .height(Length::FillPortion(2))
            .padding(10)
            .style(container_style(PanelKind::Log))
            .into()
    }

    fn detail_row<'a>(&self, label: &'a str, value: &'a str) -> Element<'a, Message> {
        row![
            text(label)
                .size(11)
                .font(Font::MONOSPACE)
                .style(theme::Text::Color(MUTED_TEXT))
                .width(Length::Fixed(132.0)),
            text(value)
                .size(11)
                .font(Font::MONOSPACE)
                .style(theme::Text::Color(status_color(value)))
                .width(Length::Fill),
        ]
        .spacing(8)
        .width(Length::Fill)
        .into()
    }

    fn artifact_detail_row(
        &self,
        label: impl Into<String>,
        value: impl Into<String>,
    ) -> Element<'static, Message> {
        let label = label.into();
        let value = value.into();
        let value_color = status_color(&value);

        container(
            row![
                text(label)
                    .size(12)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(MUTED_TEXT))
                    .width(Length::FillPortion(2)),
                text(value)
                    .size(12)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(value_color))
                    .width(Length::FillPortion(3)),
            ]
            .spacing(12)
            .align_items(Alignment::Center),
        )
        .width(Length::Fill)
        .padding([8, 10])
        .style(container_style(PanelKind::StepCard))
        .into()
    }

    fn selected_artifact_rows(&self) -> (&'static str, Vec<(&'static str, String)>) {
        match self.selected_artifact {
            ArtifactSection::ChallengeMessage => (
                "Challenge Message",
                vec![
                    ("Status", self.challenge_status().to_string()),
                    ("Vehicle ID", TECH_VEHICLE_ID.to_string()),
                    ("Protocol", "AIACS_AUTH_V1".to_string()),
                    ("Nonce", "[REDACTED]".to_string()),
                    (
                        "Evidence",
                        "Nonce hash appears in protocol trace after verification".to_string(),
                    ),
                ],
            ),
            ArtifactSection::AuthenticationProof => (
                "Authentication Proof",
                vec![
                    ("Status", self.authentication_proof_status().to_string()),
                    ("Subject ID", TECH_KEY_FOB_ID.to_string()),
                    ("Auth Method", "Ed25519 + PKI".to_string()),
                    (
                        "Canonical Payload",
                        "AIACS_AUTH_V1 fields summarized only".to_string(),
                    ),
                    ("Signature", "[REDACTED]".to_string()),
                ],
            ),
            ArtifactSection::CertificateDetails => (
                "Certificate Details",
                vec![
                    ("Status", self.certificate_artifact_status().to_string()),
                    ("Subject ID", TECH_KEY_FOB_ID.to_string()),
                    ("Issuer", "AIACS-Demo-CA".to_string()),
                    ("Certificate Path", "certs/fob_FOB-0001.json".to_string()),
                    (
                        "Public Key",
                        "Fingerprint only; see credential storage".to_string(),
                    ),
                ],
            ),
            ArtifactSection::SessionSummary => (
                "Session Summary",
                vec![
                    ("Status", self.session_artifact_status().to_string()),
                    ("Key Exchange", "X25519".to_string()),
                    ("KDF", "HKDF-SHA256".to_string()),
                    ("Cipher", "AES-GCM".to_string()),
                    ("Session Key", "[REDACTED]".to_string()),
                    ("Shared Secret", "[REDACTED]".to_string()),
                ],
            ),
            ArtifactSection::AccessDecision => (
                "Access Decision",
                vec![
                    ("Status", self.access_decision_artifact_status().to_string()),
                    (
                        "Authentication",
                        self.authentication_artifact_status().to_string(),
                    ),
                    (
                        "Decision",
                        self.access_decision_artifact_status().to_string(),
                    ),
                    (
                        "Policy Path",
                        "AppController -> Authentication -> Access Decision".to_string(),
                    ),
                    ("Secret Material", "[REDACTED]".to_string()),
                ],
            ),
        }
    }

    fn challenge_status(&self) -> &'static str {
        if self.workflow_state.challenge_generated {
            "Generated"
        } else {
            "Pending"
        }
    }

    fn authentication_proof_status(&self) -> &'static str {
        if self.workflow_state.authentication_verified {
            "Verified"
        } else if self.workflow_state.payload_signed {
            "Signed"
        } else {
            "Pending"
        }
    }

    fn certificate_artifact_status(&self) -> &'static str {
        if self.workflow_state.certificate_issued {
            "Issued"
        } else {
            "Pending"
        }
    }

    fn session_artifact_status(&self) -> &'static str {
        if self.workflow_state.session_active {
            "Active"
        } else {
            "Pending"
        }
    }

    fn authentication_artifact_status(&self) -> &'static str {
        match self.status.authentication_status.as_str() {
            "Verified" => "Verified",
            "Failed" | "Error" => "Failed",
            _ => "Pending",
        }
    }

    fn view_summary_row<'a>(
        &self,
        icon_name: &'static str,
        label: &'a str,
        value: &'a str,
    ) -> Element<'a, Message> {
        row![
            icon(icon_name, 18),
            text(label)
                .size(12)
                .font(Font::MONOSPACE)
                .style(theme::Text::Color(MUTED_TEXT))
                .width(Length::Fill),
            text(value)
                .size(12)
                .font(Font::MONOSPACE)
                .style(theme::Text::Color(status_color(value)))
                .horizontal_alignment(alignment::Horizontal::Right),
        ]
        .spacing(8)
        .align_items(Alignment::Center)
        .into()
    }

    fn view_provisioning_summary_rows(&self) -> Element<'_, Message> {
        column![
            self.view_summary_row("auth", "Owner", OWNER_NAME),
            self.view_summary_row("vehicle", "Vehicle", VEHICLE_DISPLAY_NAME),
            self.view_summary_row("key", "Digital Key", KEY_FOB_LABEL),
            self.view_summary_row(
                "certificate",
                "Certificate",
                &self.status.certificate_status
            ),
            self.view_summary_row("auth", "Authentication", &self.status.authentication_status),
            self.view_summary_row("lock", "Secure Session", &self.status.session_status),
            self.view_summary_row("decision", "Access Decision", &self.status.access_decision),
        ]
        .spacing(8)
        .into()
    }

    fn view_compact_status_rows(&self) -> Element<'_, Message> {
        container(
            column![
                self.view_summary_row(
                    "certificate",
                    "Certificate",
                    &self.status.certificate_status
                ),
                self.view_summary_row("auth", "Authentication", &self.status.authentication_status),
                self.view_summary_row("lock", "Session", &self.status.session_status),
                self.view_summary_row("decision", "Access", &self.status.access_decision),
            ]
            .spacing(7),
        )
        .width(Length::Fill)
        .padding(8)
        .style(container_style(PanelKind::Detail))
        .into()
    }

    fn compact_current_result_card(&self) -> Element<'_, Message> {
        container(
            column![
                text("Current Result")
                    .size(12)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(ACCENT_BLUE)),
                text(self.selected_detail.as_str())
                    .size(11)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(PRIMARY_TEXT))
                    .width(Length::Fill),
            ]
            .spacing(5),
        )
        .width(Length::Fill)
        .padding(9)
        .style(container_style(PanelKind::Detail))
        .into()
    }

    fn setup_complete(&self) -> bool {
        self.status.session_status == "Active" && self.status.access_decision == "Access Granted"
    }

    fn setup_status_label(&self) -> &'static str {
        if self.setup_complete() {
            "Complete"
        } else {
            "Provisioning In Progress"
        }
    }

    fn credential_storage_status(&self) -> &'static str {
        if self.workflow_state.keyfob_registered {
            "Stored"
        } else {
            "Pending"
        }
    }

    fn keyfob_public_key_fingerprint(&self) -> String {
        self.controller
            .credential_storage_summary()
            .into_iter()
            .find_map(|line| {
                line.strip_prefix("Key fob public key fingerprint: ")
                    .map(str::to_string)
            })
            .unwrap_or_else(|| "Pending".to_string())
    }

    fn certificate_trust_label(&self) -> &str {
        if self.status.certificate_status == "Issued" {
            "CA-signed certificate issued"
        } else if self.status.trust_status == "Initialized" {
            "Trust root initialized"
        } else if self.status.certificate_status == "Error" || self.status.trust_status == "Error" {
            "Certificate trust error"
        } else {
            "Pending"
        }
    }

    fn access_decision_artifact_status(&self) -> &str {
        match self.status.access_decision.as_str() {
            "Access Granted" => "Granted",
            "Error" | "Access Rejected" => "Rejected",
            _ => "Pending",
        }
    }

    fn completed_status(
        &self,
        completed: bool,
        completed_label: &'static str,
        failed: bool,
    ) -> ChipState {
        if failed {
            ChipState {
                status: StepStatus::Error,
                label: "Error",
            }
        } else if completed {
            ChipState {
                status: StepStatus::Completed,
                label: completed_label,
            }
        } else {
            ChipState {
                status: StepStatus::Pending,
                label: "Pending",
            }
        }
    }

    fn nav_button<'a>(
        &self,
        icon_name: &'static str,
        label: &'a str,
        message: Message,
    ) -> Element<'a, Message> {
        styled_button(icon_name, label, message, ButtonKind::Nav)
    }

    fn record_metadata_sync(&mut self, message: String) {
        self.cloud_status = "Connected".to_string();
        self.last_metadata_sync_status = message.clone();
        self.last_metadata_sync_time = Local::now().format("%H:%M:%S").to_string();
        self.selected_detail = message;
    }

    fn record_metadata_sync_error(&mut self, error: AppControllerError) {
        self.cloud_status = "Error".to_string();
        self.last_metadata_sync_status = format!("Metadata sync failed: {}", error);
        self.last_metadata_sync_time = Local::now().format("%H:%M:%S").to_string();
        self.selected_detail = self.last_metadata_sync_status.clone();
        self.push_log("[DB]", self.last_metadata_sync_status.clone());
    }

    fn record_certificate_sync(&mut self, message: String) {
        self.cloud_status = "Connected".to_string();
        self.last_certificate_sync_status = message.clone();
        self.last_certificate_sync_time = Local::now().format("%H:%M:%S").to_string();
        self.selected_detail = message;
    }

    fn record_certificate_sync_error(&mut self, error: AppControllerError) {
        self.cloud_status = "Error".to_string();
        self.last_certificate_sync_status = format!("Certificate metadata sync failed: {}", error);
        self.last_certificate_sync_time = Local::now().format("%H:%M:%S").to_string();
        self.selected_detail = self.last_certificate_sync_status.clone();
        self.push_log("[DB]", self.last_certificate_sync_status.clone());
    }

    fn record_provisioning_session_sync(&mut self, message: String) {
        self.cloud_status = "Connected".to_string();
        self.last_provisioning_session_sync_status = message.clone();
        self.last_provisioning_session_sync_time = Local::now().format("%H:%M:%S").to_string();
        self.selected_detail = message;
    }

    fn record_provisioning_session_sync_error(&mut self, error: AppControllerError) {
        self.cloud_status = "Error".to_string();
        self.last_provisioning_session_sync_status =
            format!("Provisioning session sync failed: {}", error);
        self.last_provisioning_session_sync_time = Local::now().format("%H:%M:%S").to_string();
        self.selected_detail = self.last_provisioning_session_sync_status.clone();
        self.push_log("[DB]", self.last_provisioning_session_sync_status.clone());
    }

    fn record_audit_log_sync(&mut self, message: String) {
        self.cloud_status = "Connected".to_string();
        self.last_audit_log_sync_status = message.clone();
        self.last_audit_log_sync_time = Local::now().format("%H:%M:%S").to_string();
        self.selected_detail = message;
    }

    fn record_audit_log_sync_error(&mut self, error: AppControllerError) {
        self.cloud_status = "Error".to_string();
        self.last_audit_log_sync_status = format!("Audit log sync failed: {}", error);
        self.last_audit_log_sync_time = Local::now().format("%H:%M:%S").to_string();
        self.selected_detail = self.last_audit_log_sync_status.clone();
        self.push_log("[DB]", self.last_audit_log_sync_status.clone());
    }

    fn record_diagnostic_result_sync(&mut self, message: String) {
        self.cloud_status = "Connected".to_string();
        self.last_diagnostic_result_sync_status = message.clone();
        self.last_diagnostic_result_sync_time = Local::now().format("%H:%M:%S").to_string();
        self.selected_detail = message;
    }

    fn record_diagnostic_result_sync_error(&mut self, error: AppControllerError) {
        self.cloud_status = "Error".to_string();
        self.last_diagnostic_result_sync_status =
            format!("Diagnostic result sync failed: {}", error);
        self.last_diagnostic_result_sync_time = Local::now().format("%H:%M:%S").to_string();
        self.selected_detail = self.last_diagnostic_result_sync_status.clone();
        self.push_log("[DB]", self.last_diagnostic_result_sync_status.clone());
    }

    fn record_encrypted_key_sync(&mut self, message: String) {
        self.cloud_status = "Connected".to_string();
        self.last_encrypted_key_sync_status = message.clone();
        self.last_encrypted_key_sync_time = Local::now().format("%H:%M:%S").to_string();
        self.selected_detail = message;
    }

    fn record_encrypted_key_sync_error(&mut self, error: AppControllerError) {
        self.cloud_status = "Error".to_string();
        self.last_encrypted_key_sync_status = format!("Encrypted key upload failed: {}", error);
        self.last_encrypted_key_sync_time = Local::now().format("%H:%M:%S").to_string();
        self.selected_detail = self.last_encrypted_key_sync_status.clone();
        self.push_log("[DB]", self.last_encrypted_key_sync_status.clone());
    }

    fn push_log(&mut self, tag: &str, message: impl AsRef<str>) {
        let message = message.as_ref();
        self.event_log.push(timestamped(tag, message));
        if let Err(error) = self.controller.save_log_entry(tag, message) {
            self.event_log.push(timestamped(
                "[ERROR]",
                &format!("Persistent log write failed: {}", error),
            ));
        }
    }
}

struct WorkflowStep<'a> {
    icon_name: &'static str,
    title: &'a str,
    description: &'a str,
    status: ChipState,
    button_label: &'a str,
    message: Message,
}

#[derive(Clone, Copy)]
struct ChipState {
    status: StepStatus,
    label: &'static str,
}

#[derive(Clone, Copy)]
enum StepStatus {
    Pending,
    Completed,
    Error,
}

#[derive(Clone, Copy)]
enum PanelKind {
    Window,
    Status,
    Panel,
    Elevated,
    Log,
    Detail,
    StepCard,
    SuccessCard,
    ProgressCard,
    StatusChip(StepStatus),
    StatusDot(Color),
    Badge,
}

#[derive(Clone, Copy)]
struct PanelStyle {
    kind: PanelKind,
}

impl iced::widget::container::StyleSheet for PanelStyle {
    type Style = Theme;

    fn appearance(&self, _style: &Self::Style) -> iced::widget::container::Appearance {
        let (background, border_color, radius) = match self.kind {
            PanelKind::Window => (WINDOW_BG, WINDOW_BG, 0.0),
            PanelKind::Status => (STATUS_PANEL_BG, BORDER, 7.0),
            PanelKind::Panel => (PANEL_BG, BORDER, 7.0),
            PanelKind::Elevated => (ELEVATED_BG, BORDER, 7.0),
            PanelKind::Log => (LOG_BG, BORDER, 7.0),
            PanelKind::Detail => (PANEL_BG, BORDER, 6.0),
            PanelKind::StepCard => (PANEL_BG, BUTTON_BORDER, 6.0),
            PanelKind::SuccessCard => (
                Color::from_rgb(0.095, 0.16, 0.13),
                Color::from_rgb(0.24, 0.42, 0.28),
                7.0,
            ),
            PanelKind::ProgressCard => (PENDING_BG, PENDING_BORDER, 7.0),
            PanelKind::StatusChip(status) => match status {
                StepStatus::Pending => (PENDING_BG, PENDING_BORDER, 5.0),
                StepStatus::Completed => (Color::from_rgb(0.11, 0.14, 0.12), SUCCESS_GREEN, 5.0),
                StepStatus::Error => (Color::from_rgb(0.18, 0.105, 0.115), DANGER_RED, 5.0),
            },
            PanelKind::StatusDot(color) => (color, color, 999.0),
            PanelKind::Badge => (BUTTON_BG, BUTTON_BORDER, 5.0),
        };

        iced::widget::container::Appearance {
            text_color: Some(PRIMARY_TEXT),
            background: Some(Background::Color(background)),
            border: Border {
                color: border_color,
                width: if matches!(self.kind, PanelKind::Window) {
                    0.0
                } else {
                    1.0
                },
                radius: radius.into(),
            },
            ..Default::default()
        }
    }
}

#[derive(Clone, Copy)]
enum ButtonKind {
    StepAction,
    Nav,
    Tab(bool),
    Artifact(bool),
}

#[derive(Clone, Copy)]
struct ButtonStyle {
    kind: ButtonKind,
}

impl iced::widget::button::StyleSheet for ButtonStyle {
    type Style = Theme;

    fn active(&self, _style: &Self::Style) -> iced::widget::button::Appearance {
        let (text_color, border_color) = match self.kind {
            ButtonKind::StepAction => (PRIMARY_TEXT, ACCENT_PINK),
            ButtonKind::Nav => (ACCENT_BLUE, ACCENT_BLUE),
            ButtonKind::Tab(selected) => {
                if selected {
                    (ACCENT_PINK, ACCENT_PINK)
                } else {
                    (SECONDARY_TEXT, BUTTON_BORDER)
                }
            }
            ButtonKind::Artifact(selected) => {
                if selected {
                    (ACCENT_BLUE, ACCENT_BLUE)
                } else {
                    (SECONDARY_TEXT, BUTTON_BORDER)
                }
            }
        };

        iced::widget::button::Appearance {
            background: Some(Background::Color(BUTTON_BG)),
            text_color,
            border: Border {
                color: border_color,
                width: 1.0,
                radius: 5.0.into(),
            },
            ..Default::default()
        }
    }

    fn hovered(&self, style: &Self::Style) -> iced::widget::button::Appearance {
        iced::widget::button::Appearance {
            background: Some(Background::Color(BUTTON_HOVER_BG)),
            ..self.active(style)
        }
    }

    fn pressed(&self, style: &Self::Style) -> iced::widget::button::Appearance {
        iced::widget::button::Appearance {
            background: Some(Background::Color(ELEVATED_BG)),
            ..self.active(style)
        }
    }
}

fn container_style(kind: PanelKind) -> theme::Container {
    theme::Container::Custom(Box::new(PanelStyle { kind }))
}

fn button_style(kind: ButtonKind) -> theme::Button {
    theme::Button::custom(ButtonStyle { kind })
}

fn styled_button<'a>(
    icon_name: &'static str,
    label: &'a str,
    message: Message,
    kind: ButtonKind,
) -> Element<'a, Message> {
    button(
        row![
            icon(icon_name, 18),
            text(label).size(12).font(Font::MONOSPACE)
        ]
        .spacing(8),
    )
    .width(Length::Fill)
    .padding([7, 9])
    .style(button_style(kind))
    .on_press(message)
    .into()
}

fn tab_button<'a>(
    icon_name: &'static str,
    label: &'a str,
    tab: MainTab,
    selected_tab: MainTab,
) -> Element<'a, Message> {
    button(
        row![
            icon(icon_name, 17),
            text(label).size(12).font(Font::MONOSPACE)
        ]
        .spacing(8)
        .align_items(Alignment::Center),
    )
    .width(Length::Fill)
    .padding([8, 10])
    .style(button_style(ButtonKind::Tab(tab == selected_tab)))
    .on_press(Message::SelectTab(tab))
    .into()
}

fn artifact_button<'a>(
    icon_name: &'static str,
    label: &'a str,
    section: ArtifactSection,
    selected_section: ArtifactSection,
) -> Element<'a, Message> {
    button(
        row![
            icon(icon_name, 17),
            text(label).size(12).font(Font::MONOSPACE)
        ]
        .spacing(8)
        .align_items(Alignment::Center),
    )
    .width(Length::Fill)
    .padding([8, 10])
    .style(button_style(ButtonKind::Artifact(
        section == selected_section,
    )))
    .on_press(Message::SelectArtifact(section))
    .into()
}

fn compact_button<'a>(
    icon_name: &'static str,
    label: &'a str,
    message: Message,
    kind: ButtonKind,
) -> Element<'a, Message> {
    button(
        row![
            icon(icon_name, 16),
            text(label).size(11).font(Font::MONOSPACE)
        ]
        .spacing(7)
        .align_items(Alignment::Center),
    )
    .width(Length::Fixed(190.0))
    .padding([7, 9])
    .style(button_style(kind))
    .on_press(message)
    .into()
}

fn status_chip(state: ChipState) -> Element<'static, Message> {
    let text_color = step_status_color(state.status);
    let dot_color = step_status_dot_color(state.status);

    container(
        row![
            status_dot(dot_color),
            text(state.label)
                .size(11)
                .font(Font::MONOSPACE)
                .style(theme::Text::Color(text_color)),
        ]
        .spacing(6)
        .align_items(Alignment::Center),
    )
    .width(Length::Fixed(112.0))
    .padding([6, 8])
    .style(container_style(PanelKind::StatusChip(state.status)))
    .into()
}

fn status_dot(color: Color) -> Element<'static, Message> {
    container(text(""))
        .width(Length::Fixed(7.0))
        .height(Length::Fixed(7.0))
        .style(container_style(PanelKind::StatusDot(color)))
        .into()
}

fn icon(name: &'static str, size: u16) -> Element<'static, Message> {
    let path = format!("{}/{}.svg", ICON_DIR, name);

    Svg::from_path(path)
        .width(Length::Fixed(f32::from(size)))
        .height(Length::Fixed(f32::from(size)))
        .into()
}

fn status_badge(label: &str) -> Element<'_, Message> {
    container(
        text(label)
            .size(12)
            .font(Font::MONOSPACE)
            .style(theme::Text::Color(badge_color(label))),
    )
    .padding([5, 8])
    .style(container_style(PanelKind::Badge))
    .into()
}

fn badge_color(value: &str) -> Color {
    match value {
        "Not Initialized" => PENDING_TEXT,
        "Vehicle Connected"
        | "Connected"
        | "Detected"
        | "Stored"
        | "Generated"
        | "Signed"
        | "Exported"
        | "Viewed"
        | "Issued"
        | "Granted"
        | "Verified"
        | "Active"
        | "Access Granted"
        | "Valid"
        | "Complete"
        | "CA-signed certificate issued"
        | "Trust root initialized"
        | "Trust Ready"
        | "Key Fob Registered"
        | "Access Certificate Issued"
        | "Key Verified"
        | "Session Active" => SUCCESS_GREEN,
        "Error" | "Failed" => DANGER_RED,
        _ => PRIMARY_TEXT,
    }
}

fn status_color(value: &str) -> Color {
    match value {
        "Connected"
        | "Detected"
        | "Registered"
        | "Initialized"
        | "Viewed"
        | "Generated"
        | "Signed"
        | "Stored"
        | "Exported"
        | "Issued"
        | "Verified"
        | "Active"
        | "Yes"
        | "Access Granted"
        | "Granted"
        | "Valid"
        | "Complete"
        | "CA-signed certificate issued"
        | "Trust root initialized" => SUCCESS_GREEN,
        "Pending"
        | "Not Initialized"
        | "Not Registered"
        | "Not Issued"
        | "Not Run"
        | "Not Established"
        | "N/A"
        | "Provisioning In Progress" => PENDING_TEXT,
        "Error" | "Failed" | "Rejected" | "Access Rejected" | "Certificate trust error" => {
            DANGER_RED
        }
        _ => PRIMARY_TEXT,
    }
}

fn step_status_color(status: StepStatus) -> Color {
    match status {
        StepStatus::Pending => PENDING_TEXT,
        StepStatus::Completed => SUCCESS_GREEN,
        StepStatus::Error => DANGER_RED,
    }
}

fn step_status_dot_color(status: StepStatus) -> Color {
    match status {
        StepStatus::Pending => PENDING_DOT,
        StepStatus::Completed => SUCCESS_GREEN,
        StepStatus::Error => DANGER_RED,
    }
}

fn log_tag_color(tag: &str) -> Color {
    match tag {
        "[INFO]" => ACCENT_BLUE,
        "[AUTH]" => ACCENT_PINK,
        "[SESSION]" => SUCCESS_GREEN,
        "[ATTACK]" | "[ERROR]" => DANGER_RED,
        "[WARN]" => WARNING_YELLOW,
        _ => SECONDARY_TEXT,
    }
}

fn log_parts(entry: &str) -> (&str, &str, &str) {
    let mut parts = entry.splitn(3, ' ');
    let timestamp = parts.next().unwrap_or("");
    let tag = parts.next().unwrap_or("");
    let message = parts.next().unwrap_or("");

    (timestamp, tag, message)
}

fn split_storage_line(line: &str) -> (&str, &str) {
    line.split_once(':')
        .map(|(label, value)| (label.trim(), value.trim()))
        .unwrap_or(("Storage Entry", line))
}

fn trace_parts(entry: &str) -> (&str, &str) {
    entry
        .split_once(' ')
        .map_or(("", entry), |(tag, message)| (tag, message))
}

fn timestamped(tag: &str, message: &str) -> String {
    format!("{} {} {}", Local::now().format("%H:%M:%S"), tag, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_sync_gui_status_line_redacts_sensitive_material() {
        assert!(AUDIT_SYNC_REDACTION_LINE.contains("[REDACTED]"));
        assert!(AUDIT_SYNC_REDACTION_LINE.contains("Raw session key: [REDACTED]"));
        assert!(AUDIT_SYNC_REDACTION_LINE.contains("Private key material: [REDACTED]"));
        assert!(!AUDIT_SYNC_REDACTION_LINE.contains("DATABASE_URL"));
        assert!(!AUDIT_SYNC_REDACTION_LINE.contains("AIACS_MASTER_KEY"));
        assert!(!AUDIT_SYNC_REDACTION_LINE.contains("encrypted_key_blob"));
        assert!(!AUDIT_SYNC_REDACTION_LINE.contains("encryption_nonce"));
    }

    #[test]
    fn diagnostic_sync_gui_status_line_redacts_sensitive_material() {
        assert!(DIAGNOSTIC_SYNC_REDACTION_LINE.contains("[REDACTED]"));
        assert!(DIAGNOSTIC_SYNC_REDACTION_LINE.contains("Raw attack payloads: [REDACTED]"));
        assert!(!DIAGNOSTIC_SYNC_REDACTION_LINE.contains("DATABASE_URL"));
        assert!(!DIAGNOSTIC_SYNC_REDACTION_LINE.contains("AIACS_MASTER_KEY"));
        assert!(!DIAGNOSTIC_SYNC_REDACTION_LINE.contains("raw_ciphertext"));
        assert!(!DIAGNOSTIC_SYNC_REDACTION_LINE.contains("raw_nonce"));
        assert!(!DIAGNOSTIC_SYNC_REDACTION_LINE.contains("encrypted_key_blob"));
        assert!(!DIAGNOSTIC_SYNC_REDACTION_LINE.contains("encryption_nonce"));
    }
}
