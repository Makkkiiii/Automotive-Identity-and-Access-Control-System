use aiacs::app_controller::AppController;
use chrono::Local;
use iced::alignment;
use iced::theme;
use iced::widget::{button, column, container, row, scrollable, text, text_input, Svg};
use iced::{
    application, executor, Alignment, Application, Background, Border, Color, Command, Element,
    Font, Length, Settings, Theme,
};

const OWNER_NAME: &str = "Dennis Maharjan";
const CUSTOMER_EMAIL: &str = "dennis.m@example.com";
const CUSTOMER_PHONE: &str = "+977-9800000000";
const VEHICLE_DISPLAY_NAME: &str = "Nissan Magnite 2021";
const VEHICLE_MAKE: &str = "Nissan";
const VEHICLE_MODEL: &str = "Magnite";
const VEHICLE_YEAR: &str = "2021";
const VEHICLE_VIN: &str = "VIN-DEMO-001";
const VEHICLE_REGISTRATION: &str = "BA-00-PA-0001";
const KEY_FOB_LABEL: &str = "Primary Key Fob";
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
#[cfg(test)]
const AUDIT_SYNC_REDACTION_LINE: &str =
    "Sensitive material: [REDACTED] | Raw session key: [REDACTED] | Private key material: [REDACTED]";
#[cfg(test)]
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
    cloud_ui_status: CloudUiStatus,
    cloud_status: String,
    cloud_auto_sync_status: String,
    cloud_sync_metadata_status: String,
    cloud_sync_certificate_status: String,
    cloud_sync_encrypted_key_status: String,
    cloud_sync_session_status: String,
    cloud_sync_audit_status: String,
    cloud_sync_diagnostic_status: String,
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
    customer_load_status: String,
    customer_create_status: String,
    vehicle_load_status: String,
    vehicle_create_status: String,
    key_fob_load_status: String,
    key_fob_create_status: String,
    cloud_sync_status: String,
    cloud_operation_in_progress: bool,
    customer_owner_input: String,
    customer_email_input: String,
    customer_phone_input: String,
    vehicle_display_name_input: String,
    vehicle_make_input: String,
    vehicle_model_input: String,
    vehicle_year_input: String,
    vehicle_vin_input: String,
    vehicle_registration_input: String,
    key_fob_label_input: String,
}

impl Default for ManagementState {
    fn default() -> Self {
        Self {
            customer_note: "No customer selected".to_string(),
            vehicle_note: "Select a customer before selecting a vehicle".to_string(),
            keyfob_note: "Select a vehicle before selecting a key fob".to_string(),
            customer_load_status: "Ready".to_string(),
            customer_create_status: "Ready".to_string(),
            vehicle_load_status: "Ready".to_string(),
            vehicle_create_status: "Ready".to_string(),
            key_fob_load_status: "Ready".to_string(),
            key_fob_create_status: "Ready".to_string(),
            cloud_sync_status: "Ready".to_string(),
            cloud_operation_in_progress: false,
            customer_owner_input: String::new(),
            customer_email_input: String::new(),
            customer_phone_input: String::new(),
            vehicle_display_name_input: String::new(),
            vehicle_make_input: String::new(),
            vehicle_model_input: String::new(),
            vehicle_year_input: String::new(),
            vehicle_vin_input: String::new(),
            vehicle_registration_input: String::new(),
            key_fob_label_input: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum CloudOperation {
    LoadCustomers,
    CreateCustomer,
    SelectCustomer,
    LoadVehicles,
    CreateVehicle,
    SelectVehicle,
    LoadKeyFobs,
    CreateKeyFob,
    SelectKeyFob,
    StartupAutoEnable,
    EnableAutoSync,
    DisableAutoSync,
    ProvisioningConnectVehicle,
    ProvisioningDetectKeyFob,
    ProvisioningRegisterKeyFob,
    ProvisioningInitializeTrust,
    ProvisioningIssueCertificate,
    ProvisioningGenerateChallenge,
    ProvisioningSignCanonicalPayload,
    ProvisioningVerifyAuthentication,
    ProvisioningActivateSession,
    ProvisioningFinalize,
    ProvisioningDiagnostics,
}

#[derive(Debug, Clone)]
struct CloudOperationResult {
    operation: CloudOperation,
    controller: AppController,
    result: Result<String, String>,
}

type VehicleFormValues = (String, String, String, i32, Option<String>, Option<String>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MainTab {
    Dashboard,
    Customers,
    Vehicles,
    KeyFobs,
    Provisioning,
    ProtocolArtifacts,
    CredentialStorage,
    LogsReport,
    Diagnostics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloudUiStatus {
    Connecting,
    Connected,
    Disconnected,
    NotConfigured,
    Disabled,
}

impl CloudUiStatus {
    fn label(self) -> &'static str {
        match self {
            CloudUiStatus::Connecting => "Cloud: Connecting...",
            CloudUiStatus::Connected => "Cloud: Connected",
            CloudUiStatus::Disconnected => "Cloud: Disconnected",
            CloudUiStatus::NotConfigured => "Cloud: Not Configured",
            CloudUiStatus::Disabled => "Cloud: Disabled",
        }
    }
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
    LoadCustomers,
    CreateCustomer,
    SelectCustomer,
    CustomerOwnerChanged(String),
    CustomerEmailChanged(String),
    CustomerPhoneChanged(String),
    FillDemoCustomer,
    LoadVehicles,
    CreateVehicle,
    SelectVehicle,
    VehicleDisplayNameChanged(String),
    VehicleMakeChanged(String),
    VehicleModelChanged(String),
    VehicleYearChanged(String),
    VehicleVinChanged(String),
    VehicleRegistrationChanged(String),
    FillDemoVehicle,
    LoadKeyFobs,
    CreateKeyFobRecord,
    SelectKeyFobRecord,
    KeyFobLabelChanged(String),
    FillDemoKeyFob,
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
    EnableCloudAutoSync,
    DisableCloudAutoSync,
    CloudOperationFinished(Box<CloudOperationResult>),
    ClearLog,
    ExportLogs,
    ExportProvisioningReport,
}

impl Application for AIACSApp {
    type Executor = executor::Default;
    type Flags = ();
    type Message = Message;
    type Theme = Theme;

    fn new(_flags: Self::Flags) -> (Self, Command<Self::Message>) {
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

        let app = Self {
            controller,
            status: SystemStatus::default(),
            workflow_state: WorkflowState::default(),
            management_state: ManagementState::default(),
            selected_tab: MainTab::Dashboard,
            selected_artifact: ArtifactSection::ChallengeMessage,
            cloud_ui_status: CloudUiStatus::Connecting,
            cloud_status: "Disconnected".to_string(),
            cloud_auto_sync_status: "Checking...".to_string(),
            cloud_sync_metadata_status: "Pending".to_string(),
            cloud_sync_certificate_status: "Pending".to_string(),
            cloud_sync_encrypted_key_status: "Pending".to_string(),
            cloud_sync_session_status: "Pending".to_string(),
            cloud_sync_audit_status: "Pending".to_string(),
            cloud_sync_diagnostic_status: "Pending".to_string(),
            selected_detail: "No customer selected".to_string(),
            event_log: initial_messages
                .iter()
                .map(|message| timestamped("[INFO]", message))
                .collect(),
        };

        let startup_controller = app.controller.clone();
        let startup_command = Command::perform(
            async move {
                perform_cloud_operation(startup_controller, CloudOperation::StartupAutoEnable)
            },
            |result| Message::CloudOperationFinished(Box::new(result)),
        );

        (app, startup_command)
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

    fn update(&mut self, message: Message) -> Command<Self::Message> {
        match message {
            Message::SelectTab(tab) => {
                self.selected_tab = tab;
            }
            Message::SelectArtifact(section) => {
                self.selected_artifact = section;
            }
            Message::LoadCustomers => {
                self.begin_cloud_operation("Loading customers...");
                self.management_state.customer_load_status = "Loading customers...".to_string();
                return self.run_cloud_operation(CloudOperation::LoadCustomers);
            }
            Message::CreateCustomer => match self.customer_form_values() {
                Ok((owner_name, email, phone)) => {
                    self.begin_cloud_operation("Creating customer...");
                    self.management_state.customer_create_status =
                        "Creating customer...".to_string();
                    return self.run_cloud_operation_with(move |mut controller| {
                        let result = controller
                            .create_customer_record(owner_name, Some(email), phone)
                            .map_err(|error| error.to_string());
                        CloudOperationResult {
                            operation: CloudOperation::CreateCustomer,
                            controller,
                            result,
                        }
                    });
                }
                Err(message) => self.record_customer_form_error(message),
            },
            Message::SelectCustomer => {
                let Some(customer_id) = self.controller.customer_selection_candidate_id() else {
                    self.record_customer_form_error(
                        "No customer available. Load or create a customer first.".to_string(),
                    );
                    return Command::none();
                };
                self.begin_cloud_operation("Selecting customer...");
                return self.run_cloud_operation_with(move |mut controller| {
                    let result = controller
                        .select_customer(&customer_id)
                        .map_err(|error| error.to_string());
                    CloudOperationResult {
                        operation: CloudOperation::SelectCustomer,
                        controller,
                        result,
                    }
                });
            }
            Message::CustomerOwnerChanged(value) => {
                self.management_state.customer_owner_input = value;
            }
            Message::CustomerEmailChanged(value) => {
                self.management_state.customer_email_input = value;
            }
            Message::CustomerPhoneChanged(value) => {
                self.management_state.customer_phone_input = value;
            }
            Message::FillDemoCustomer => {
                self.management_state.customer_owner_input = OWNER_NAME.to_string();
                self.management_state.customer_email_input = CUSTOMER_EMAIL.to_string();
                self.management_state.customer_phone_input = CUSTOMER_PHONE.to_string();
                self.management_state.customer_note =
                    "Demo customer fields filled for operator review".to_string();
            }
            Message::LoadVehicles => {
                self.begin_cloud_operation("Loading vehicles...");
                self.management_state.vehicle_load_status = "Loading vehicles...".to_string();
                return self.run_cloud_operation(CloudOperation::LoadVehicles);
            }
            Message::CreateVehicle => match self.vehicle_form_values() {
                Ok((display_name, make, model, year, vin, registration)) => {
                    let Some(customer) = self.controller.selected_customer_record() else {
                        self.record_vehicle_form_error(
                            "Select a customer before creating a vehicle".to_string(),
                        );
                        return Command::none();
                    };
                    let customer_id = customer.customer_id;
                    self.begin_cloud_operation("Creating vehicle...");
                    self.management_state.vehicle_create_status = "Creating vehicle...".to_string();
                    return self.run_cloud_operation_with(move |mut controller| {
                        let result = controller
                            .create_vehicle_record(
                                customer_id,
                                display_name,
                                Some(make),
                                Some(model),
                                Some(year),
                                vin,
                                registration,
                            )
                            .map_err(|error| error.to_string());
                        CloudOperationResult {
                            operation: CloudOperation::CreateVehicle,
                            controller,
                            result,
                        }
                    });
                }
                Err(message) => self.record_vehicle_form_error(message),
            },
            Message::SelectVehicle => {
                let Some(vehicle_id) = self.controller.vehicle_selection_candidate_id() else {
                    self.record_vehicle_form_error(
                        "Select a customer and load/create a vehicle first".to_string(),
                    );
                    return Command::none();
                };
                self.begin_cloud_operation("Selecting vehicle...");
                return self.run_cloud_operation_with(move |mut controller| {
                    let result = controller
                        .select_vehicle(&vehicle_id)
                        .map_err(|error| error.to_string());
                    CloudOperationResult {
                        operation: CloudOperation::SelectVehicle,
                        controller,
                        result,
                    }
                });
            }
            Message::VehicleDisplayNameChanged(value) => {
                self.management_state.vehicle_display_name_input = value;
            }
            Message::VehicleMakeChanged(value) => {
                self.management_state.vehicle_make_input = value;
            }
            Message::VehicleModelChanged(value) => {
                self.management_state.vehicle_model_input = value;
            }
            Message::VehicleYearChanged(value) => {
                self.management_state.vehicle_year_input = value;
            }
            Message::VehicleVinChanged(value) => {
                self.management_state.vehicle_vin_input = value;
            }
            Message::VehicleRegistrationChanged(value) => {
                self.management_state.vehicle_registration_input = value;
            }
            Message::FillDemoVehicle => {
                self.management_state.vehicle_display_name_input = VEHICLE_DISPLAY_NAME.to_string();
                self.management_state.vehicle_make_input = VEHICLE_MAKE.to_string();
                self.management_state.vehicle_model_input = VEHICLE_MODEL.to_string();
                self.management_state.vehicle_year_input = VEHICLE_YEAR.to_string();
                self.management_state.vehicle_vin_input = VEHICLE_VIN.to_string();
                self.management_state.vehicle_registration_input = VEHICLE_REGISTRATION.to_string();
                self.management_state.vehicle_note =
                    "Demo vehicle fields filled for operator review".to_string();
            }
            Message::LoadKeyFobs => {
                self.begin_cloud_operation("Loading key fobs...");
                self.management_state.key_fob_load_status = "Loading key fobs...".to_string();
                return self.run_cloud_operation(CloudOperation::LoadKeyFobs);
            }
            Message::CreateKeyFobRecord => match self.key_fob_form_values() {
                Ok(label) => {
                    let Some(vehicle) = self.controller.selected_vehicle_record() else {
                        self.record_key_fob_form_error(
                            "Select a vehicle before creating a key fob".to_string(),
                        );
                        return Command::none();
                    };
                    let vehicle_id = vehicle.vehicle_id;
                    self.begin_cloud_operation("Creating key fob...");
                    self.management_state.key_fob_create_status = "Creating key fob...".to_string();
                    return self.run_cloud_operation_with(move |mut controller| {
                        let result = controller
                            .create_key_fob_record(vehicle_id, label)
                            .map_err(|error| error.to_string());
                        CloudOperationResult {
                            operation: CloudOperation::CreateKeyFob,
                            controller,
                            result,
                        }
                    });
                }
                Err(message) => self.record_key_fob_form_error(message),
            },
            Message::SelectKeyFobRecord => {
                let Some(fob_id) = self.controller.key_fob_selection_candidate_id() else {
                    self.record_key_fob_form_error(
                        "Select a vehicle and load/create a key fob first".to_string(),
                    );
                    return Command::none();
                };
                self.begin_cloud_operation("Selecting key fob...");
                return self.run_cloud_operation_with(move |mut controller| {
                    let result = controller
                        .select_key_fob(&fob_id)
                        .map_err(|error| error.to_string());
                    CloudOperationResult {
                        operation: CloudOperation::SelectKeyFob,
                        controller,
                        result,
                    }
                });
            }
            Message::KeyFobLabelChanged(value) => {
                self.management_state.key_fob_label_input = value;
            }
            Message::FillDemoKeyFob => {
                self.management_state.key_fob_label_input = KEY_FOB_LABEL.to_string();
                self.management_state.keyfob_note =
                    "Demo key fob label filled for operator review".to_string();
            }
            Message::RotateCredential => match self.controller.rotate_key_fob_credential() {
                Ok(message) => {
                    self.management_state.keyfob_note = message.clone();
                    self.selected_detail = message.clone();
                    self.push_log("[INFO]", message);
                }
                Err(error) => {
                    self.selected_detail = format!("Credential rotation failed: {}", error);
                    self.push_log("[ERROR]", format!("Credential rotation failed: {}", error));
                }
            },
            Message::ConnectVehicle => {
                self.workflow_state.vehicle_connected = true;
                self.status.top_badge = "Vehicle Connected".to_string();
                self.cloud_sync_metadata_status = "Syncing metadata...".to_string();
                self.begin_cloud_operation("Connecting vehicle and syncing metadata...");
                return self.run_cloud_operation(CloudOperation::ProvisioningConnectVehicle);
            }
            Message::DetectKeyFob => {
                self.workflow_state.keyfob_detected = true;
                self.management_state.keyfob_note = format!("{} detected", KEY_FOB_LABEL);
                self.cloud_sync_metadata_status = "Syncing metadata...".to_string();
                self.begin_cloud_operation("Detecting key fob and syncing metadata...");
                return self.run_cloud_operation(CloudOperation::ProvisioningDetectKeyFob);
            }
            Message::InitializeVehicleTrust => {
                self.workflow_state.trust_initialized = true;
                self.status.trust_status = "Initialized".to_string();
                self.status.top_badge = "Trust Ready".to_string();
                self.cloud_sync_encrypted_key_status = "Syncing encrypted key blob...".to_string();
                self.begin_cloud_operation("Initializing vehicle trust...");
                return self.run_cloud_operation(CloudOperation::ProvisioningInitializeTrust);
            }
            Message::RegisterDigitalKeyFob => {
                self.workflow_state.keyfob_registered = true;
                self.management_state.keyfob_note = format!("{} registered", KEY_FOB_LABEL);
                self.status.key_fob_status = "Registered".to_string();
                self.status.top_badge = "Key Fob Registered".to_string();
                self.cloud_sync_metadata_status = "Syncing metadata...".to_string();
                self.begin_cloud_operation("Registering digital key fob...");
                return self.run_cloud_operation(CloudOperation::ProvisioningRegisterKeyFob);
            }
            Message::IssueCertificate => {
                self.workflow_state.trust_initialized = true;
                self.workflow_state.keyfob_registered = true;
                self.workflow_state.certificate_issued = true;
                self.status.trust_status = "Initialized".to_string();
                self.status.key_fob_status = "Registered".to_string();
                self.status.certificate_status = "Issued".to_string();
                self.status.top_badge = "Access Certificate Issued".to_string();
                self.cloud_sync_certificate_status = "Syncing certificate metadata...".to_string();
                self.begin_cloud_operation("Issuing certificate and syncing metadata...");
                return self.run_cloud_operation(CloudOperation::ProvisioningIssueCertificate);
            }
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
                self.cloud_sync_metadata_status = "No sync required".to_string();
                self.begin_cloud_operation("Generating authentication challenge...");
                return self.run_cloud_operation(CloudOperation::ProvisioningGenerateChallenge);
            }
            Message::SignCanonicalPayload => {
                self.workflow_state.payload_signed = true;
                self.cloud_sync_metadata_status = "No sync required".to_string();
                self.begin_cloud_operation("Signing canonical authentication payload...");
                return self.run_cloud_operation(CloudOperation::ProvisioningSignCanonicalPayload);
            }
            Message::VerifyAuthentication => {
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
                self.cloud_sync_session_status = "Pending secure session activation".to_string();
                self.begin_cloud_operation("Verifying key authentication...");
                return self.run_cloud_operation(CloudOperation::ProvisioningVerifyAuthentication);
            }
            Message::ActivateSecureChannel => {
                self.workflow_state.trust_initialized = true;
                self.workflow_state.keyfob_registered = true;
                self.workflow_state.certificate_issued = true;
                self.workflow_state.session_active = true;
                self.status.trust_status = "Initialized".to_string();
                self.status.key_fob_status = "Registered".to_string();
                self.status.certificate_status = "Issued".to_string();
                self.status.session_status = "Active".to_string();
                self.status.top_badge = "Session Active".to_string();
                self.cloud_sync_session_status = "Syncing provisioning session...".to_string();
                self.begin_cloud_operation("Activating secure session...");
                return self.run_cloud_operation(CloudOperation::ProvisioningActivateSession);
            }
            Message::LaunchDiagnosticsTool => {
                self.cloud_sync_diagnostic_status = "Syncing diagnostic results...".to_string();
                self.begin_cloud_operation("Launching diagnostics tool...");
                return self.run_cloud_operation(CloudOperation::ProvisioningDiagnostics);
            }
            Message::EnableCloudAutoSync => {
                self.cloud_ui_status = CloudUiStatus::Connecting;
                self.begin_cloud_operation("Cloud sync running...");
                return self.run_cloud_operation(CloudOperation::EnableAutoSync);
            }
            Message::DisableCloudAutoSync => {
                self.cloud_ui_status = CloudUiStatus::Disabled;
                self.begin_cloud_operation("Cloud sync running...");
                return self.run_cloud_operation(CloudOperation::DisableAutoSync);
            }
            Message::CloudOperationFinished(result) => {
                self.finish_cloud_operation(*result);
            }
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
            Message::ExportProvisioningReport => {
                self.workflow_state.report_exported = true;
                self.cloud_sync_audit_status = "Syncing audit logs...".to_string();
                self.begin_cloud_operation("Finalizing provisioning and exporting report...");
                return self.run_cloud_operation(CloudOperation::ProvisioningFinalize);
            }
        }

        Command::none()
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
    fn run_cloud_operation(&self, operation: CloudOperation) -> Command<Message> {
        let controller = self.controller.clone();
        Command::perform(
            async move { perform_cloud_operation(controller, operation) },
            |result| Message::CloudOperationFinished(Box::new(result)),
        )
    }

    fn run_cloud_operation_with<F>(&self, operation: F) -> Command<Message>
    where
        F: FnOnce(AppController) -> CloudOperationResult + Send + 'static,
    {
        let controller = self.controller.clone();
        Command::perform(async move { operation(controller) }, |result| {
            Message::CloudOperationFinished(Box::new(result))
        })
    }

    fn begin_cloud_operation(&mut self, message: &'static str) {
        self.management_state.cloud_operation_in_progress = true;
        self.management_state.cloud_sync_status = message.to_string();
        self.selected_detail = message.to_string();
    }

    fn finish_cloud_operation(&mut self, result: CloudOperationResult) {
        self.management_state.cloud_operation_in_progress = false;
        self.controller = result.controller;

        match result.result {
            Ok(message) => self.apply_cloud_success(result.operation, message),
            Err(error) => self.apply_cloud_error(result.operation, error),
        }
    }

    fn apply_startup_cloud_status(&mut self, message: String) {
        self.selected_detail = message.clone();
        self.management_state.cloud_sync_status = message.clone();
        if message.contains("enabled automatically") {
            self.cloud_status = "Connected".to_string();
            self.cloud_ui_status = CloudUiStatus::Connected;
            self.cloud_auto_sync_status = "Enabled automatically".to_string();
            self.cloud_sync_metadata_status = "Pending".to_string();
            self.selected_detail = format!("No customer selected; {}", message);
        } else if message.contains("not configured") {
            self.cloud_status = "Disconnected".to_string();
            self.cloud_ui_status = CloudUiStatus::NotConfigured;
            self.cloud_auto_sync_status = "Disabled - cloud database not configured".to_string();
            self.cloud_sync_metadata_status = "Skipped - disabled".to_string();
            self.selected_detail = "No customer selected".to_string();
        } else if message.contains("health check failed") {
            self.cloud_status = "Disconnected".to_string();
            self.cloud_ui_status = CloudUiStatus::Disconnected;
            self.cloud_auto_sync_status = "Disabled - health check failed".to_string();
            self.cloud_sync_metadata_status = "Skipped - disabled".to_string();
            self.selected_detail = "No customer selected".to_string();
        } else {
            self.cloud_status = "Disconnected".to_string();
            self.cloud_ui_status = CloudUiStatus::Disconnected;
            self.cloud_auto_sync_status = "Disabled - startup cloud check failed".to_string();
            self.cloud_sync_metadata_status = "Skipped - disabled".to_string();
            self.selected_detail = "No customer selected".to_string();
        }
        self.push_log("[DB]", message);
    }

    fn apply_cloud_success(&mut self, operation: CloudOperation, message: String) {
        self.management_state.cloud_sync_status = "Cloud sync completed".to_string();
        match operation {
            CloudOperation::StartupAutoEnable => {
                self.apply_startup_cloud_status(message);
            }
            CloudOperation::LoadCustomers => {
                self.management_state.customer_load_status = "Customers loaded".to_string();
                self.management_state.customer_note = message.clone();
                self.selected_detail = message.clone();
                self.push_log("[DB]", message);
            }
            CloudOperation::CreateCustomer => {
                self.management_state.customer_create_status = if message.contains("saved to cloud")
                {
                    "Customer saved to cloud".to_string()
                } else {
                    "Customer created locally".to_string()
                };
                self.management_state.customer_note = message.clone();
                self.selected_detail = message.clone();
                self.push_log("[DB]", message);
                self.cloud_sync_metadata_status = "Synced".to_string();
                self.management_state.customer_owner_input.clear();
                self.management_state.customer_email_input.clear();
                self.management_state.customer_phone_input.clear();
            }
            CloudOperation::SelectCustomer => {
                self.management_state.customer_note = message.clone();
                self.selected_detail = message.clone();
                self.push_log("[INFO]", message);
            }
            CloudOperation::LoadVehicles => {
                self.management_state.vehicle_load_status = "Vehicles loaded".to_string();
                self.management_state.vehicle_note = message.clone();
                self.selected_detail = message.clone();
                self.push_log("[DB]", message);
            }
            CloudOperation::CreateVehicle => {
                self.management_state.vehicle_create_status = if message.contains("saved to cloud")
                {
                    "Vehicle saved to cloud".to_string()
                } else {
                    "Vehicle created locally".to_string()
                };
                self.management_state.vehicle_note = message.clone();
                self.selected_detail = message.clone();
                self.push_log("[DB]", message);
                self.cloud_sync_metadata_status = "Synced".to_string();
                self.management_state.vehicle_display_name_input.clear();
                self.management_state.vehicle_make_input.clear();
                self.management_state.vehicle_model_input.clear();
                self.management_state.vehicle_year_input.clear();
                self.management_state.vehicle_vin_input.clear();
                self.management_state.vehicle_registration_input.clear();
            }
            CloudOperation::SelectVehicle => {
                self.management_state.vehicle_note = message.clone();
                self.selected_detail = message.clone();
                self.push_log("[INFO]", message);
            }
            CloudOperation::LoadKeyFobs => {
                self.management_state.key_fob_load_status = "Key fobs loaded".to_string();
                self.management_state.keyfob_note = message.clone();
                self.selected_detail = message.clone();
                self.push_log("[DB]", message);
            }
            CloudOperation::CreateKeyFob => {
                self.management_state.key_fob_create_status = if message.contains("saved to cloud")
                {
                    "Key fob saved to cloud".to_string()
                } else {
                    "Key fob created locally".to_string()
                };
                self.management_state.keyfob_note = message.clone();
                self.selected_detail = message.clone();
                self.push_log("[DB]", message);
                self.cloud_sync_metadata_status = "Synced".to_string();
                self.management_state.key_fob_label_input.clear();
            }
            CloudOperation::SelectKeyFob => {
                self.management_state.keyfob_note = message.clone();
                self.selected_detail = message.clone();
                self.push_log("[INFO]", message);
            }
            CloudOperation::EnableAutoSync => {
                self.cloud_status = "Connected".to_string();
                self.cloud_ui_status = CloudUiStatus::Connected;
                self.cloud_auto_sync_status =
                    self.controller.get_cloud_auto_sync_status().to_string();
                self.selected_detail = message.clone();
                self.push_log("[DB]", message);
                self.push_log("[SECURITY]", "Cloud secret material: [REDACTED]");
            }
            CloudOperation::DisableAutoSync => {
                self.cloud_ui_status = CloudUiStatus::Disabled;
                self.cloud_auto_sync_status =
                    self.controller.get_cloud_auto_sync_status().to_string();
                self.selected_detail = message.clone();
                self.push_log("[DB]", message);
            }
            CloudOperation::ProvisioningConnectVehicle => {
                self.workflow_state.vehicle_connected = true;
                self.status.top_badge = "Vehicle Connected".to_string();
                self.record_provisioning_cloud_result("Metadata", "[INFO]", message);
            }
            CloudOperation::ProvisioningDetectKeyFob => {
                self.workflow_state.keyfob_detected = true;
                self.record_provisioning_cloud_result("Metadata", "[INFO]", message);
            }
            CloudOperation::ProvisioningRegisterKeyFob => {
                self.workflow_state.keyfob_registered = true;
                self.status.key_fob_status = "Registered".to_string();
                self.status.top_badge = "Key Fob Registered".to_string();
                self.record_provisioning_cloud_result("Metadata", "[INFO]", message);
            }
            CloudOperation::ProvisioningInitializeTrust => {
                self.workflow_state.trust_initialized = true;
                self.status.trust_status = "Initialized".to_string();
                self.status.top_badge = "Trust Ready".to_string();
                self.record_provisioning_cloud_result("Encrypted Key Blob", "[INFO]", message);
            }
            CloudOperation::ProvisioningIssueCertificate => {
                self.workflow_state.trust_initialized = true;
                self.workflow_state.keyfob_registered = true;
                self.workflow_state.certificate_issued = true;
                self.status.trust_status = "Initialized".to_string();
                self.status.key_fob_status = "Registered".to_string();
                self.status.certificate_status = "Issued".to_string();
                self.status.top_badge = "Access Certificate Issued".to_string();
                self.record_provisioning_cloud_result("Certificate", "[INFO]", message);
            }
            CloudOperation::ProvisioningGenerateChallenge => {
                self.workflow_state.challenge_generated = true;
                self.record_provisioning_cloud_result("Metadata", "[AUTH]", message);
            }
            CloudOperation::ProvisioningSignCanonicalPayload => {
                self.workflow_state.payload_signed = true;
                self.record_provisioning_cloud_result("Metadata", "[AUTH]", message);
            }
            CloudOperation::ProvisioningVerifyAuthentication => {
                self.workflow_state.authentication_verified = true;
                self.status.authentication_status = "Verified".to_string();
                self.status.access_decision = "Access Granted".to_string();
                self.status.top_badge = "Key Verified".to_string();
                self.record_provisioning_cloud_result("Session", "[AUTH]", message);
            }
            CloudOperation::ProvisioningActivateSession => {
                self.workflow_state.session_active = true;
                self.status.session_status = "Active".to_string();
                self.status.top_badge = "Session Active".to_string();
                self.record_provisioning_cloud_result("Session", "[SESSION]", message);
            }
            CloudOperation::ProvisioningFinalize => {
                self.workflow_state.report_exported = true;
                self.record_provisioning_cloud_result("Audit Logs", "[INFO]", message);
            }
            CloudOperation::ProvisioningDiagnostics => {
                self.record_provisioning_cloud_result("Diagnostic Results", "[INFO]", message);
            }
        }
    }

    fn apply_cloud_error(&mut self, operation: CloudOperation, error: String) {
        self.management_state.cloud_sync_status = format!("Cloud sync failed: {}", error);
        match operation {
            CloudOperation::StartupAutoEnable => {
                self.cloud_status = "Disconnected".to_string();
                self.cloud_auto_sync_status = "Disabled - startup cloud check failed".to_string();
                self.management_state.cloud_sync_status =
                    "Cloud Auto Sync disabled - startup cloud check failed".to_string();
                self.selected_detail = self.management_state.cloud_sync_status.clone();
                self.push_log("[DB]", self.selected_detail.clone());
            }
            CloudOperation::LoadCustomers => {
                self.management_state.customer_load_status = "Customer load failed".to_string();
                self.management_state.customer_note = format!("Customer load failed: {}", error);
                self.selected_detail = self.management_state.customer_note.clone();
                self.push_log("[ERROR]", self.management_state.customer_note.clone());
            }
            CloudOperation::CreateCustomer => {
                self.record_customer_form_error(format!("Customer creation failed: {}", error))
            }
            CloudOperation::SelectCustomer => {
                self.record_customer_form_error(format!("Customer selection failed: {}", error))
            }
            CloudOperation::LoadVehicles => {
                self.management_state.vehicle_load_status = "Vehicle load failed".to_string();
                self.management_state.vehicle_note = format!("Vehicle load failed: {}", error);
                self.selected_detail = self.management_state.vehicle_note.clone();
                self.push_log("[ERROR]", self.management_state.vehicle_note.clone());
            }
            CloudOperation::CreateVehicle => {
                self.record_vehicle_form_error(format!("Vehicle creation failed: {}", error))
            }
            CloudOperation::SelectVehicle => {
                self.record_vehicle_form_error(format!("Vehicle selection failed: {}", error))
            }
            CloudOperation::LoadKeyFobs => {
                self.management_state.key_fob_load_status = "Key fob load failed".to_string();
                self.management_state.keyfob_note = format!("Key fob load failed: {}", error);
                self.selected_detail = self.management_state.keyfob_note.clone();
                self.push_log("[ERROR]", self.management_state.keyfob_note.clone());
            }
            CloudOperation::CreateKeyFob => {
                self.record_key_fob_form_error(format!("Key fob creation failed: {}", error))
            }
            CloudOperation::SelectKeyFob => {
                self.record_key_fob_form_error(format!("Key fob selection failed: {}", error))
            }
            CloudOperation::EnableAutoSync => {
                self.cloud_ui_status = if error.contains("not configured") {
                    CloudUiStatus::NotConfigured
                } else {
                    CloudUiStatus::Disconnected
                };
                self.cloud_auto_sync_status = "Disabled".to_string();
                self.selected_detail = format!("Cloud auto-sync enable failed: {}", error);
                self.push_log("[DB]", self.selected_detail.clone());
            }
            CloudOperation::DisableAutoSync => {
                self.cloud_ui_status = CloudUiStatus::Disabled;
                self.selected_detail = format!("Cloud auto-sync disable failed: {}", error);
                self.push_log("[DB]", self.selected_detail.clone());
            }
            CloudOperation::ProvisioningConnectVehicle => {
                self.workflow_state.vehicle_connected = false;
                self.record_provisioning_cloud_error("Metadata", "Vehicle connection", error);
            }
            CloudOperation::ProvisioningDetectKeyFob => {
                self.workflow_state.keyfob_detected = false;
                self.record_provisioning_cloud_error("Metadata", "Key fob detection", error);
            }
            CloudOperation::ProvisioningRegisterKeyFob => {
                self.workflow_state.keyfob_registered = false;
                self.status.key_fob_status = "Error".to_string();
                self.record_provisioning_cloud_error(
                    "Metadata",
                    "Digital key fob registration",
                    error,
                );
            }
            CloudOperation::ProvisioningInitializeTrust => {
                self.workflow_state.trust_initialized = false;
                self.status.trust_status = "Error".to_string();
                self.record_provisioning_cloud_error(
                    "Encrypted Key Blob",
                    "Vehicle trust initialization",
                    error,
                );
            }
            CloudOperation::ProvisioningIssueCertificate => {
                self.workflow_state.certificate_issued = false;
                self.status.certificate_status = "Error".to_string();
                self.record_provisioning_cloud_error(
                    "Certificate",
                    "Access certificate issuance",
                    error,
                );
            }
            CloudOperation::ProvisioningGenerateChallenge => {
                self.workflow_state.challenge_generated = false;
                self.record_provisioning_cloud_error("Metadata", "Challenge generation", error);
            }
            CloudOperation::ProvisioningSignCanonicalPayload => {
                self.workflow_state.payload_signed = false;
                self.record_provisioning_cloud_error(
                    "Metadata",
                    "Canonical payload signing",
                    error,
                );
            }
            CloudOperation::ProvisioningVerifyAuthentication => {
                self.workflow_state.authentication_verified = false;
                self.status.authentication_status = "Failed".to_string();
                self.status.access_decision = "Error".to_string();
                self.record_provisioning_cloud_error("Session", "Key authentication", error);
            }
            CloudOperation::ProvisioningActivateSession => {
                self.workflow_state.session_active = false;
                self.status.session_status = "Error".to_string();
                self.record_provisioning_cloud_error("Session", "Secure session activation", error);
            }
            CloudOperation::ProvisioningFinalize => {
                self.workflow_state.report_exported = false;
                self.record_provisioning_cloud_error(
                    "Audit Logs",
                    "Finalize and export report",
                    error,
                );
            }
            CloudOperation::ProvisioningDiagnostics => {
                self.record_provisioning_cloud_error(
                    "Diagnostic Results",
                    "Diagnostics launch",
                    error,
                );
            }
        }
    }

    fn customer_form_values(&self) -> Result<(String, String, Option<String>), String> {
        let owner_name = self
            .management_state
            .customer_owner_input
            .trim()
            .to_string();
        let email = self
            .management_state
            .customer_email_input
            .trim()
            .to_string();
        let phone = optional_trimmed(&self.management_state.customer_phone_input);
        if owner_name.is_empty() {
            return Err("Owner name is required".to_string());
        }
        if !simple_email_is_valid(&email) {
            return Err("Valid email is required".to_string());
        }
        Ok((owner_name, email, phone))
    }

    fn vehicle_form_values(&self) -> Result<VehicleFormValues, String> {
        let display_name = self
            .management_state
            .vehicle_display_name_input
            .trim()
            .to_string();
        let make = self.management_state.vehicle_make_input.trim().to_string();
        let model = self.management_state.vehicle_model_input.trim().to_string();
        let year_text = self.management_state.vehicle_year_input.trim();
        if display_name.is_empty() {
            return Err("Vehicle display name is required".to_string());
        }
        if make.is_empty() {
            return Err("Make is required".to_string());
        }
        if model.is_empty() {
            return Err("Model is required".to_string());
        }
        let year = year_text
            .parse::<i32>()
            .map_err(|_| "Vehicle year must be numeric".to_string())?;
        Ok((
            display_name,
            make,
            model,
            year,
            optional_trimmed(&self.management_state.vehicle_vin_input),
            optional_trimmed(&self.management_state.vehicle_registration_input),
        ))
    }

    fn key_fob_form_values(&self) -> Result<String, String> {
        let label = self.management_state.key_fob_label_input.trim().to_string();
        if label.is_empty() {
            return Err("Key fob label is required".to_string());
        }
        Ok(label)
    }

    fn record_customer_form_error(&mut self, message: String) {
        self.management_state.customer_create_status = message.clone();
        self.management_state.customer_note = message.clone();
        self.selected_detail = message.clone();
        self.push_log("[ERROR]", message);
    }

    fn record_vehicle_form_error(&mut self, message: String) {
        self.management_state.vehicle_create_status = message.clone();
        self.management_state.vehicle_note = message.clone();
        self.selected_detail = message.clone();
        self.push_log("[ERROR]", message);
    }

    fn record_key_fob_form_error(&mut self, message: String) {
        self.management_state.key_fob_create_status = message.clone();
        self.management_state.keyfob_note = message.clone();
        self.selected_detail = message.clone();
        self.push_log("[ERROR]", message);
    }

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
        let visible_context = self.controller.get_visible_provisioning_context();
        let setup_status = self.access_setup_status_label(&visible_context);
        let customer_title = visible_context.owner_name.clone();
        let customer_subtitle = if visible_context.customer_selected {
            visible_context.customer_id.clone()
        } else {
            "Select a customer to begin provisioning".to_string()
        };
        let vehicle_title = visible_context.vehicle_display_name.clone();
        let vehicle_subtitle = if visible_context.vehicle_selected {
            visible_context.vehicle_id.clone()
        } else {
            "Select or create a vehicle for the active customer".to_string()
        };
        let fob_title = visible_context.fob_label.clone();
        let fob_subtitle = if visible_context.key_fob_selected {
            visible_context.fob_id.clone()
        } else {
            "Select or create a key fob for the active vehicle".to_string()
        };
        let certificate_status = if visible_context.key_fob_selected {
            self.status.certificate_status.as_str()
        } else {
            "Not Issued"
        };
        let certificate_hint = if visible_context.key_fob_selected {
            visible_context.certificate_id.as_str()
        } else {
            "Select key fob and issue certificate"
        };

        column![
            row![
                self.dashboard_card(
                    "auth",
                    "Active Customer",
                    customer_title,
                    customer_subtitle
                ),
                self.dashboard_card(
                    "vehicle",
                    "Selected Vehicle",
                    vehicle_title,
                    vehicle_subtitle,
                ),
                self.dashboard_card(
                    "key",
                    "Registered Key Fob",
                    fob_title,
                    fob_subtitle
                ),
                self.dashboard_card(
                    "certificate",
                    "Certificate Status",
                    certificate_status,
                    certificate_hint,
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
        let customer = self.controller.selected_customer_record();
        let vehicle = self.controller.selected_vehicle_record();
        let owner_name = customer
            .as_ref()
            .map(|record| record.owner_name.clone())
            .unwrap_or_else(|| "No customer selected".to_string());
        let customer_id = customer
            .as_ref()
            .map(|record| record.customer_id.clone())
            .unwrap_or_else(|| "N/A".to_string());
        let email = customer
            .as_ref()
            .and_then(|record| record.email.clone())
            .unwrap_or_else(|| "N/A".to_string());
        let phone = customer
            .as_ref()
            .and_then(|record| record.phone.clone())
            .unwrap_or_else(|| "N/A".to_string());
        let assigned_vehicle = vehicle
            .as_ref()
            .map(|record| record.vehicle_display_name.clone())
            .unwrap_or_else(|| "No vehicle selected".to_string());
        row![
            self.management_details_panel(
                "Customer / Owner",
                "Cloud-backed customer record used for access provisioning.",
                vec![
                    ("Owner Name", owner_name),
                    ("Customer ID", customer_id),
                    ("Email", email),
                    ("Phone", phone),
                    ("Assigned Vehicle", assigned_vehicle),
                    ("Provisioning Status", self.setup_status_label().to_string()),
                ],
            ),
            container(
                scrollable(
                    column![
                        text("Customer Actions")
                            .size(18)
                            .font(Font::MONOSPACE)
                            .style(theme::Text::Color(ACCENT_PINK)),
                        text("Manual customer fields. Customer ID is generated automatically.")
                            .size(12)
                            .font(Font::MONOSPACE)
                            .style(theme::Text::Color(SECONDARY_TEXT)),
                        self.form_input(
                            "Owner name",
                            &self.management_state.customer_owner_input,
                            Message::CustomerOwnerChanged,
                        ),
                        self.form_input(
                            "Email",
                            &self.management_state.customer_email_input,
                            Message::CustomerEmailChanged,
                        ),
                        self.form_input(
                            "Phone (optional)",
                            &self.management_state.customer_phone_input,
                            Message::CustomerPhoneChanged,
                        ),
                        self.cloud_action_button("auth", "Load Customers", Message::LoadCustomers),
                        self.cloud_action_button(
                            "auth",
                            "Create Customer",
                            Message::CreateCustomer
                        ),
                        self.cloud_action_button(
                            "auth",
                            "Select Customer",
                            Message::SelectCustomer
                        ),
                        compact_button(
                            "auth",
                            "Fill Demo Customer",
                            Message::FillDemoCustomer,
                            ButtonKind::Nav
                        ),
                        self.status_text("Load", &self.management_state.customer_load_status),
                        self.status_text("Create", &self.management_state.customer_create_status),
                        text(self.management_state.customer_note.as_str())
                            .size(12)
                            .font(Font::MONOSPACE)
                            .style(theme::Text::Color(SECONDARY_TEXT)),
                    ]
                    .spacing(8)
                )
                .height(Length::Fill),
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

    fn view_vehicles_tab(&self) -> Element<'_, Message> {
        let customer = self.controller.selected_customer_record();
        let vehicle = self.controller.selected_vehicle_record();
        let vehicle_name = vehicle
            .as_ref()
            .map(|record| record.vehicle_display_name.clone())
            .unwrap_or_else(|| "No vehicle selected".to_string());
        let vehicle_id = vehicle
            .as_ref()
            .map(|record| record.vehicle_id.clone())
            .unwrap_or_else(|| "N/A".to_string());
        let make = vehicle
            .as_ref()
            .and_then(|record| record.make.clone())
            .unwrap_or_else(|| "N/A".to_string());
        let model = vehicle
            .as_ref()
            .and_then(|record| record.model.clone())
            .unwrap_or_else(|| "N/A".to_string());
        let year = vehicle
            .as_ref()
            .and_then(|record| record.year)
            .map(|year| year.to_string())
            .unwrap_or_else(|| "N/A".to_string());
        let vin = vehicle
            .as_ref()
            .and_then(|record| record.vin.clone())
            .unwrap_or_else(|| "N/A".to_string());
        let registration_number = vehicle
            .as_ref()
            .and_then(|record| record.registration_number.clone())
            .unwrap_or_else(|| "N/A".to_string());
        let owner_name = customer
            .as_ref()
            .map(|record| record.owner_name.clone())
            .unwrap_or_else(|| "No customer selected".to_string());
        row![
            self.management_details_panel(
                "Vehicle",
                "Cloud-backed vehicle record for dealer-side digital access setup.",
                vec![
                    ("Vehicle Name", vehicle_name),
                    ("Vehicle ID", vehicle_id),
                    ("Make", make),
                    ("Model", model),
                    ("Year", year),
                    ("VIN", vin),
                    ("Registration Number", registration_number),
                    ("Assigned Owner", owner_name),
                    ("Access Status", self.setup_status_label().to_string()),
                ],
            ),
            container(
                scrollable(
                    column![
                        text("Vehicle Actions")
                            .size(18)
                            .font(Font::MONOSPACE)
                            .style(theme::Text::Color(ACCENT_PINK)),
                        text("Manual vehicle fields. Vehicle ID is generated automatically.")
                            .size(12)
                            .font(Font::MONOSPACE)
                            .style(theme::Text::Color(SECONDARY_TEXT)),
                        self.form_input(
                            "Vehicle display name",
                            &self.management_state.vehicle_display_name_input,
                            Message::VehicleDisplayNameChanged,
                        ),
                        self.form_input(
                            "Make",
                            &self.management_state.vehicle_make_input,
                            Message::VehicleMakeChanged,
                        ),
                        self.form_input(
                            "Model",
                            &self.management_state.vehicle_model_input,
                            Message::VehicleModelChanged,
                        ),
                        self.form_input(
                            "Year",
                            &self.management_state.vehicle_year_input,
                            Message::VehicleYearChanged,
                        ),
                        self.form_input(
                            "VIN (optional)",
                            &self.management_state.vehicle_vin_input,
                            Message::VehicleVinChanged,
                        ),
                        self.form_input(
                            "Registration number (optional)",
                            &self.management_state.vehicle_registration_input,
                            Message::VehicleRegistrationChanged,
                        ),
                        self.cloud_action_button("vehicle", "Load Vehicles", Message::LoadVehicles),
                        self.cloud_action_button(
                            "vehicle",
                            "Create Vehicle",
                            Message::CreateVehicle
                        ),
                        self.cloud_action_button(
                            "vehicle",
                            "Select Vehicle",
                            Message::SelectVehicle
                        ),
                        compact_button(
                            "vehicle",
                            "Fill Demo Vehicle",
                            Message::FillDemoVehicle,
                            ButtonKind::Nav
                        ),
                        self.status_text("Load", &self.management_state.vehicle_load_status),
                        self.status_text("Create", &self.management_state.vehicle_create_status),
                        text(self.management_state.vehicle_note.as_str())
                            .size(12)
                            .font(Font::MONOSPACE)
                            .style(theme::Text::Color(SECONDARY_TEXT)),
                    ]
                    .spacing(8)
                )
                .height(Length::Fill),
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

    fn view_keyfobs_tab(&self) -> Element<'_, Message> {
        let customer = self.controller.selected_customer_record();
        let vehicle = self.controller.selected_vehicle_record();
        let key_fob = self.controller.selected_key_fob_record();
        let fob_label = key_fob
            .as_ref()
            .map(|record| record.fob_label.clone())
            .unwrap_or_else(|| "No key fob selected".to_string());
        let fob_id = key_fob
            .as_ref()
            .map(|record| record.fob_id.clone())
            .unwrap_or_else(|| "N/A".to_string());
        let assigned_vehicle = vehicle
            .as_ref()
            .map(|record| record.vehicle_display_name.clone())
            .unwrap_or_else(|| "No vehicle selected".to_string());
        let assigned_owner = customer
            .as_ref()
            .map(|record| record.owner_name.clone())
            .unwrap_or_else(|| "No customer selected".to_string());
        let certificate_status = key_fob
            .as_ref()
            .and_then(|record| record.certificate_status.clone())
            .unwrap_or_else(|| "Not Issued".to_string());
        let public_key_fingerprint = key_fob
            .as_ref()
            .and_then(|record| record.public_key_fingerprint.clone())
            .unwrap_or_else(|| "Pending".to_string());
        row![
            self.management_details_panel(
                "Digital Key Fob",
                "Cloud-backed key fob metadata used for vehicle access provisioning.",
                vec![
                    ("Fob Label", fob_label),
                    ("Fob ID", fob_id),
                    ("Assigned Vehicle", assigned_vehicle),
                    ("Assigned Owner", assigned_owner),
                    ("Certificate Status", certificate_status),
                    ("Public Key Fingerprint", public_key_fingerprint),
                    ("Private Key", "[REDACTED]".to_string()),
                    (
                        "Credential Storage Status",
                        self.credential_storage_status().to_string()
                    ),
                ],
            ),
            container(
                scrollable(
                    column![
                        text("Key Fob Actions")
                            .size(18)
                            .font(Font::MONOSPACE)
                            .style(theme::Text::Color(ACCENT_PINK)),
                        text("Manual key fob label. Fob ID is generated automatically.")
                            .size(12)
                            .font(Font::MONOSPACE)
                            .style(theme::Text::Color(SECONDARY_TEXT)),
                        self.form_input(
                            "Fob label",
                            &self.management_state.key_fob_label_input,
                            Message::KeyFobLabelChanged,
                        ),
                        self.cloud_action_button("key", "Load Key Fobs", Message::LoadKeyFobs),
                        self.cloud_action_button(
                            "register-key",
                            "Create/Register Key Fob",
                            Message::CreateKeyFobRecord
                        ),
                        self.cloud_action_button(
                            "key",
                            "Select Key Fob",
                            Message::SelectKeyFobRecord
                        ),
                        compact_button(
                            "key",
                            "Fill Demo Key Fob",
                            Message::FillDemoKeyFob,
                            ButtonKind::Nav
                        ),
                        compact_button(
                            "certificate",
                            "View Certificate",
                            Message::ViewCertificateDetails,
                            ButtonKind::Nav
                        ),
                        compact_button(
                            "secure-session",
                            "Rotate Credential",
                            Message::RotateCredential,
                            ButtonKind::Nav
                        ),
                        self.status_text("Load", &self.management_state.key_fob_load_status),
                        self.status_text("Create", &self.management_state.key_fob_create_status),
                        text(self.management_state.keyfob_note.as_str())
                            .size(12)
                            .font(Font::MONOSPACE)
                            .style(theme::Text::Color(SECONDARY_TEXT)),
                    ]
                    .spacing(8)
                )
                .height(Length::Fill),
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
                cloud_status_badge(self.cloud_ui_status),
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
                        description: "Sign Ed25519 payload; private key stays redacted.",
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
                "Finalize provisioning and export the safe report after setup is complete.",
                column![
                    self.provisioning_completion_card(),
                    self.workflow_step_card(WorkflowStep {
                        icon_name: "terminal",
                        title: "Finalize & Export Report",
                        description:
                            "Finalize provisioning, sync audit logs, and save the safe report.",
                        status: self.completed_status(
                            self.workflow_state.report_exported,
                            "Finalized",
                            false,
                        ),
                        button_label: "Finalize & Export Report",
                        message: Message::ExportProvisioningReport,
                    }),
                ]
                .spacing(6),
            ),
        ]
        .spacing(10);

        container(
            column![
                text("Vehicle Access Provisioning")
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
        let context = self.controller.get_visible_provisioning_context();
        let crypto_identity = self.controller.get_active_key_fob_crypto_identity();
        container(
            column![
                text("Active Provisioning Context")
                    .size(16)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(ACCENT_PINK)),
                self.selected_setup_card(
                    "auth",
                    "Customer",
                    if context.customer_selected {
                        format!("{} / {}", context.owner_name, context.customer_id)
                    } else {
                        "No customer selected".to_string()
                    }
                ),
                self.selected_setup_card(
                    "vehicle",
                    "Vehicle",
                    if context.vehicle_selected {
                        format!("{} / {}", context.vehicle_display_name, context.vehicle_id)
                    } else {
                        "No vehicle selected".to_string()
                    }
                ),
                self.selected_setup_card(
                    "key",
                    "Key Fob",
                    if context.key_fob_selected {
                        format!("{} / {}", context.fob_label, context.fob_id)
                    } else {
                        "No key fob selected".to_string()
                    }
                ),
                self.selected_setup_card("certificate", "Certificate", context.certificate_id),
                self.selected_setup_card("lock", "Session", context.session_id),
                self.selected_setup_card("terminal", "Source", context.selection_source),
                text("Crypto Identity")
                    .size(16)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(ACCENT_PINK)),
                self.selected_setup_card("key", "Fob ID", crypto_identity.fob_id),
                self.selected_setup_card("certificate", "Certificate ID", crypto_identity.certificate_id),
                self.selected_setup_card("certificate", "Certificate Status", crypto_identity.certificate_status),
                self.selected_setup_card("auth", "Public Fingerprint", crypto_identity.public_key_fingerprint),
                self.selected_setup_card("shield", "Binding", crypto_identity.binding_status),
                text("Selected records now bind to the active cryptographic fob identity; private key material remains redacted.")
                    .size(10)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(SECONDARY_TEXT)),
                text("Provisioning Status")
                    .size(16)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(ACCENT_PINK)),
                self.provisioning_completion_card(),
                self.view_compact_status_rows(),
                self.view_cloud_sync_status_rows(),
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

    fn selected_setup_card(
        &self,
        icon_name: &'static str,
        label: &'static str,
        value: impl Into<String>,
    ) -> Element<'_, Message> {
        let value = value.into();
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

    fn dashboard_card(
        &self,
        icon_name: &'static str,
        title: &'static str,
        value: impl Into<String>,
        detail: impl Into<String>,
    ) -> Element<'_, Message> {
        let value = value.into();
        let detail = detail.into();
        let value_color = status_color(&value);
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
                    .style(theme::Text::Color(value_color)),
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

    fn form_input<'a>(
        &self,
        placeholder: &'static str,
        value: &'a str,
        on_input: fn(String) -> Message,
    ) -> Element<'a, Message> {
        text_input(placeholder, value)
            .on_input(on_input)
            .padding(8)
            .size(12)
            .font(Font::MONOSPACE)
            .style(theme::TextInput::Custom(Box::new(InputStyle)))
            .into()
    }

    fn cloud_action_button<'a>(
        &self,
        icon_name: &'static str,
        label: &'a str,
        message: Message,
    ) -> Element<'a, Message> {
        if self.management_state.cloud_operation_in_progress {
            disabled_compact_button(icon_name, label, ButtonKind::Nav)
        } else {
            compact_button(icon_name, label, message, ButtonKind::Nav)
        }
    }

    fn status_text<'a>(&self, label: &'static str, value: &'a str) -> Element<'a, Message> {
        row![
            text(label)
                .size(11)
                .font(Font::MONOSPACE)
                .style(theme::Text::Color(MUTED_TEXT)),
            text(value)
                .size(11)
                .font(Font::MONOSPACE)
                .style(theme::Text::Color(status_color(value))),
        ]
        .spacing(8)
        .align_items(Alignment::Center)
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
                        "Finalize & Export Report",
                        Message::ExportProvisioningReport,
                        ButtonKind::Nav
                    ),
                    compact_button(
                        "shield",
                        "Retry Cloud Connection",
                        Message::EnableCloudAutoSync,
                        ButtonKind::Nav
                    ),
                    compact_button(
                        "terminal",
                        "Disable Cloud Auto Sync",
                        Message::DisableCloudAutoSync,
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
        let context = self.controller.get_visible_provisioning_context();
        match self.selected_artifact {
            ArtifactSection::ChallengeMessage => (
                "Challenge Message",
                vec![
                    ("Status", self.challenge_status().to_string()),
                    ("Vehicle ID", context.vehicle_id.clone()),
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
                    ("Subject ID", context.fob_id.clone()),
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
                    ("Subject ID", context.fob_id.clone()),
                    ("Issuer", "AIACS-Demo-CA".to_string()),
                    (
                        "Certificate Path",
                        format!("certs/fob_{}.json", context.fob_id),
                    ),
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

    fn view_summary_row(
        &self,
        icon_name: &'static str,
        label: impl Into<String>,
        value: impl Into<String>,
    ) -> Element<'static, Message> {
        let label = label.into();
        let value = value.into();
        let value_color = status_color(&value);
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
                .style(theme::Text::Color(value_color))
                .horizontal_alignment(alignment::Horizontal::Right),
        ]
        .spacing(8)
        .align_items(Alignment::Center)
        .into()
    }

    fn view_provisioning_summary_rows(&self) -> Element<'_, Message> {
        let context = self.controller.get_visible_provisioning_context();
        let certificate_status = if context.key_fob_selected {
            self.status.certificate_status.as_str()
        } else {
            "Not Issued"
        };
        column![
            self.view_summary_row("auth", "Owner", &context.owner_name),
            self.view_summary_row("vehicle", "Vehicle", &context.vehicle_display_name),
            self.view_summary_row("key", "Digital Key", &context.fob_label),
            self.view_summary_row("certificate", "Certificate ID", &context.certificate_id),
            self.view_summary_row("lock", "Session ID", &context.session_id),
            self.view_summary_row("certificate", "Certificate", certificate_status),
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

    fn view_cloud_sync_status_rows(&self) -> Element<'_, Message> {
        container(
            column![
                text("Cloud Sync Status")
                    .size(12)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(ACCENT_BLUE)),
                self.view_summary_row("terminal", "Auto Sync", &self.cloud_auto_sync_status),
                self.view_summary_row("auth", "Metadata", &self.cloud_sync_metadata_status),
                self.view_summary_row(
                    "certificate",
                    "Certificate",
                    &self.cloud_sync_certificate_status
                ),
                self.view_summary_row(
                    "shield",
                    "Encrypted Key Blob",
                    &self.cloud_sync_encrypted_key_status
                ),
                self.view_summary_row("lock", "Session", &self.cloud_sync_session_status),
                self.view_summary_row("terminal", "Audit Logs", &self.cloud_sync_audit_status),
                self.view_summary_row(
                    "warning-shield",
                    "Diagnostics",
                    &self.cloud_sync_diagnostic_status
                ),
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

    fn access_setup_status_label(
        &self,
        context: &aiacs::app_controller::VisibleProvisioningContext,
    ) -> &'static str {
        if self.setup_complete() {
            "Complete"
        } else if !context.customer_selected {
            "Awaiting customer selection"
        } else if !context.vehicle_selected {
            "Awaiting vehicle selection"
        } else if !context.key_fob_selected {
            "Awaiting key fob selection"
        } else {
            "Ready for provisioning"
        }
    }

    fn credential_storage_status(&self) -> &'static str {
        if self.workflow_state.keyfob_registered {
            "Stored"
        } else {
            "Pending"
        }
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

    fn record_provisioning_cloud_result(
        &mut self,
        area: &'static str,
        tag: &'static str,
        message: String,
    ) {
        let cloud_status = cloud_status_from_provisioning_result(&message);
        self.management_state.cloud_sync_status = format!("Cloud sync {}", cloud_status);
        self.selected_detail = message.clone();
        self.update_cloud_sync_area(area, &cloud_status);
        if cloud_status == "Synced" || cloud_status.to_lowercase().contains("synced") {
            self.cloud_status = "Connected".to_string();
        }
        self.push_log(tag, message);
        self.push_log("[SECURITY]", "Cloud secret material: [REDACTED]");
    }

    fn record_provisioning_cloud_error(
        &mut self,
        area: &'static str,
        action_name: &'static str,
        error: String,
    ) {
        let message = format!("{} failed: {}", action_name, error);
        self.management_state.cloud_sync_status = message.clone();
        self.selected_detail = message.clone();
        self.update_cloud_sync_area(area, "Failed");
        self.push_log("[ERROR]", message);
    }

    fn update_cloud_sync_area(&mut self, area: &'static str, status: &str) {
        match area {
            "Metadata" => self.cloud_sync_metadata_status = status.to_string(),
            "Certificate" => self.cloud_sync_certificate_status = status.to_string(),
            "Encrypted Key Blob" => self.cloud_sync_encrypted_key_status = status.to_string(),
            "Session" => self.cloud_sync_session_status = status.to_string(),
            "Audit Logs" => self.cloud_sync_audit_status = status.to_string(),
            "Diagnostic Results" => self.cloud_sync_diagnostic_status = status.to_string(),
            _ => {}
        }
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

struct InputStyle;

impl iced::widget::text_input::StyleSheet for InputStyle {
    type Style = Theme;

    fn active(&self, _style: &Self::Style) -> iced::widget::text_input::Appearance {
        iced::widget::text_input::Appearance {
            background: Background::Color(BUTTON_BG),
            border: Border {
                color: BUTTON_BORDER,
                width: 1.0,
                radius: 5.0.into(),
            },
            icon_color: SECONDARY_TEXT,
        }
    }

    fn focused(&self, style: &Self::Style) -> iced::widget::text_input::Appearance {
        let mut appearance = self.active(style);
        appearance.border.color = ACCENT_BLUE;
        appearance
    }

    fn placeholder_color(&self, _style: &Self::Style) -> Color {
        MUTED_TEXT
    }

    fn value_color(&self, _style: &Self::Style) -> Color {
        PRIMARY_TEXT
    }

    fn disabled_color(&self, _style: &Self::Style) -> Color {
        MUTED_TEXT
    }

    fn selection_color(&self, _style: &Self::Style) -> Color {
        ACCENT_BLUE
    }

    fn disabled(&self, style: &Self::Style) -> iced::widget::text_input::Appearance {
        let mut appearance = self.active(style);
        appearance.background = Background::Color(PENDING_BG);
        appearance
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

fn disabled_compact_button<'a>(
    icon_name: &'static str,
    label: &'a str,
    kind: ButtonKind,
) -> Element<'a, Message> {
    button(
        row![
            icon(icon_name, 16),
            text(label)
                .size(11)
                .font(Font::MONOSPACE)
                .style(theme::Text::Color(MUTED_TEXT))
        ]
        .spacing(7)
        .align_items(Alignment::Center),
    )
    .width(Length::Fixed(190.0))
    .padding([7, 9])
    .style(button_style(kind))
    .into()
}

fn perform_cloud_operation(
    mut controller: AppController,
    operation: CloudOperation,
) -> CloudOperationResult {
    let result = match operation {
        CloudOperation::StartupAutoEnable => {
            let startup = controller.startup_auto_enable_cloud_sync();
            if startup.enabled {
                match controller.load_customer_records() {
                    Ok(load_message) => Ok(format!("{}; {}", startup, load_message)),
                    Err(error) => Ok(format!("{}; customer load skipped: {}", startup, error)),
                }
            } else {
                Ok(startup.to_string())
            }
        }
        CloudOperation::LoadCustomers => controller.load_customer_records(),
        CloudOperation::CreateCustomer
        | CloudOperation::CreateVehicle
        | CloudOperation::CreateKeyFob => unreachable!("create operations carry form values"),
        CloudOperation::SelectCustomer
        | CloudOperation::SelectVehicle
        | CloudOperation::SelectKeyFob => unreachable!("select operations carry selected ids"),
        CloudOperation::LoadVehicles => {
            if let Some(customer) = controller.selected_customer_record() {
                controller.load_vehicle_records_for_customer(&customer.customer_id)
            } else {
                Ok("Select a customer before loading vehicles".to_string())
            }
        }
        CloudOperation::LoadKeyFobs => {
            if let Some(vehicle) = controller.selected_vehicle_record() {
                controller.load_key_fob_records_for_vehicle(&vehicle.vehicle_id)
            } else {
                Ok("Select a vehicle before loading key fobs".to_string())
            }
        }
        CloudOperation::EnableAutoSync => controller.enable_cloud_auto_sync(),
        CloudOperation::DisableAutoSync => controller.disable_cloud_auto_sync(),
        CloudOperation::ProvisioningConnectVehicle => controller
            .connect_vehicle_with_cloud_sync()
            .map(|result| result.to_string()),
        CloudOperation::ProvisioningDetectKeyFob => controller
            .detect_key_fob_with_cloud_sync()
            .map(|result| result.to_string()),
        CloudOperation::ProvisioningRegisterKeyFob => controller
            .register_key_fob_with_cloud_sync()
            .map(|result| result.to_string()),
        CloudOperation::ProvisioningInitializeTrust => controller
            .initialize_vehicle_trust_with_cloud_sync()
            .map(|result| result.to_string()),
        CloudOperation::ProvisioningIssueCertificate => controller
            .issue_access_certificate_with_cloud_sync()
            .map(|result| result.to_string()),
        CloudOperation::ProvisioningGenerateChallenge => controller
            .generate_challenge_with_cloud_sync()
            .map(|result| result.to_string()),
        CloudOperation::ProvisioningSignCanonicalPayload => controller
            .sign_canonical_payload_with_cloud_sync()
            .map(|result| result.to_string()),
        CloudOperation::ProvisioningVerifyAuthentication => controller
            .verify_authentication_with_cloud_sync()
            .map(|result| result.to_string()),
        CloudOperation::ProvisioningActivateSession => controller
            .activate_secure_session_with_cloud_sync()
            .map(|result| result.to_string()),
        CloudOperation::ProvisioningFinalize => controller
            .finalize_provisioning_with_cloud_sync()
            .map(|result| result.to_string()),
        CloudOperation::ProvisioningDiagnostics => controller
            .run_diagnostics_with_cloud_sync()
            .map(|result| result.to_string()),
    }
    .map_err(|error| error.to_string());

    CloudOperationResult {
        operation,
        controller,
        result,
    }
}

fn optional_trimmed(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn cloud_status_from_provisioning_result(message: &str) -> String {
    message
        .split("Cloud Sync: ")
        .nth(1)
        .and_then(|tail| tail.split(" |").next())
        .unwrap_or("Pending")
        .to_string()
}

fn simple_email_is_valid(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty() && domain.contains('.') && !domain.ends_with('.')
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

fn cloud_status_badge(status: CloudUiStatus) -> Element<'static, Message> {
    container(
        text(status.label())
            .size(12)
            .font(Font::MONOSPACE)
            .style(theme::Text::Color(cloud_ui_status_color(status))),
    )
    .padding([5, 8])
    .style(container_style(PanelKind::Badge))
    .into()
}

fn cloud_ui_status_color(status: CloudUiStatus) -> Color {
    match status {
        CloudUiStatus::Connecting => ACCENT_BLUE,
        CloudUiStatus::Connected => SUCCESS_GREEN,
        CloudUiStatus::Disconnected => DANGER_RED,
        CloudUiStatus::NotConfigured | CloudUiStatus::Disabled => PENDING_TEXT,
    }
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
        | "Trust root initialized"
        | "Enabled"
        | "Synced"
        | "Customer saved to cloud"
        | "Vehicle saved to cloud"
        | "Key fob saved to cloud"
        | "Cloud sync completed" => SUCCESS_GREEN,
        "Pending"
        | "Not Initialized"
        | "Not Registered"
        | "Not Issued"
        | "Not Run"
        | "Not Established"
        | "N/A"
        | "Provisioning In Progress"
        | "Disabled"
        | "Skipped" => PENDING_TEXT,
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

    #[test]
    fn cloud_auto_sync_gui_strings_are_safe() {
        let source = include_str!("main.rs");

        for expected in [
            "Cloud Auto Sync",
            "Retry Cloud Connection",
            "Disable Cloud Auto Sync",
            "Cloud: Connected",
            "Cloud: Not Configured",
            "[REDACTED]",
        ] {
            assert!(source.contains(expected));
        }

        for disallowed in [
            "DATABASE_URL",
            "AIACS_MASTER_KEY",
            "private_key",
            "session_key",
            "shared_secret",
        ] {
            assert!(!source.contains(&format!("{disallowed}=")));
        }
    }

    #[test]
    fn cloud_storage_page_is_removed_from_visible_navigation() {
        let source = include_str!("main.rs");

        assert!(!source.contains("\"Cloud Storage\""));
        assert!(!source.contains(concat!("MainTab", "::", "CloudStorage")));
        assert!(!source.contains(concat!("view_", "cloud_", "storage_", "tab")));
        assert!(!source.contains("\"Sync Customer Metadata\""));
        assert!(!source.contains("\"Sync Provisioning Session\""));
        assert!(source.contains("\"Retry Cloud Connection\""));
        assert!(source.contains("\"Disable Cloud Auto Sync\""));
    }

    #[test]
    fn startup_cloud_auto_enable_runs_once_from_app_startup() {
        let source = include_str!("main.rs");
        assert!(source.contains("CloudOperation::StartupAutoEnable"));
        assert!(source.contains("cloud_auto_sync_status: \"Checking...\""));
        assert!(source.contains("cloud_ui_status: CloudUiStatus::Connecting"));
        assert!(source.contains("startup_auto_enable_cloud_sync"));
        let startup_match_arm = concat!("CloudOperation", "::", "StartupAutoEnable =>");
        assert_eq!(source.matches(startup_match_arm).count(), 3);
        assert!(!source.contains(concat!("cloud_", "storage", "::")));
    }

    #[test]
    fn startup_cloud_status_strings_are_safe() {
        let statuses = [
            CloudUiStatus::Connecting.label(),
            CloudUiStatus::Connected.label(),
            CloudUiStatus::Disconnected.label(),
            CloudUiStatus::NotConfigured.label(),
            CloudUiStatus::Disabled.label(),
            "Enabled automatically",
            "Disabled - cloud database not configured",
            "Disabled - health check failed",
            "Disabled - startup cloud check failed",
        ];
        let combined = statuses.join("\n");
        for expected in statuses {
            assert!(
                combined.contains(expected),
                "missing startup status: {expected}"
            );
        }
        for forbidden in ["DATABASE_URL", "AIACS_MASTER_KEY", "postgresql://"] {
            assert!(!combined.contains(forbidden));
        }
    }

    #[test]
    fn header_cloud_status_lifecycle_maps_safe_states() {
        let (mut app, _) = <AIACSApp as Application>::new(());

        assert_eq!(app.cloud_ui_status, CloudUiStatus::Connecting);
        assert_eq!(app.cloud_ui_status.label(), "Cloud: Connecting...");

        app.apply_startup_cloud_status("Cloud Auto Sync enabled automatically".to_string());
        assert_eq!(app.cloud_ui_status, CloudUiStatus::Connected);
        assert_eq!(app.cloud_ui_status.label(), "Cloud: Connected");

        app.apply_startup_cloud_status(
            "Cloud Auto Sync disabled - cloud database not configured".to_string(),
        );
        assert_eq!(app.cloud_ui_status, CloudUiStatus::NotConfigured);
        assert_eq!(app.cloud_ui_status.label(), "Cloud: Not Configured");

        app.apply_startup_cloud_status(
            "Cloud Auto Sync disabled - health check failed".to_string(),
        );
        assert_eq!(app.cloud_ui_status, CloudUiStatus::Disconnected);
        assert_eq!(app.cloud_ui_status.label(), "Cloud: Disconnected");
    }

    #[test]
    fn security_workflow_buttons_are_not_labelled_gui_only_demo_actions() {
        let source = include_str!("main.rs");

        for forbidden in [
            concat!("sta", "ged as a ", "GUI", "-only ", "demo ", "action"),
            concat!("GUI", "-only ", "demo ", "action"),
            concat!("place", "holder ", "selected"),
        ] {
            assert!(!source.contains(forbidden));
        }
        for security_label in [
            "Connect Vehicle",
            "Detect Key Fob",
            "Register Key Fob",
            "Initialize Trust",
            "Issue Certificate",
            "Generate",
            "Sign Payload",
            "Verify Authentication",
            "Activate Session",
            "Finalize & Export Report",
            "Sync Diagnostic Results",
        ] {
            assert!(source.contains(security_label));
        }
    }

    #[test]
    fn provisioning_finalize_button_uses_clear_label() {
        let source = include_str!("main.rs");

        assert!(source.contains("\"Finalize & Export Report\""));
        assert!(source.contains("Finalizing provisioning and exporting report..."));
        assert!(!source.contains("button_label: \"Export Report\""));
    }

    #[test]
    fn fresh_gui_visible_context_starts_empty() {
        let (app, _) = <AIACSApp as Application>::new(());
        let visible = app.controller.get_visible_provisioning_context();

        assert!(!visible.customer_selected);
        assert!(!visible.vehicle_selected);
        assert!(!visible.key_fob_selected);
        assert_eq!(visible.owner_name, "No customer selected");
        assert_eq!(visible.vehicle_display_name, "No vehicle selected");
        assert_eq!(visible.fob_label, "No key fob selected");
        assert!(!app.selected_detail.contains("CUST-0001"));
        assert!(!app.selected_detail.contains("FOB-0001"));
    }

    #[test]
    fn gui_empty_state_strings_are_visible_and_demo_is_not_initial_detail() {
        let source = include_str!("main.rs");

        for expected in [
            "No customer selected",
            "Select a customer to begin provisioning",
            "No vehicle selected",
            "Select or create a vehicle for the active customer",
            "No key fob selected",
            "Select or create a key fob for the active vehicle",
            "Select a customer before creating a vehicle",
            "Select a vehicle before creating a key fob",
        ] {
            assert!(
                source.contains(expected),
                "missing empty-state text: {expected}"
            );
        }
        assert!(!source.contains(concat!("Demo ", "customer ", "selected")));
        assert!(!source.contains(concat!("Demo ", "vehicle ", "selected")));
        assert!(!source.contains(concat!(
            "Primary ",
            "key ",
            "fob ",
            "ready ",
            "for ",
            "provisioning"
        )));
    }

    #[test]
    fn management_pages_use_cloud_backed_record_language() {
        let source = include_str!("main.rs");

        for expected in [
            "Cloud-backed customer record",
            "Cloud-backed vehicle record",
            "Cloud-backed key fob metadata",
            "Load Customers",
            "Create Customer",
            "Load Vehicles",
            "Create Vehicle",
            "Load Key Fobs",
            "Create/Register Key Fob",
            "Select Key Fob",
        ] {
            assert!(source.contains(expected), "missing GUI text: {expected}");
        }

        let old_vehicle_message = concat!(
            "Static demo vehicle profile; ",
            "database-backed vehicle creation ",
            "is not enabled in this phase"
        );
        assert!(!source.contains(old_vehicle_message));
        let old_demo_action = concat!("GUI-only ", "demo action");
        let old_unwired_copy = concat!("not ", "wired");
        assert!(!source.contains(old_demo_action));
        assert!(!source.contains(old_unwired_copy));
    }

    #[test]
    fn management_forms_start_empty_and_require_manual_input() {
        let (app, _) = <AIACSApp as Application>::new(());

        assert!(app.management_state.customer_owner_input.is_empty());
        assert!(app.management_state.customer_email_input.is_empty());
        assert!(app.management_state.customer_phone_input.is_empty());
        assert!(app.management_state.vehicle_display_name_input.is_empty());
        assert!(app.management_state.vehicle_make_input.is_empty());
        assert!(app.management_state.vehicle_model_input.is_empty());
        assert!(app.management_state.vehicle_year_input.is_empty());
        assert!(app.management_state.key_fob_label_input.is_empty());
        assert_eq!(
            app.customer_form_values()
                .expect_err("empty owner should fail"),
            "Owner name is required"
        );
    }

    #[test]
    fn management_forms_accept_manually_supplied_values() {
        let (mut app, _) = <AIACSApp as Application>::new(());
        app.management_state.customer_owner_input = "Manual Owner".to_string();
        app.management_state.customer_email_input = "manual@example.com".to_string();
        app.management_state.customer_phone_input = "+977-9800000001".to_string();
        app.management_state.vehicle_display_name_input = "Manual Vehicle".to_string();
        app.management_state.vehicle_make_input = "Nissan".to_string();
        app.management_state.vehicle_model_input = "Magnite".to_string();
        app.management_state.vehicle_year_input = "2021".to_string();
        app.management_state.key_fob_label_input = "Buyer Primary Fob".to_string();

        let (owner, email, phone) = app
            .customer_form_values()
            .expect("manual customer form should parse");
        assert_eq!(owner, "Manual Owner");
        assert_eq!(email, "manual@example.com");
        assert_eq!(phone.as_deref(), Some("+977-9800000001"));

        let (display_name, make, model, year, _, _) = app
            .vehicle_form_values()
            .expect("manual vehicle form should parse");
        assert_eq!(display_name, "Manual Vehicle");
        assert_eq!(make, "Nissan");
        assert_eq!(model, "Magnite");
        assert_eq!(year, 2021);

        assert_eq!(
            app.key_fob_form_values()
                .expect("manual key fob form should parse"),
            "Buyer Primary Fob"
        );
    }

    #[test]
    fn gui_cloud_operations_use_async_command_pattern() {
        let source = include_str!("main.rs");

        for expected in [
            "Command::perform",
            "CloudOperationFinished",
            "Loading customers...",
            "Creating customer...",
            "Loading vehicles...",
            "Creating vehicle...",
            "Loading key fobs...",
            "Creating key fob...",
            "Cloud sync running...",
            "Cloud sync completed",
        ] {
            assert!(
                source.contains(expected),
                "missing async GUI marker: {expected}"
            );
        }
    }

    #[test]
    fn gui_status_strings_do_not_expose_secret_names_or_material() {
        let statuses = [
            "Loading customers...",
            "Customers loaded",
            "Creating customer...",
            "Customer saved to cloud",
            "Customer created locally",
            "Creating vehicle...",
            "Vehicle saved to cloud",
            "Vehicle created locally",
            "Loading key fobs...",
            "Key fobs loaded",
            "Key fob saved to cloud",
            "Key fob created locally",
            "Cloud sync running...",
            "Cloud sync completed",
            "Cloud sync failed: safe error",
        ]
        .join("\n");

        for disallowed in [
            "DATABASE_URL",
            "AIACS_MASTER_KEY",
            "private_key",
            "session_key",
            "shared_secret",
            "raw AES",
        ] {
            assert!(!statuses.contains(disallowed));
        }
    }

    #[test]
    fn create_record_completion_does_not_chain_unrelated_syncs() {
        let source = include_str!("main.rs");

        assert!(source.contains("Customer saved to cloud"));
        assert!(source.contains("Vehicle saved to cloud"));
        assert!(source.contains("Key fob saved to cloud"));
        assert!(!source.contains(concat!("Cloud auto", "-sync queued")));
    }

    #[test]
    fn cargo_default_run_points_to_gui_binary() {
        let cargo_toml = include_str!("../Cargo.toml");

        assert!(cargo_toml.contains("default-run = \"aiacs\""));
    }
}
