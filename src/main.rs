use aiacs::app_controller::AppController;
use chrono::Local;
use iced::alignment;
use iced::theme;
use iced::widget::{button, column, container, row, scrollable, text, Svg};
use iced::{
    application, Alignment, Background, Border, Color, Element, Font, Length, Sandbox, Settings,
    Theme,
};

const VEHICLE_ID: &str = "VEHICLE_001";
const KEY_FOB_ID: &str = "FOB_001";
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

pub fn main() -> iced::Result {
    AIACSApp::run(Settings::default())
}

struct AIACSApp {
    controller: AppController,
    status: SystemStatus,
    workflow_state: WorkflowState,
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
enum Message {
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
            row![
                self.view_status_panel(),
                column![self.view_core_header(), self.view_workflow_panel(),]
                    .spacing(10)
                    .width(Length::FillPortion(5))
                    .height(Length::Fill),
                self.view_provisioning_side_panel(),
            ]
            .spacing(10)
            .height(Length::FillPortion(7)),
            self.view_protocol_trace_panel(),
            self.view_event_log(),
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

    fn view_status_panel(&self) -> Element<'_, Message> {
        let logo = column![
            text("AIACS")
                .size(30)
                .font(Font::MONOSPACE)
                .style(theme::Text::Color(ACCENT_PINK)),
            text("VEHICLE ACCESS PROVISIONING")
                .size(11)
                .font(Font::MONOSPACE)
                .style(theme::Text::Color(MUTED_TEXT)),
        ]
        .spacing(6);
        let storage_rows = self.controller.credential_storage_summary().iter().fold(
            column![text("Credential Storage")
                .size(12)
                .font(Font::MONOSPACE)
                .style(theme::Text::Color(ACCENT_BLUE))]
            .spacing(5),
            |column, line| {
                column.push(
                    text(line.as_str())
                        .size(10)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(SECONDARY_TEXT)),
                )
            },
        );

        self.panel(
            None,
            column![
                logo,
                self.status_row("vehicle", "Vehicle ID", VEHICLE_ID),
                self.status_row("key", "Key Fob ID", KEY_FOB_ID),
                self.status_row("shield", "Trust Status", &self.status.trust_status),
                self.status_row(
                    "certificate",
                    "Certificate Status",
                    &self.status.certificate_status
                ),
                self.status_row(
                    "auth",
                    "Authentication Status",
                    &self.status.authentication_status
                ),
                self.status_row("lock", "Secure Session Status", &self.status.session_status),
                self.status_row("decision", "Access Decision", &self.status.access_decision),
                self.status_row("gear", "Controller", self.controller_label()),
                storage_rows,
            ]
            .spacing(9),
            Length::FillPortion(2),
            PanelKind::Status,
        )
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
                    description: "Connect to VEHICLE_001 using AIACS_AUTH_V1.",
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
                        description: "Detect FOB_001 and prepare credential registration.",
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
            self.core_detail_box(),
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

    fn view_provisioning_side_panel(&self) -> Element<'_, Message> {
        column![
            self.view_protocol_artifact_viewer(),
            self.view_diagnostics_card(),
        ]
        .spacing(10)
        .width(Length::FillPortion(3))
        .height(Length::Fill)
        .into()
    }

    fn view_protocol_artifact_viewer(&self) -> Element<'_, Message> {
        let artifact_rows = column![
            self.artifact_summary_row(
                "auth",
                "Challenge Message",
                if self.workflow_state.challenge_generated {
                    "Generated"
                } else {
                    "Pending"
                },
                "Vehicle nonce evidence is summarized in the trace; raw nonce stays redacted.",
            ),
            self.artifact_summary_row(
                "verify-auth",
                "Authentication Proof",
                if self.workflow_state.authentication_verified {
                    "Verified"
                } else if self.workflow_state.payload_signed {
                    "Signed"
                } else {
                    "Pending"
                },
                "Canonical payload and signature fingerprints only; no raw signature material shown.",
            ),
            self.artifact_summary_row(
                "certificate",
                "Certificate Details",
                if self.workflow_state.certificate_issued {
                    "Issued"
                } else {
                    "Pending"
                },
                "Subject FOB-GUI-001, issuer AIACS-Demo-CA, public key fingerprint only.",
            ),
            self.artifact_summary_row(
                "key",
                "Credential Storage",
                if self.workflow_state.keyfob_registered {
                    "Stored"
                } else {
                    "Pending"
                },
                "Local prototype key paths and public fingerprints; private key material redacted.",
            ),
            self.artifact_summary_row(
                "lock",
                "Session Summary",
                if self.workflow_state.session_active {
                    "Active"
                } else {
                    "Pending"
                },
                "X25519 + HKDF + AES-GCM summary only; session keys remain redacted.",
            ),
            self.artifact_summary_row(
                "decision",
                "Access Decision",
                self.access_decision_artifact_status(),
                "Decision result from the AppController-backed authentication flow.",
            ),
        ]
        .spacing(7)
        .width(Length::Fill);

        container(
            column![
                text("Protocol Artifact Viewer")
                    .size(16)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(ACCENT_PINK)),
                text("Safe summaries only. Full secret material is never rendered.")
                    .size(11)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(SECONDARY_TEXT)),
                scrollable(artifact_rows).height(Length::Fill),
            ]
            .spacing(8),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(10)
        .style(container_style(PanelKind::Panel))
        .into()
    }

    fn view_diagnostics_card(&self) -> Element<'_, Message> {
        container(
            column![
                text("Diagnostics & Testing")
                    .size(16)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(ACCENT_PINK)),
                text("Run security validations and protocol testing in a separate environment.")
                    .size(12)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(PRIMARY_TEXT)),
                self.nav_button(
                    "warning-shield",
                    "Launch Diagnostics Tool",
                    Message::LaunchDiagnosticsTool,
                ),
                row![
                    icon("diagnostics", 18),
                    text("Diagnostics are isolated from normal provisioning.")
                        .size(11)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(ACCENT_BLUE)),
                ]
                .spacing(8)
                .align_items(Alignment::Center),
            ]
            .spacing(7),
        )
        .width(Length::Fill)
        .height(Length::Fixed(150.0))
        .padding(10)
        .style(container_style(PanelKind::Elevated))
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
            column![row![
                row![
                    icon("terminal", 20),
                    text("Event Log")
                        .size(16)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(ACCENT_PINK))
                ]
                .spacing(8)
                .align_items(Alignment::Center)
                .width(Length::Fill),
                compact_button("terminal", "Clear Log", Message::ClearLog, ButtonKind::Nav),
                compact_button(
                    "terminal",
                    "Save / Export Logs",
                    Message::ExportLogs,
                    ButtonKind::Nav
                ),
            ]
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

    fn panel<'a>(
        &self,
        title: Option<&'a str>,
        content: iced::widget::Column<'a, Message>,
        width: Length,
        kind: PanelKind,
    ) -> Element<'a, Message> {
        let panel_content = if let Some(title) = title {
            column![
                text(title)
                    .size(16)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(ACCENT_PINK)),
                content,
            ]
            .spacing(10)
        } else {
            content
        };

        container(panel_content)
            .width(width)
            .height(Length::Fill)
            .padding(12)
            .style(container_style(kind))
            .into()
    }

    fn status_row<'a>(
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
                .width(Length::Fixed(154.0)),
            text(value)
                .size(12)
                .font(Font::MONOSPACE)
                .style(theme::Text::Color(status_color(value)))
                .width(Length::Fill)
                .horizontal_alignment(alignment::Horizontal::Right),
        ]
        .spacing(8)
        .width(Length::Fill)
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

    fn artifact_summary_row<'a>(
        &self,
        icon_name: &'static str,
        label: &'a str,
        value: &'a str,
        detail: &'a str,
    ) -> Element<'a, Message> {
        container(
            row![
                icon(icon_name, 18),
                column![
                    row![
                        text(label)
                            .size(11)
                            .font(Font::MONOSPACE)
                            .style(theme::Text::Color(PRIMARY_TEXT))
                            .width(Length::Fill),
                        text(value)
                            .size(11)
                            .font(Font::MONOSPACE)
                            .style(theme::Text::Color(status_color(value)))
                            .horizontal_alignment(alignment::Horizontal::Right),
                    ]
                    .spacing(8)
                    .align_items(Alignment::Center),
                    text(detail)
                        .size(10)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(SECONDARY_TEXT))
                        .width(Length::Fill),
                ]
                .spacing(3)
                .width(Length::Fill),
            ]
            .spacing(8)
            .align_items(Alignment::Center),
        )
        .width(Length::Fill)
        .padding(7)
        .style(container_style(PanelKind::StepCard))
        .into()
    }

    fn setup_complete(&self) -> bool {
        self.status.session_status == "Active" && self.status.access_decision == "Access Granted"
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

    fn controller_label(&self) -> &str {
        if self.controller.get_status_summary().is_empty() {
            "Unavailable"
        } else {
            "Ready"
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
        | "Access Granted"
        | "Granted"
        | "Valid"
        | "Complete"
        | "CA-signed certificate issued"
        | "Trust root initialized" => SUCCESS_GREEN,
        "Pending" | "Not Initialized" | "Not Registered" | "Not Issued" | "Not Run"
        | "Not Established" | "N/A" => PENDING_TEXT,
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

fn trace_parts(entry: &str) -> (&str, &str) {
    entry
        .split_once(' ')
        .map_or(("", entry), |(tag, message)| (tag, message))
}

fn timestamped(tag: &str, message: &str) -> String {
    format!("{} {} {}", Local::now().format("%H:%M:%S"), tag, message)
}
