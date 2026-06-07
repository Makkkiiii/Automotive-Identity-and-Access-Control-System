use aiacs::app_controller::AppController;
use aiacs::attacks::AttackType;
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
    screen: Screen,
    status: SystemStatus,
    selected_detail: String,
    event_log: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    CoreSystem,
    ValidationLab,
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

#[derive(Debug, Clone)]
enum Message {
    OpenValidationLab,
    BackToCoreSystem,
    InitializeVehicleTrust,
    RegisterDigitalKeyFob,
    IssueCertificate,
    VerifyKeyAuthentication,
    ActivateSecureSession,
    RunAttack(AttackType),
    RunAllAttacks,
    ClearLog,
    ExportLogs,
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
            screen: Screen::CoreSystem,
            status: SystemStatus::default(),
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
            Message::OpenValidationLab => {
                self.screen = Screen::ValidationLab;
                self.selected_detail =
                    "Diagnostics / Security Validation opened. Select an attack scenario to run."
                        .to_string();
                self.push_log("[INFO]", "Diagnostics / Security Validation opened");
            }
            Message::BackToCoreSystem => {
                self.screen = Screen::CoreSystem;
                self.selected_detail = "Returned to Core System operation.".to_string();
                self.push_log("[INFO]", "Returned to Core System");
            }
            Message::InitializeVehicleTrust => match self.controller.initialize_ca() {
                Ok(message) => {
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
            Message::VerifyKeyAuthentication => {
                match self.controller.run_legitimate_authentication_demo() {
                    Ok(message) => {
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
            Message::ActivateSecureSession => {
                match self.controller.establish_secure_session_demo() {
                    Ok(_message) => {
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
            Message::RunAttack(attack_type) => match self.controller.run_attack(attack_type) {
                Ok(message) => {
                    let attack_name = attack_type.to_string();
                    let defense_status = defense_status_for_attack(&message);
                    self.selected_detail =
                        format_attack_detail(&attack_name, &message, defense_status);
                    self.push_log(
                        "[ATTACK]",
                        format!("{} completed: defense {}", attack_name, defense_status),
                    );
                }
                Err(error) => {
                    let attack_name = attack_type.to_string();
                    self.selected_detail = format!(
                        "Attack name: {}\nExpected outcome: Rejected\nActual result: {}\nDefense status: Failed",
                        attack_name, error
                    );
                    self.push_log("[ERROR]", format!("{} failed: {}", attack_name, error));
                }
            },
            Message::RunAllAttacks => match self.controller.run_all_attacks() {
                Ok(messages) => {
                    self.selected_detail = format_attack_suite_summary(&messages);
                    for message in messages {
                        self.push_log("[ATTACK]", summarize_log_message(&message));
                    }
                }
                Err(error) => {
                    self.selected_detail = format!(
                        "Attack suite: Run All Attacks\nExpected outcome: Rejected\nActual result: {}\nDefense status: Failed",
                        error
                    );
                    self.push_log("[ERROR]", format!("Run All Attacks failed: {}", error));
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
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let content = match self.screen {
            Screen::CoreSystem => self.view_core_system(),
            Screen::ValidationLab => self.view_validation_lab(),
        };

        container(content)
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
            .height(Length::FillPortion(5)),
            self.view_protocol_trace_panel(),
            self.view_event_log(),
        ]
        .spacing(10)
        .height(Length::Fill)
        .into()
    }

    fn view_validation_lab(&self) -> Element<'_, Message> {
        column![
            self.view_validation_header(),
            row![self.view_attack_panel(), self.view_result_panel()]
                .spacing(10)
                .height(Length::FillPortion(3)),
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

    fn view_validation_header(&self) -> Element<'_, Message> {
        container(
            row![
                column![
                    text("Diagnostics / Security Validation")
                        .size(26)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(ACCENT_PINK)),
                    text("Controlled adversarial validation for technician testing")
                        .size(13)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(ACCENT_BLUE)),
                ]
                .spacing(3)
                .width(Length::Fill),
                container(self.nav_button(
                    "diagnostics",
                    "Back to Core System",
                    Message::BackToCoreSystem,
                ))
                .width(Length::Fixed(240.0)),
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
            ]
            .spacing(9),
            Length::FillPortion(2),
            PanelKind::Status,
        )
    }

    fn view_workflow_panel(&self) -> Element<'_, Message> {
        self.panel(
            Some("Vehicle Access Provisioning"),
            column![
                text("Step-by-step workflow to provision and activate a digital key fob for this vehicle.")
                    .size(12)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(SECONDARY_TEXT)),
                self.workflow_step_card(WorkflowStep {
                    icon_name: "trust",
                    title: "Initialize Vehicle Trust",
                    description: "Initialize vehicle trust root and certificate authority.",
                    status: self.step_status_for("trust"),
                    button_label: "Initialize Trust",
                    message: Message::InitializeVehicleTrust,
                }),
                self.workflow_step_card(WorkflowStep {
                    icon_name: "register-key",
                    title: "Register Digital Key Fob",
                    description: "Register and prepare the buyer's key fob identity.",
                    status: self.step_status_for("key_fob"),
                    button_label: "Register Fob",
                    message: Message::RegisterDigitalKeyFob,
                }),
                self.workflow_step_card(WorkflowStep {
                    icon_name: "issue-cert",
                    title: "Issue Access Certificate",
                    description: "Issue CA-signed access certificate to the key fob.",
                    status: self.step_status_for("certificate"),
                    button_label: "Issue Certificate",
                    message: Message::IssueCertificate,
                }),
                self.workflow_step_card(WorkflowStep {
                    icon_name: "verify-auth",
                    title: "Verify Key Authentication",
                    description: "Perform challenge-response authentication.",
                    status: self.step_status_for("authentication"),
                    button_label: "Verify Authentication",
                    message: Message::VerifyKeyAuthentication,
                }),
                self.workflow_step_card(WorkflowStep {
                    icon_name: "secure-session",
                    title: "Activate Secure Session",
                    description: "Establish encrypted access session.",
                    status: self.step_status_for("session"),
                    button_label: "Activate Session",
                    message: Message::ActivateSecureSession,
                }),
                self.provisioning_completion_card(),
                self.core_detail_box(),
            ]
            .spacing(8),
            Length::Fill,
            PanelKind::Elevated,
        )
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
        .padding([8, 10])
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

    fn summary_status_card(&self) -> Element<'_, Message> {
        let complete = self.setup_complete();
        let color = if complete {
            SUCCESS_GREEN
        } else {
            PENDING_TEXT
        };
        let title = if complete {
            "Setup Complete"
        } else {
            "In Progress"
        };
        let message = if complete {
            "The vehicle and key fob are successfully provisioned."
        } else {
            "Complete the provisioning steps to authorize the key fob."
        };

        container(
            column![
                summary_indicator(complete),
                text(title)
                    .size(15)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(color))
                    .horizontal_alignment(alignment::Horizontal::Center),
                text(message)
                    .size(12)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(SECONDARY_TEXT))
                    .horizontal_alignment(alignment::Horizontal::Center),
            ]
            .spacing(5)
            .align_items(Alignment::Center),
        )
        .width(Length::Fill)
        .padding([10, 12])
        .style(container_style(PanelKind::SummaryHero))
        .into()
    }

    fn view_provisioning_side_panel(&self) -> Element<'_, Message> {
        column![
            self.view_provisioning_summary_panel(),
            self.view_diagnostics_card(),
        ]
        .spacing(10)
        .width(Length::FillPortion(3))
        .height(Length::Fill)
        .into()
    }

    fn view_provisioning_summary_panel(&self) -> Element<'_, Message> {
        container(
            column![
                text("Provisioning Summary")
                    .size(16)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(ACCENT_PINK)),
                self.summary_status_card(),
                column![
                    self.summary_row("vehicle", "Vehicle", VEHICLE_ID),
                    self.summary_row("key", "Key Fob", KEY_FOB_ID),
                    self.summary_row(
                        "certificate",
                        "Certificate",
                        self.summary_certificate_value()
                    ),
                    self.summary_row(
                        "auth",
                        "Authentication",
                        self.summary_authentication_value()
                    ),
                    self.summary_row("lock", "Secure Session", self.summary_session_value()),
                    self.summary_row("decision", "Access Decision", self.summary_access_value()),
                ]
                .spacing(6),
            ]
            .spacing(10),
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
                    "Open Diagnostics / Security Validation",
                    Message::OpenValidationLab,
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

    fn view_attack_panel(&self) -> Element<'_, Message> {
        self.panel(
            Some("Attack Scenarios"),
            column![
                row![
                    icon("warning-shield", 20),
                    text("Testing mode only")
                        .size(12)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(ACCENT_BLUE)),
                ]
                .spacing(8),
                self.validation_button(
                    "warning-shield",
                    "Replay Attack",
                    Message::RunAttack(AttackType::ReplayAttack),
                ),
                self.validation_button(
                    "warning-shield",
                    "Forged Signature",
                    Message::RunAttack(AttackType::ForgedSignature),
                ),
                self.validation_button(
                    "warning-shield",
                    "Fake Certificate",
                    Message::RunAttack(AttackType::FakeCertificate),
                ),
                self.validation_button(
                    "warning-shield",
                    "Identity Mismatch",
                    Message::RunAttack(AttackType::IdentityMismatch),
                ),
                self.validation_button(
                    "warning-shield",
                    "Delayed Relay",
                    Message::RunAttack(AttackType::DelayedRelay),
                ),
                self.validation_button(
                    "warning-shield",
                    "Packet Tampering",
                    Message::RunAttack(AttackType::PacketTampering),
                ),
                self.validation_button(
                    "warning-shield",
                    "Unauthorized Key Fob",
                    Message::RunAttack(AttackType::UnauthorizedKeyFob),
                ),
                self.validation_button(
                    "warning-shield",
                    "Tampered Ciphertext",
                    Message::RunAttack(AttackType::TamperedSessionCiphertext),
                ),
                self.validation_button(
                    "warning-shield",
                    "Wrong Session Key",
                    Message::RunAttack(AttackType::WrongSessionKey),
                ),
                self.validation_suite_button(
                    "diagnostics",
                    "Run All Attacks",
                    Message::RunAllAttacks
                ),
            ]
            .spacing(7),
            Length::FillPortion(2),
            PanelKind::Elevated,
        )
    }

    fn view_result_panel(&self) -> Element<'_, Message> {
        self.panel(
            Some("Validation Result / Details"),
            column![
                row![
                    icon("diagnostics", 20),
                    text("Adversarial validation is isolated from Core System operation.")
                        .size(12)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(ACCENT_BLUE)),
                ]
                .spacing(8),
                self.detail_box("Selected Attack / Result"),
            ]
            .spacing(10),
            Length::FillPortion(3),
            PanelKind::Panel,
        )
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

    fn summary_row<'a>(
        &self,
        icon_name: &'static str,
        label: &'a str,
        value: &'a str,
    ) -> Element<'a, Message> {
        container(
            row![
                container(icon(icon_name, 18))
                    .width(Length::Fixed(24.0))
                    .center_x(),
                text(label)
                    .size(12)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(MUTED_TEXT))
                    .width(Length::Fill),
                text(value)
                    .size(12)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(status_color(value)))
                    .width(Length::Fixed(96.0))
                    .horizontal_alignment(alignment::Horizontal::Right),
            ]
            .spacing(8)
            .align_items(Alignment::Center)
            .width(Length::Fill),
        )
        .width(Length::Fill)
        .height(Length::Fixed(32.0))
        .padding([6, 0])
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

    fn setup_complete(&self) -> bool {
        self.status.session_status == "Active" && self.status.access_decision == "Access Granted"
    }

    fn summary_certificate_value(&self) -> &str {
        match self.status.certificate_status.as_str() {
            "Issued" => "Issued",
            "Error" | "Failed" => "Error",
            _ => "Not Issued",
        }
    }

    fn summary_authentication_value(&self) -> &str {
        match self.status.authentication_status.as_str() {
            "Verified" => "Verified",
            "Failed" | "Error" => "Failed",
            _ => "Pending",
        }
    }

    fn summary_session_value(&self) -> &str {
        match self.status.session_status.as_str() {
            "Active" => "Active",
            "Error" | "Failed" => "Error",
            _ => "Pending",
        }
    }

    fn summary_access_value(&self) -> &str {
        match self.status.access_decision.as_str() {
            "Access Granted" | "Granted" => "Granted",
            "Access Rejected" | "Rejected" | "Error" => "Rejected",
            _ => "Pending",
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

    fn step_status_for(&self, step: &str) -> StepStatus {
        match step {
            "trust" => match self.status.trust_status.as_str() {
                "Initialized" => StepStatus::Completed,
                "Error" => StepStatus::Error,
                _ => StepStatus::Pending,
            },
            "key_fob" => match self.status.key_fob_status.as_str() {
                "Registered" => StepStatus::Completed,
                "Error" => StepStatus::Error,
                _ => StepStatus::Pending,
            },
            "certificate" => match self.status.certificate_status.as_str() {
                "Issued" => StepStatus::Completed,
                "Error" => StepStatus::Error,
                _ => StepStatus::Pending,
            },
            "authentication" => match self.status.authentication_status.as_str() {
                "Verified" => StepStatus::Success,
                "Failed" | "Error" => StepStatus::Error,
                _ => StepStatus::Pending,
            },
            "session" => match self.status.session_status.as_str() {
                "Active" => StepStatus::Active,
                "Error" => StepStatus::Error,
                _ => StepStatus::Pending,
            },
            _ => StepStatus::Pending,
        }
    }

    fn validation_button<'a>(
        &self,
        icon_name: &'static str,
        label: &'a str,
        message: Message,
    ) -> Element<'a, Message> {
        styled_button(icon_name, label, message, ButtonKind::Validation)
    }

    fn validation_suite_button<'a>(
        &self,
        icon_name: &'static str,
        label: &'a str,
        message: Message,
    ) -> Element<'a, Message> {
        styled_button(icon_name, label, message, ButtonKind::ValidationSuite)
    }

    fn nav_button<'a>(
        &self,
        icon_name: &'static str,
        label: &'a str,
        message: Message,
    ) -> Element<'a, Message> {
        styled_button(icon_name, label, message, ButtonKind::Nav)
    }

    fn detail_box<'a>(&'a self, title: &'a str) -> Element<'a, Message> {
        container(
            scrollable(
                column![
                    text(title)
                        .size(12)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(ACCENT_BLUE)),
                    text(self.selected_detail.as_str())
                        .size(13)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(PRIMARY_TEXT)),
                ]
                .spacing(6),
            )
            .height(Length::Fill),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(10)
        .style(container_style(PanelKind::Detail))
        .into()
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
    status: StepStatus,
    button_label: &'a str,
    message: Message,
}

#[derive(Clone, Copy)]
enum StepStatus {
    Pending,
    Completed,
    Success,
    Active,
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
    SummaryHero,
    SummaryIndicator(bool),
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
            PanelKind::SummaryHero => (LOG_BG, BUTTON_BORDER, 7.0),
            PanelKind::SummaryIndicator(complete) => {
                if complete {
                    (Color::from_rgb(0.10, 0.17, 0.13), SUCCESS_GREEN, 999.0)
                } else {
                    (PENDING_BG, PENDING_BORDER, 999.0)
                }
            }
            PanelKind::StatusChip(status) => match status {
                StepStatus::Pending => (PENDING_BG, PENDING_BORDER, 5.0),
                StepStatus::Completed | StepStatus::Success | StepStatus::Active => {
                    (Color::from_rgb(0.11, 0.14, 0.12), SUCCESS_GREEN, 5.0)
                }
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
    Validation,
    ValidationSuite,
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
            ButtonKind::Validation => (PRIMARY_TEXT, BUTTON_BORDER),
            ButtonKind::ValidationSuite => (ACCENT_PINK, ACCENT_PINK),
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
    .width(Length::Fixed(168.0))
    .padding([7, 9])
    .style(button_style(kind))
    .on_press(message)
    .into()
}

fn status_chip(status: StepStatus) -> Element<'static, Message> {
    let label = step_status_label(status);
    let text_color = step_status_color(status);
    let dot_color = step_status_dot_color(status);

    container(
        row![
            status_dot(dot_color),
            text(label)
                .size(11)
                .font(Font::MONOSPACE)
                .style(theme::Text::Color(text_color)),
        ]
        .spacing(6)
        .align_items(Alignment::Center),
    )
    .width(Length::Fixed(112.0))
    .padding([6, 8])
    .style(container_style(PanelKind::StatusChip(status)))
    .into()
}

fn status_dot(color: Color) -> Element<'static, Message> {
    container(text(""))
        .width(Length::Fixed(7.0))
        .height(Length::Fixed(7.0))
        .style(container_style(PanelKind::StatusDot(color)))
        .into()
}

fn summary_indicator(complete: bool) -> Element<'static, Message> {
    let label = if complete { "✓" } else { "" };
    let color = if complete { SUCCESS_GREEN } else { PENDING_DOT };

    container(
        text(label)
            .size(20)
            .font(Font::MONOSPACE)
            .style(theme::Text::Color(color)),
    )
    .width(Length::Fixed(36.0))
    .height(Length::Fixed(36.0))
    .center_x()
    .center_y()
    .style(container_style(PanelKind::SummaryIndicator(complete)))
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
        "Trust Ready"
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
        "Initialized"
        | "Registered"
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

fn step_status_label(status: StepStatus) -> &'static str {
    match status {
        StepStatus::Pending => "Pending",
        StepStatus::Completed => "Completed",
        StepStatus::Success => "Success",
        StepStatus::Active => "Active",
        StepStatus::Error => "Error",
    }
}

fn step_status_color(status: StepStatus) -> Color {
    match status {
        StepStatus::Pending => PENDING_TEXT,
        StepStatus::Completed | StepStatus::Success | StepStatus::Active => SUCCESS_GREEN,
        StepStatus::Error => DANGER_RED,
    }
}

fn step_status_dot_color(status: StepStatus) -> Color {
    match status {
        StepStatus::Pending => PENDING_DOT,
        StepStatus::Completed | StepStatus::Success | StepStatus::Active => SUCCESS_GREEN,
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

fn format_attack_detail(_attack_name: &str, message: &str, _defense_status: &str) -> String {
    message.to_string()
}

fn format_attack_suite_summary(messages: &[String]) -> String {
    let baseline_count = messages
        .iter()
        .filter(|message| is_baseline_result(message))
        .count();
    let attack_count = messages.len().saturating_sub(baseline_count);
    let successful_defenses = messages
        .iter()
        .filter(|message| !is_baseline_result(message))
        .filter(|message| attack_defense_succeeded(message))
        .count();
    let defense_status = if successful_defenses == attack_count {
        "Successful"
    } else {
        "Failed"
    };

    let mut summary = format!(
        "Attack suite: Run All Attacks\nExpected outcome: Rejected for attack scenarios\nScenarios run: {}\nAttack scenarios: {}\nDefense status: {}\n\nResults:",
        messages.len(),
        attack_count,
        defense_status
    );

    for message in messages {
        summary.push_str("\n- ");
        summary.push_str(message);
    }

    summary
}

fn defense_status_for_attack(message: &str) -> &'static str {
    if attack_defense_succeeded(message) {
        "Successful"
    } else {
        "Failed"
    }
}

fn attack_defense_succeeded(message: &str) -> bool {
    let lower = message.to_lowercase();

    lower.contains("access denied")
        || lower.contains("rejected")
        || lower.contains("detected")
        || lower.contains("should fail")
}

fn is_baseline_result(message: &str) -> bool {
    message.contains("Legitimate Baseline")
}

fn summarize_log_message(message: &str) -> String {
    message
        .lines()
        .find(|line| line.starts_with("Attack:") || line.starts_with("Scenario:"))
        .map(|line| line.replace("Attack: ", "").replace("Scenario: ", ""))
        .unwrap_or_else(|| message.replace(['\r', '\n'], " | "))
}

fn trace_parts(entry: &str) -> (&str, &str) {
    entry
        .split_once(' ')
        .map_or(("", entry), |(tag, message)| (tag, message))
}

fn timestamped(tag: &str, message: &str) -> String {
    format!("{} {} {}", Local::now().format("%H:%M:%S"), tag, message)
}
