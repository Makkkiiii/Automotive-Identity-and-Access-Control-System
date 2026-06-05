use aiacs::app_controller::AppController;
use chrono::Local;
use iced::alignment;
use iced::theme;
use iced::widget::{button, column, container, row, scrollable, text, Svg};
use iced::{
    application, Background, Border, Color, Element, Font, Length, Sandbox, Settings, Theme,
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
    RunAttack(&'static str),
    RunAllAttacks,
}

impl Sandbox for AIACSApp {
    type Message = Message;

    fn new() -> Self {
        Self {
            controller: AppController::new(),
            screen: Screen::CoreSystem,
            status: SystemStatus::default(),
            selected_detail: "Provisioning console ready. Initialize vehicle trust to begin."
                .to_string(),
            event_log: vec![
                timestamped("[INFO]", "AIACS provisioning console initialized"),
                timestamped("[INFO]", "Vehicle Access Provisioning Console ready"),
                timestamped("[INFO]", "Awaiting vehicle trust initialization"),
                timestamped("[INFO]", "Backend controller ready"),
            ],
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
                    "Diagnostics / Security Validation opened. Attack execution is placeholder-only."
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
            Message::RegisterDigitalKeyFob => {
                self.status.key_fob_status = "Registered".to_string();
                self.status.top_badge = "Key Fob Registered".to_string();
                self.selected_detail = format!(
                    "Digital key fob {} registered for vehicle {}. Certificate issuance is next.",
                    KEY_FOB_ID, VEHICLE_ID
                );
                self.push_log("[INFO]", "Digital key fob registration staged");
            }
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
            Message::RunAttack(label) => {
                self.status.access_decision = format!("{} queued", label);
                self.selected_detail = format!(
                    "{} queued in testing mode. Execution is deferred for this phase.",
                    label
                );
                self.push_log("[ATTACK]", format!("{} selected", label));
            }
            Message::RunAllAttacks => {
                self.status.access_decision = "Attack suite queued".to_string();
                self.selected_detail =
                    "Full adversarial validation suite queued. Execution is deferred.".to_string();
                self.push_log("[ATTACK]", "Run All Attacks selected");
            }
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
            .height(Length::FillPortion(4)),
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
                .height(Length::FillPortion(4)),
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
                self.nav_button(
                    "diagnostics",
                    "Back to Core System",
                    Message::BackToCoreSystem
                ),
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
            status_badge(&self.status.top_badge),
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
                row![
                    self.primary_button(
                        "trust",
                        "Initialize Vehicle Trust",
                        Message::InitializeVehicleTrust,
                    ),
                    self.action_button(
                        "register-key",
                        "Register Digital Key Fob",
                        Message::RegisterDigitalKeyFob,
                    ),
                ]
                .spacing(8),
                row![
                    self.action_button(
                        "issue-cert",
                        "Issue Access Certificate",
                        Message::IssueCertificate,
                    ),
                    self.action_button(
                        "verify-auth",
                        "Verify Key Authentication",
                        Message::VerifyKeyAuthentication
                    ),
                ]
                .spacing(8),
                self.action_button(
                    "secure-session",
                    "Activate Secure Session",
                    Message::ActivateSecureSession,
                ),
                self.detail_box("Core Result / Details"),
            ]
            .spacing(10),
            Length::Fill,
            PanelKind::Elevated,
        )
    }

    fn view_provisioning_side_panel(&self) -> Element<'_, Message> {
        column![
            self.panel(
                Some("Provisioning Summary"),
                column![
                    self.summary_row("shield", "Trust", &self.status.trust_status),
                    self.summary_row("key", "Key Fob", &self.status.key_fob_status),
                    self.summary_row(
                        "certificate",
                        "Certificate",
                        &self.status.certificate_status
                    ),
                    self.summary_row("auth", "Authentication", &self.status.authentication_status),
                    self.summary_row("lock", "Session", &self.status.session_status),
                    self.summary_row("decision", "Access", &self.status.access_decision),
                ]
                .spacing(8),
                Length::Fill,
                PanelKind::Panel,
            ),
            self.panel(
                Some("Diagnostics & Testing"),
                column![
                    row![
                        icon("diagnostics", 20),
                        text("Diagnostics are isolated from normal vehicle access provisioning.")
                            .size(12)
                            .font(Font::MONOSPACE)
                            .style(theme::Text::Color(ACCENT_BLUE)),
                    ]
                    .spacing(8),
                    self.nav_button(
                        "warning-shield",
                        "Open Diagnostics / Security Validation",
                        Message::OpenValidationLab,
                    ),
                ]
                .spacing(10),
                Length::Fill,
                PanelKind::Elevated,
            ),
        ]
        .spacing(10)
        .width(Length::FillPortion(3))
        .height(Length::Fill)
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
                    Message::RunAttack("Replay Attack")
                ),
                self.validation_button(
                    "warning-shield",
                    "Forged Signature",
                    Message::RunAttack("Forged Signature")
                ),
                self.validation_button(
                    "warning-shield",
                    "Fake Certificate",
                    Message::RunAttack("Fake Certificate")
                ),
                self.validation_button(
                    "warning-shield",
                    "Identity Mismatch",
                    Message::RunAttack("Identity Mismatch"),
                ),
                self.validation_button(
                    "warning-shield",
                    "Delayed Relay",
                    Message::RunAttack("Delayed Relay")
                ),
                self.validation_button(
                    "warning-shield",
                    "Packet Tampering",
                    Message::RunAttack("Packet Tampering"),
                ),
                self.validation_button(
                    "warning-shield",
                    "Unauthorized Key Fob",
                    Message::RunAttack("Unauthorized Key Fob"),
                ),
                self.validation_button(
                    "warning-shield",
                    "Tampered Ciphertext",
                    Message::RunAttack("Tampered Ciphertext"),
                ),
                self.validation_button(
                    "warning-shield",
                    "Wrong Session Key",
                    Message::RunAttack("Wrong Session Key"),
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

    fn view_event_log(&self) -> Element<'_, Message> {
        let entries = self.event_log.iter().fold(
            column![row![
                icon("terminal", 20),
                text("Event Log")
                    .size(16)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(ACCENT_PINK))
            ]
            .spacing(8)]
            .spacing(5),
            |log, entry| {
                log.push(
                    text(entry.as_str())
                        .size(12)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(PRIMARY_TEXT)),
                )
            },
        );

        container(scrollable(entries).height(Length::Fill))
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
                .width(Length::FillPortion(2)),
            text(value)
                .size(12)
                .font(Font::MONOSPACE)
                .style(theme::Text::Color(status_color(value)))
                .width(Length::FillPortion(3))
                .horizontal_alignment(alignment::Horizontal::Right),
        ]
        .spacing(8)
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
                icon(icon_name, 18),
                text(label)
                    .size(12)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(MUTED_TEXT))
                    .width(Length::FillPortion(2)),
                text(value)
                    .size(12)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(status_color(value)))
                    .width(Length::FillPortion(3))
                    .horizontal_alignment(alignment::Horizontal::Right),
            ]
            .spacing(8),
        )
        .padding([4, 0])
        .into()
    }

    fn action_button<'a>(
        &self,
        icon_name: &'static str,
        label: &'a str,
        message: Message,
    ) -> Element<'a, Message> {
        styled_button(icon_name, label, message, ButtonKind::Normal)
    }

    fn primary_button<'a>(
        &self,
        icon_name: &'static str,
        label: &'a str,
        message: Message,
    ) -> Element<'a, Message> {
        styled_button(icon_name, label, message, ButtonKind::Primary)
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
        .width(Length::Fill)
        .height(Length::Fixed(96.0))
        .padding(10)
        .style(container_style(PanelKind::Detail))
        .into()
    }

    fn push_log(&mut self, tag: &str, message: impl AsRef<str>) {
        self.event_log.push(timestamped(tag, message.as_ref()));
    }

    fn controller_label(&self) -> &str {
        if self.controller.get_status_summary().is_empty() {
            "Unavailable"
        } else {
            "Ready"
        }
    }
}

#[derive(Clone, Copy)]
enum PanelKind {
    Window,
    Status,
    Panel,
    Elevated,
    Log,
    Detail,
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
    Normal,
    Primary,
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
            ButtonKind::Normal => (PRIMARY_TEXT, BUTTON_BORDER),
            ButtonKind::Primary => (ACCENT_PINK, ACCENT_PINK),
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
            .style(theme::Text::Color(WARNING_YELLOW)),
    )
    .padding([5, 8])
    .style(container_style(PanelKind::Badge))
    .into()
}

fn status_color(value: &str) -> Color {
    match value {
        "Initialized" | "Registered" | "Issued" | "Verified" | "Active" | "Access Granted" => {
            SUCCESS_GREEN
        }
        "Pending" => WARNING_YELLOW,
        "Error" | "Failed" => DANGER_RED,
        _ => PRIMARY_TEXT,
    }
}

fn timestamped(tag: &str, message: &str) -> String {
    format!("{} {} {}", Local::now().format("%H:%M:%S"), tag, message)
}
