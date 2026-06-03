use aiacs::app_controller::AppController;
use chrono::Local;
use iced::alignment;
use iced::theme;
use iced::widget::{button, column, container, row, scrollable, text};
use iced::{Alignment, Color, Element, Font, Length, Sandbox, Settings, Theme};

const VEHICLE_ID: &str = "VEHICLE_001";
const KEY_FOB_ID: &str = "FOB_001";
const ACCENT_PINK: Color = Color::from_rgb(0.88, 0.55, 0.64);
const ACCENT_BLUE: Color = Color::from_rgb(0.44, 0.63, 0.78);
const TEXT_MUTED: Color = Color::from_rgb(0.64, 0.60, 0.58);

pub fn main() -> iced::Result {
    AIACSApp::run(Settings::default())
}

struct AIACSApp {
    controller: AppController,
    status: SystemStatus,
    selected_detail: String,
    event_log: Vec<String>,
}

#[derive(Debug, Clone)]
struct SystemStatus {
    ca_status: String,
    certificate_status: String,
    authentication_status: String,
    session_status: String,
    last_decision: String,
}

impl Default for SystemStatus {
    fn default() -> Self {
        Self {
            ca_status: "Not Initialized".to_string(),
            certificate_status: "Not Issued".to_string(),
            authentication_status: "Not Run".to_string(),
            session_status: "Not Established".to_string(),
            last_decision: "N/A".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
enum Message {
    InitializeCa,
    IssueCertificate,
    RunLegitimateAuthentication,
    EstablishSecureSession,
    RunAttack(&'static str),
    RunAllAttacks,
}

impl Sandbox for AIACSApp {
    type Message = Message;

    fn new() -> Self {
        Self {
            controller: AppController::new(),
            status: SystemStatus::default(),
            selected_detail: "Select a workflow or validation action.".to_string(),
            event_log: vec![
                timestamped("[INFO]", "AIACS GUI initialized"),
                timestamped("[INFO]", "Awaiting CA initialization"),
                timestamped("[INFO]", "Backend controller ready"),
            ],
        }
    }

    fn title(&self) -> String {
        "AIACS - Automotive Identity and Access Control System".to_string()
    }

    fn theme(&self) -> Theme {
        Theme::Dark
    }

    fn update(&mut self, message: Message) {
        match message {
            Message::InitializeCa => {
                self.status.ca_status = "Pending".to_string();
                self.selected_detail =
                    "Initialize CA requested. Backend wiring is deferred for this GUI phase."
                        .to_string();
                self.push_log("[INFO]", "Initialize CA selected");
            }
            Message::IssueCertificate => {
                self.status.certificate_status = "Pending".to_string();
                self.selected_detail =
                    "Key fob certificate issuance requested. No certificate material is displayed."
                        .to_string();
                self.push_log("[INFO]", "Issue Key Fob Certificate selected");
            }
            Message::RunLegitimateAuthentication => {
                self.status.authentication_status = "Pending".to_string();
                self.status.last_decision = "Pending".to_string();
                self.selected_detail =
                    "Legitimate authentication demo selected. No protocol logic runs in main.rs."
                        .to_string();
                self.push_log("[AUTH]", "Legitimate authentication selected");
            }
            Message::EstablishSecureSession => {
                self.status.session_status = "Pending".to_string();
                self.selected_detail =
                    "Secure session establishment selected. Session keys remain hidden."
                        .to_string();
                self.push_log("[SESSION]", "Secure session establishment selected");
            }
            Message::RunAttack(label) => {
                self.status.last_decision = format!("{} queued", label);
                self.selected_detail = format!(
                    "{} queued in the Security Validation Lab. Execution is deferred.",
                    label
                );
                self.push_log("[ATTACK]", format!("{} selected", label));
            }
            Message::RunAllAttacks => {
                self.status.last_decision = "Attack suite queued".to_string();
                self.selected_detail =
                    "Full adversarial validation suite queued. Execution is deferred.".to_string();
                self.push_log("[ATTACK]", "Run All Attacks selected");
            }
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let layout = column![row![
            self.view_left_panel(),
            column![self.view_workflow_panel(), self.view_event_log()]
                .spacing(10)
                .width(Length::FillPortion(5))
                .height(Length::Fill),
            self.view_validation_panel(),
        ]
        .spacing(10)
        .height(Length::Fill),]
        .padding(12)
        .spacing(10)
        .width(Length::Fill)
        .height(Length::Fill);

        container(layout)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(theme::Container::Box)
            .into()
    }
}

impl AIACSApp {
    fn view_left_panel(&self) -> Element<'_, Message> {
        let logo = column![
            text("AIACS")
                .size(30)
                .font(Font::MONOSPACE)
                .style(theme::Text::Color(ACCENT_PINK)),
            text("AUTOMOTIVE IDENTITY ACCESS")
                .size(11)
                .font(Font::MONOSPACE)
                .style(theme::Text::Color(TEXT_MUTED)),
            container(text("Not Initialized").size(12).font(Font::MONOSPACE))
                .padding([5, 8])
                .style(theme::Container::Box),
        ]
        .spacing(6);

        self.panel(
            None,
            column![
                logo,
                self.status_row("Vehicle ID", VEHICLE_ID),
                self.status_row("Key Fob ID", KEY_FOB_ID),
                self.status_row("CA Status", &self.status.ca_status),
                self.status_row("Certificate", &self.status.certificate_status),
                self.status_row("Authentication", &self.status.authentication_status),
                self.status_row("Session", &self.status.session_status),
                self.status_row("Last Decision", &self.status.last_decision),
                self.status_row("Controller", self.controller_label()),
            ]
            .spacing(9),
            Length::FillPortion(2),
        )
    }

    fn view_workflow_panel(&self) -> Element<'_, Message> {
        self.panel(
            Some("Core Authentication Workflow"),
            column![
                row![
                    self.action_button("Initialize CA", Message::InitializeCa),
                    self.action_button("Issue Key Fob Certificate", Message::IssueCertificate),
                ]
                .spacing(8),
                row![
                    self.action_button(
                        "Run Legitimate Authentication",
                        Message::RunLegitimateAuthentication,
                    ),
                    self.action_button(
                        "Establish Secure Session",
                        Message::EstablishSecureSession,
                    ),
                ]
                .spacing(8),
                self.detail_box(),
            ]
            .spacing(10),
            Length::Fill,
        )
    }

    fn view_validation_panel(&self) -> Element<'_, Message> {
        self.panel(
            Some("Security Validation Lab"),
            column![
                text("Testing / adversarial validation")
                    .size(12)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(ACCENT_BLUE)),
                self.action_button("Replay Attack", Message::RunAttack("Replay Attack")),
                self.action_button("Forged Signature", Message::RunAttack("Forged Signature")),
                self.action_button("Fake Certificate", Message::RunAttack("Fake Certificate")),
                self.action_button("Identity Mismatch", Message::RunAttack("Identity Mismatch")),
                self.action_button("Delayed Relay", Message::RunAttack("Delayed Relay")),
                self.action_button("Packet Tampering", Message::RunAttack("Packet Tampering")),
                self.action_button(
                    "Unauthorized Key Fob",
                    Message::RunAttack("Unauthorized Key Fob"),
                ),
                self.action_button(
                    "Tampered Ciphertext",
                    Message::RunAttack("Tampered Ciphertext"),
                ),
                self.action_button("Wrong Session Key", Message::RunAttack("Wrong Session Key")),
                self.action_button("Run All Attacks", Message::RunAllAttacks),
            ]
            .spacing(7),
            Length::FillPortion(3),
        )
    }

    fn view_event_log(&self) -> Element<'_, Message> {
        let entries = self.event_log.iter().fold(
            column![text("Event Log")
                .size(16)
                .font(Font::MONOSPACE)
                .style(theme::Text::Color(ACCENT_PINK))]
            .spacing(5),
            |log, entry| {
                log.push(
                    text(entry.as_str())
                        .size(12)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(Color::from_rgb(0.78, 0.75, 0.71))),
                )
            },
        );

        container(scrollable(entries).height(Length::Fill))
            .width(Length::Fill)
            .height(Length::FillPortion(3))
            .padding(10)
            .style(theme::Container::Box)
            .into()
    }

    fn panel<'a>(
        &self,
        title: Option<&'a str>,
        content: iced::widget::Column<'a, Message>,
        width: Length,
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
            .style(theme::Container::Box)
            .into()
    }

    fn status_row<'a>(&self, label: &'a str, value: &'a str) -> Element<'a, Message> {
        row![
            text(label)
                .size(12)
                .font(Font::MONOSPACE)
                .style(theme::Text::Color(TEXT_MUTED))
                .width(Length::FillPortion(2)),
            text(value)
                .size(12)
                .font(Font::MONOSPACE)
                .width(Length::FillPortion(3))
                .horizontal_alignment(alignment::Horizontal::Right),
        ]
        .spacing(8)
        .align_items(Alignment::Center)
        .into()
    }

    fn action_button<'a>(&self, label: &'a str, message: Message) -> Element<'a, Message> {
        button(text(label).size(12).font(Font::MONOSPACE))
            .width(Length::Fill)
            .padding([7, 9])
            .style(theme::Button::Secondary)
            .on_press(message)
            .into()
    }

    fn detail_box(&self) -> Element<'_, Message> {
        container(
            column![
                text("Selected Action / Result")
                    .size(12)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(ACCENT_BLUE)),
                text(self.selected_detail.as_str())
                    .size(13)
                    .font(Font::MONOSPACE),
            ]
            .spacing(6),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(10)
        .style(theme::Container::Box)
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

fn timestamped(tag: &str, message: &str) -> String {
    format!("{} {} {}", Local::now().format("%H:%M:%S"), tag, message)
}
