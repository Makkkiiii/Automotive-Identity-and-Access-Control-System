use aiacs::app_controller::AppController;
use iced::alignment;
use iced::widget::{button, column, container, row, scrollable, text};
use iced::{Alignment, Element, Length, Sandbox, Settings, Theme};

pub fn main() -> iced::Result {
    AIACSApp::run(Settings::default())
}

struct AIACSApp {
    controller: AppController,
    status: SystemStatus,
    event_log: Vec<String>,
}

#[derive(Debug, Clone)]
struct SystemStatus {
    app_status: String,
    ca_status: String,
    certificate_status: String,
    vehicle_id: String,
    key_fob_id: String,
    authentication_status: String,
    session_status: String,
    last_decision: String,
}

impl Default for SystemStatus {
    fn default() -> Self {
        Self {
            app_status: "Not Initialized".to_string(),
            ca_status: "Not Initialized".to_string(),
            certificate_status: "Not Issued".to_string(),
            vehicle_id: "VEHICLE_001".to_string(),
            key_fob_id: "FOB_001".to_string(),
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
            event_log: vec![
                "[SYSTEM] AIACS GUI initialized".to_string(),
                "[INFO] Awaiting CA initialization".to_string(),
                "[INFO] Backend controller ready".to_string(),
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
                self.status.app_status = "Configuration Pending".to_string();
                self.status.ca_status = "Initialization Requested".to_string();
                self.push_log("[ACTION] Initialize CA selected");
            }
            Message::IssueCertificate => {
                self.status.certificate_status = "Issue Requested".to_string();
                self.push_log("[ACTION] Issue Key Fob Certificate selected");
            }
            Message::RunLegitimateAuthentication => {
                self.status.authentication_status = "Demo Requested".to_string();
                self.status.last_decision = "Pending".to_string();
                self.push_log("[ACTION] Run Legitimate Authentication selected");
            }
            Message::EstablishSecureSession => {
                self.status.session_status = "Session Requested".to_string();
                self.push_log("[ACTION] Establish Secure Session selected");
            }
            Message::RunAttack(label) => {
                self.status.last_decision = format!("{} queued", label);
                self.push_log(format!("[LAB] {} selected", label));
            }
            Message::RunAllAttacks => {
                self.status.last_decision = "Attack suite queued".to_string();
                self.push_log("[LAB] Run All Attacks selected");
            }
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let shell = column![
            self.view_header(),
            row![
                self.view_status_panel(),
                self.view_workflow_panel(),
                self.view_validation_panel(),
            ]
            .spacing(12)
            .height(Length::FillPortion(3)),
            self.view_event_log(),
        ]
        .spacing(12)
        .padding(14)
        .width(Length::Fill)
        .height(Length::Fill);

        container(shell)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
}

impl AIACSApp {
    fn view_header(&self) -> Element<'_, Message> {
        let title_block = column![
            text("AIACS").size(30),
            text("Automotive Identity and Access Control System").size(14),
        ]
        .spacing(2)
        .width(Length::Fill);

        let status_badge = container(text(self.status.app_status.as_str()).size(13))
            .padding([6, 12])
            .width(Length::Shrink);

        container(
            row![title_block, status_badge]
                .align_items(Alignment::Center)
                .spacing(16),
        )
        .width(Length::Fill)
        .padding(12)
        .into()
    }

    fn view_status_panel(&self) -> Element<'_, Message> {
        self.panel(
            "Core System Status",
            column![
                self.status_row("CA Status", &self.status.ca_status),
                self.status_row("Certificate", &self.status.certificate_status),
                self.status_row("Vehicle ID", &self.status.vehicle_id),
                self.status_row("Key Fob ID", &self.status.key_fob_id),
                self.status_row("Authentication", &self.status.authentication_status),
                self.status_row("Session", &self.status.session_status),
                self.status_row("Last Decision", &self.status.last_decision),
                self.status_row("Controller", self.controller_state_label()),
            ]
            .spacing(8),
            Length::FillPortion(3),
        )
    }

    fn view_workflow_panel(&self) -> Element<'_, Message> {
        self.panel(
            "Core Authentication Workflow",
            column![
                self.action_button("Initialize CA", Message::InitializeCa),
                self.action_button("Issue Key Fob Certificate", Message::IssueCertificate),
                self.action_button(
                    "Run Legitimate Authentication",
                    Message::RunLegitimateAuthentication,
                ),
                self.action_button("Establish Secure Session", Message::EstablishSecureSession),
                text("Phase 1 buttons update GUI placeholders only.").size(12),
            ]
            .spacing(10),
            Length::FillPortion(4),
        )
    }

    fn view_validation_panel(&self) -> Element<'_, Message> {
        self.panel(
            "Security Validation Lab",
            column![
                text("Testing / adversarial validation").size(13),
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
            Length::FillPortion(4),
        )
    }

    fn view_event_log(&self) -> Element<'_, Message> {
        let entries = self.event_log.iter().fold(
            column![text("Event Log").size(18)].spacing(5),
            |log, entry| log.push(text(entry.as_str()).size(13)),
        );

        container(scrollable(entries).height(Length::Fill))
            .width(Length::Fill)
            .height(Length::FillPortion(1))
            .padding(12)
            .into()
    }

    fn panel<'a>(
        &self,
        title: &'a str,
        content: iced::widget::Column<'a, Message>,
        width: Length,
    ) -> Element<'a, Message> {
        container(column![text(title).size(18), content].spacing(12))
            .width(width)
            .height(Length::Fill)
            .padding(12)
            .into()
    }

    fn status_row<'a>(&self, label: &'a str, value: &'a str) -> Element<'a, Message> {
        row![
            text(label).size(13).width(Length::FillPortion(2)),
            text(value)
                .size(13)
                .width(Length::FillPortion(3))
                .horizontal_alignment(alignment::Horizontal::Right),
        ]
        .spacing(8)
        .align_items(Alignment::Center)
        .into()
    }

    fn action_button<'a>(&self, label: &'a str, message: Message) -> Element<'a, Message> {
        button(text(label).size(13))
            .width(Length::Fill)
            .padding([8, 10])
            .on_press(message)
            .into()
    }

    fn push_log(&mut self, entry: impl Into<String>) {
        self.event_log.push(entry.into());
    }

    fn controller_state_label(&self) -> &str {
        if self.controller.get_status_summary().is_empty() {
            "Unavailable"
        } else {
            "Ready"
        }
    }
}
