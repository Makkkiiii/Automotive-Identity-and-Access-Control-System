use aiacs::app_controller::AppController;
use chrono::Local;
use iced::alignment;
use iced::theme;
use iced::widget::{button, column, container, row, scrollable, text};
use iced::{
    application, Alignment, Background, Border, Color, Element, Font, Length, Sandbox, Settings,
    Theme,
};

const WINDOW_BG: Color = Color::from_rgb(0.105, 0.09, 0.11);
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
const DANGER_RED: Color = Color::from_rgb(0.878, 0.424, 0.459);

const ATTACKS: [(&str, &str); 9] = [
    ("Replay Attack", "replay"),
    ("Forged Signature", "forged_signature"),
    ("Fake Certificate", "fake_certificate"),
    ("Identity Mismatch", "identity_mismatch"),
    ("Delayed Relay", "delayed_relay"),
    ("Packet Tampering", "packet_tampering"),
    ("Unauthorized Key Fob", "unauthorized_key_fob"),
    ("Tampered Ciphertext", "tampered_ciphertext"),
    ("Wrong Session Key", "wrong_session_key"),
];

pub fn main() -> iced::Result {
    DiagnosticsApp::run(Settings::default())
}

struct DiagnosticsApp {
    controller: AppController,
    selected_title: String,
    selected_result: String,
    step_trace: Vec<String>,
    event_log: Vec<String>,
}

#[derive(Debug, Clone)]
enum Message {
    RunAttack(&'static str, &'static str),
    RunAllAttacks,
    Exit,
}

impl Sandbox for DiagnosticsApp {
    type Message = Message;

    fn new() -> Self {
        let mut controller = AppController::new();
        let _ = controller.save_log_entry("[INFO]", "AIACS diagnostics tool initialized");

        Self {
            controller,
            selected_title: "No attack selected".to_string(),
            selected_result: "Select an attack scenario to run controlled validation.".to_string(),
            step_trace: Vec::new(),
            event_log: vec![timestamped("[INFO]", "AIACS diagnostics tool initialized")],
        }
    }

    fn title(&self) -> String {
        "AIACS Diagnostics / Security Validation".to_string()
    }

    fn theme(&self) -> Theme {
        Theme::custom(
            "AIACS Diagnostics Dark".to_string(),
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
            Message::RunAttack(label, key) => {
                self.selected_title = label.to_string();
                self.step_trace = self
                    .controller
                    .diagnostics_attack_steps(key)
                    .unwrap_or_else(|error| vec![format!("Step trace unavailable: {}", error)]);
                match self.controller.run_named_attack(key) {
                    Ok(result) => {
                        self.selected_result = result.clone();
                        self.push_log("[ATTACK]", format!("{} completed", label));
                    }
                    Err(error) => {
                        self.selected_result = format!("{} failed: {}", label, error);
                        self.push_log("[ERROR]", format!("{} failed: {}", label, error));
                    }
                }
            }
            Message::RunAllAttacks => match self.controller.run_all_attacks() {
                Ok(results) => {
                    self.selected_title = "Run All Attacks".to_string();
                    self.step_trace = vec![
                        "Step 1: Execute legitimate baseline".to_string(),
                        "Step 2: Execute all adversarial scenarios".to_string(),
                        "Step 3: Record expected vs actual outcomes".to_string(),
                        "Step 4: Confirm defenses reject attack scenarios".to_string(),
                    ];
                    self.selected_result = format_suite_results(&results);
                    for result in results {
                        self.push_log("[ATTACK]", summarize_result(&result));
                    }
                }
                Err(error) => {
                    self.selected_result = format!("Run All Attacks failed: {}", error);
                    self.push_log("[ERROR]", format!("Run All Attacks failed: {}", error));
                }
            },
            Message::Exit => std::process::exit(0),
        }
    }

    fn view(&self) -> Element<'_, Message> {
        container(
            column![
                self.header(),
                row![self.attack_panel(), self.evidence_panel()]
                    .spacing(10)
                    .height(Length::FillPortion(4)),
                self.event_log_panel(),
            ]
            .spacing(10),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(12)
        .style(container_style(PanelKind::Window))
        .into()
    }
}

impl DiagnosticsApp {
    fn header(&self) -> Element<'_, Message> {
        container(
            row![
                column![
                    text("AIACS Diagnostics / Security Validation")
                        .size(24)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(ACCENT_PINK)),
                    text("Controlled adversarial validation for technician testing")
                        .size(13)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(ACCENT_BLUE)),
                ]
                .spacing(3)
                .width(Length::Fill),
                button(text("Close / Exit").size(12).font(Font::MONOSPACE))
                    .padding([7, 10])
                    .style(button_style())
                    .on_press(Message::Exit),
            ]
            .spacing(12)
            .align_items(Alignment::Center),
        )
        .width(Length::Fill)
        .padding(12)
        .style(container_style(PanelKind::Elevated))
        .into()
    }

    fn attack_panel(&self) -> Element<'_, Message> {
        let buttons = ATTACKS.iter().fold(
            column![
                text("Attack Scenarios")
                    .size(16)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(ACCENT_PINK)),
                text("Testing mode only. Normal provisioning is isolated.")
                    .size(12)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(ACCENT_BLUE)),
            ]
            .spacing(7),
            |column, (label, key)| {
                column.push(attack_button(label, Message::RunAttack(label, key)))
            },
        );

        container(buttons.push(attack_button("Run All Attacks", Message::RunAllAttacks)))
            .width(Length::FillPortion(2))
            .height(Length::Fill)
            .padding(12)
            .style(container_style(PanelKind::Elevated))
            .into()
    }

    fn evidence_panel(&self) -> Element<'_, Message> {
        let steps = self.step_trace.iter().fold(
            column![text("Attack Step Trace")
                .size(14)
                .font(Font::MONOSPACE)
                .style(theme::Text::Color(ACCENT_BLUE))]
            .spacing(6),
            |column, step| {
                column.push(
                    text(step.as_str())
                        .size(12)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(PRIMARY_TEXT)),
                )
            },
        );

        container(
            column![
                text(self.selected_title.as_str())
                    .size(16)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(ACCENT_PINK)),
                scrollable(steps).height(Length::FillPortion(2)),
                text("Expected vs Actual Outcome")
                    .size(14)
                    .font(Font::MONOSPACE)
                    .style(theme::Text::Color(ACCENT_BLUE)),
                scrollable(
                    text(self.selected_result.as_str())
                        .size(12)
                        .font(Font::MONOSPACE)
                        .style(theme::Text::Color(PRIMARY_TEXT))
                )
                .height(Length::FillPortion(3)),
            ]
            .spacing(10),
        )
        .width(Length::FillPortion(4))
        .height(Length::Fill)
        .padding(12)
        .style(container_style(PanelKind::Panel))
        .into()
    }

    fn event_log_panel(&self) -> Element<'_, Message> {
        let entries = self.event_log.iter().fold(
            column![text("Diagnostics Event Log")
                .size(16)
                .font(Font::MONOSPACE)
                .style(theme::Text::Color(ACCENT_PINK))]
            .spacing(5),
            |column, entry| {
                let (timestamp, tag, message) = log_parts(entry);
                column.push(
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

        container(scrollable(entries).height(Length::Fill))
            .width(Length::Fill)
            .height(Length::FillPortion(1))
            .padding(10)
            .style(container_style(PanelKind::Log))
            .into()
    }

    fn push_log(&mut self, tag: &str, message: impl AsRef<str>) {
        let message = message.as_ref();
        self.event_log.push(timestamped(tag, message));
        let _ = self.controller.save_log_entry(tag, message);
    }
}

#[derive(Clone, Copy)]
enum PanelKind {
    Window,
    Panel,
    Elevated,
    Log,
}

#[derive(Clone, Copy)]
struct PanelStyle {
    kind: PanelKind,
}

impl iced::widget::container::StyleSheet for PanelStyle {
    type Style = Theme;

    fn appearance(&self, _style: &Self::Style) -> iced::widget::container::Appearance {
        let (background, border_color, width) = match self.kind {
            PanelKind::Window => (WINDOW_BG, WINDOW_BG, 0.0),
            PanelKind::Panel => (PANEL_BG, BORDER, 1.0),
            PanelKind::Elevated => (ELEVATED_BG, BORDER, 1.0),
            PanelKind::Log => (LOG_BG, BORDER, 1.0),
        };

        iced::widget::container::Appearance {
            text_color: Some(PRIMARY_TEXT),
            background: Some(Background::Color(background)),
            border: Border {
                color: border_color,
                width,
                radius: 7.0.into(),
            },
            ..Default::default()
        }
    }
}

#[derive(Clone, Copy)]
struct DiagnosticsButtonStyle;

impl iced::widget::button::StyleSheet for DiagnosticsButtonStyle {
    type Style = Theme;

    fn active(&self, _style: &Self::Style) -> iced::widget::button::Appearance {
        iced::widget::button::Appearance {
            background: Some(Background::Color(BUTTON_BG)),
            text_color: PRIMARY_TEXT,
            border: Border {
                color: BUTTON_BORDER,
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
}

fn container_style(kind: PanelKind) -> theme::Container {
    theme::Container::Custom(Box::new(PanelStyle { kind }))
}

fn button_style() -> theme::Button {
    theme::Button::custom(DiagnosticsButtonStyle)
}

fn attack_button<'a>(label: &'a str, message: Message) -> Element<'a, Message> {
    button(
        text(label)
            .size(12)
            .font(Font::MONOSPACE)
            .horizontal_alignment(alignment::Horizontal::Left),
    )
    .width(Length::Fill)
    .padding([7, 9])
    .style(button_style())
    .on_press(message)
    .into()
}

fn format_suite_results(results: &[String]) -> String {
    let mut output = format!("Scenarios run: {}\n\n", results.len());
    for result in results {
        output.push_str(result);
        output.push_str("\n\n");
    }
    output
}

fn summarize_result(result: &str) -> String {
    result
        .lines()
        .find(|line| line.starts_with("Attack:") || line.starts_with("Scenario:"))
        .map(|line| line.replace("Attack: ", "").replace("Scenario: ", ""))
        .unwrap_or_else(|| result.replace(['\r', '\n'], " | "))
}

fn log_tag_color(tag: &str) -> Color {
    match tag {
        "[INFO]" => ACCENT_BLUE,
        "[ATTACK]" | "[ERROR]" => DANGER_RED,
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

fn timestamped(tag: &str, message: &str) -> String {
    format!("{} {} {}", Local::now().format("%H:%M:%S"), tag, message)
}
