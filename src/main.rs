use aiacs::{access, attacks, auth, ca, crypto, keyfob, session, vehicle};
use iced::widget::{button, column, container, text};
use iced::{Element, Length, Sandbox, Settings};

pub fn main() -> iced::Result {
    AIACSApp::run(Settings::default())
}

#[derive(Default)]
struct AIACSApp {
    state: AppState,
}

#[derive(Default, Clone, Copy, Debug, PartialEq)]
enum AppState {
    #[default]
    MainMenu,
    CertificateAuthority,
    Authentication,
    AttackSimulation,
    SessionMonitor,
}

#[derive(Debug, Clone)]
enum Message {
    NavigateTo(AppState),
    CAInitialize,
    CAIssueCertificate,
    AuthLegitimate,
    AttackReplay,
    AttackForge,
    AttackFakeCert,
    AttackRelay,
    AttackTamper,
}

impl Sandbox for AIACSApp {
    type Message = Message;

    fn new() -> Self {
        Self::default()
    }

    fn title(&self) -> String {
        "AIACS — Automotive Identity and Access Control System".to_string()
    }

    fn update(&mut self, message: Message) {
        match message {
            Message::NavigateTo(state) => self.state = state,
            Message::CAInitialize => {
                println!("[GUI] CA Initialize triggered");
            }
            Message::CAIssueCertificate => {
                println!("[GUI] CA Issue Certificate triggered");
            }
            Message::AuthLegitimate => {
                println!("[GUI] Legitimate Authentication triggered");
            }
            Message::AttackReplay => {
                println!("[GUI] Replay Attack triggered");
            }
            Message::AttackForge => {
                println!("[GUI] Forged Signature Attack triggered");
            }
            Message::AttackFakeCert => {
                println!("[GUI] Fake Certificate Attack triggered");
            }
            Message::AttackRelay => {
                println!("[GUI] Delayed Relay Attack triggered");
            }
            Message::AttackTamper => {
                println!("[GUI] Packet Tampering Attack triggered");
            }
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let content = match self.state {
            AppState::MainMenu => self.view_main_menu(),
            AppState::CertificateAuthority => self.view_ca_menu(),
            AppState::Authentication => self.view_auth_menu(),
            AppState::AttackSimulation => self.view_attack_menu(),
            AppState::SessionMonitor => self.view_session_monitor(),
        };

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .center_y()
            .into()
    }
}

impl AIACSApp {
    fn view_main_menu(&self) -> Element<'_, Message> {
        let title = text("AIACS Control Panel").size(32);

        let ca_btn = button("Certificate Authority")
            .on_press(Message::NavigateTo(AppState::CertificateAuthority));
        let auth_btn =
            button("Authentication").on_press(Message::NavigateTo(AppState::Authentication));
        let attack_btn =
            button("Attack Simulation").on_press(Message::NavigateTo(AppState::AttackSimulation));
        let session_btn =
            button("Session Monitor").on_press(Message::NavigateTo(AppState::SessionMonitor));

        column![title, ca_btn, auth_btn, attack_btn, session_btn]
            .spacing(10)
            .into()
    }

    fn view_ca_menu(&self) -> Element<'_, Message> {
        let back_btn = button("Back").on_press(Message::NavigateTo(AppState::MainMenu));
        let init_btn = button("Initialize CA").on_press(Message::CAInitialize);
        let issue_btn = button("Issue Certificate").on_press(Message::CAIssueCertificate);

        column![text("Certificate Authority"), init_btn, issue_btn, back_btn]
            .spacing(10)
            .into()
    }

    fn view_auth_menu(&self) -> Element<'_, Message> {
        let back_btn = button("Back").on_press(Message::NavigateTo(AppState::MainMenu));
        let legit_btn = button("Legitimate Authentication").on_press(Message::AuthLegitimate);

        column![text("Authentication"), legit_btn, back_btn]
            .spacing(10)
            .into()
    }

    fn view_attack_menu(&self) -> Element<'_, Message> {
        let back_btn = button("Back").on_press(Message::NavigateTo(AppState::MainMenu));
        let replay_btn = button("Replay Attack").on_press(Message::AttackReplay);
        let forge_btn = button("Forged Signature").on_press(Message::AttackForge);
        let fake_cert_btn = button("Fake Certificate").on_press(Message::AttackFakeCert);
        let relay_btn = button("Delayed Relay").on_press(Message::AttackRelay);
        let tamper_btn = button("Packet Tampering").on_press(Message::AttackTamper);

        column![
            text("Attack Simulation"),
            replay_btn,
            forge_btn,
            fake_cert_btn,
            relay_btn,
            tamper_btn,
            back_btn
        ]
        .spacing(10)
        .into()
    }

    fn view_session_monitor(&self) -> Element<'_, Message> {
        let back_btn = button("Back").on_press(Message::NavigateTo(AppState::MainMenu));

        column![
            text("Session Monitor"),
            text("(No active sessions)"),
            back_btn
        ]
        .spacing(10)
        .into()
    }
}
