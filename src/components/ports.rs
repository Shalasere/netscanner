use cidr::Ipv4Cidr;
use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use crossterm::event::{Event, KeyCode, KeyEvent};
use dns_lookup::{lookup_addr, lookup_host};
use futures::StreamExt;
use futures::future::join_all;
use futures::stream;
use ratatui::style::Stylize;
use ratatui::{prelude::*, widgets::*};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::{
    net::TcpStream,
    sync::{
        Semaphore,
        mpsc::{self, UnboundedSender},
    },
};
use tui_input::Input;
use tui_input::backend::crossterm::EventHandler; // Brings `handle_event` into scope. // For port input.

use super::Component;
// Adjust these to match your own definitions:
use crate::enums::{PortsScanState, TabsEnum};
use crate::mode::Mode;
use crate::{
    action::Action, // For example, PortScan(String, u16) and PortScanDone(String)
    config::DEFAULT_BORDER_STYLE,
    layout::get_vertical_layout,
    tui::Frame,
    utils::get_ips4_from_cidr,
};

pub const DEFAULT_COMMON_PORTS: &[u16] = &[22, 80, 443];
pub const DEFAULT_SCAN_NETWORK: &str = "192.168.1.0/24";

static PORT_POOL_SIZE: usize = 64;
static IP_POOL_SIZE: usize = 32;
const SPINNER_SYMBOLS: [&str; 6] = ["⠷", "⠯", "⠟", "⠻", "⠽", "⠾"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputTarget {
    Ports,
    Network,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScannedIpPorts {
    pub ip: String,
    state: PortsScanState,
    hostname: String,
    pub ports: Vec<u16>,
}

pub struct Ports {
    active_tab: TabsEnum,
    action_tx: Option<UnboundedSender<Action>>,
    ip_ports: Vec<ScannedIpPorts>,
    list_state: ListState,
    scrollbar_state: ScrollbarState,
    spinner_index: usize,
    port_input: Input,                 // For user-specified ports.
    specified_ports: Option<Vec<u16>>, // Parsed port numbers.
    network_input: Input,
    input_target: InputTarget,
    input_error: Option<String>,
    mode: Mode, // Normal or Input mode.
    port_desc: Option<port_desc::PortDescription>,
}

impl Default for Ports {
    fn default() -> Self {
        Self::new()
    }
}

impl Ports {
    pub fn new() -> Self {
        let port_desc = port_desc::PortDescription::default().ok();
        Self {
            active_tab: TabsEnum::Discovery,
            action_tx: None,
            ip_ports: Vec::new(),
            list_state: ListState::default().with_selected(Some(0)),
            scrollbar_state: ScrollbarState::new(0),
            spinner_index: 0,
            port_input: Input::default().with_value("22,80,443".to_string()),
            specified_ports: None,
            network_input: Input::default().with_value(DEFAULT_SCAN_NETWORK.to_string()),
            input_target: InputTarget::Ports,
            input_error: None,
            mode: Mode::Normal,
            port_desc,
        }
    }

    pub fn get_scanned_ports(&self) -> &Vec<ScannedIpPorts> {
        &self.ip_ports
    }

    fn make_list_from_data(
        ip_ports: Vec<ScannedIpPorts>,
        spinner_index: usize,
        port_desc: Option<&port_desc::PortDescription>,
        rect: Rect,
    ) -> List<'static> {
        let mut items = Vec::new();
        for ip in ip_ports.iter() {
            let mut lines = Vec::new();
            let mut ip_line_vec = vec!["IP:    ".yellow(), ip.ip.clone().blue()];
            if !ip.hostname.is_empty() {
                ip_line_vec.push(" (".into());
                ip_line_vec.push(ip.hostname.clone().cyan());
                ip_line_vec.push(")".into());
            }
            lines.push(Line::from(ip_line_vec));

            let mut ports_spans = vec!["PORTS: ".yellow()];
            if ip.state == PortsScanState::Waiting {
                ports_spans.push("?".red());
            } else if ip.state == PortsScanState::Scanning {
                let spinner = SPINNER_SYMBOLS[spinner_index];
                ports_spans.push(spinner.magenta());
            } else {
                let mut line_size = 0;
                for p in &ip.ports {
                    let port_str = p.to_string();
                    line_size += port_str.len();
                    ports_spans.push(port_str.green());
                    if let Some(pd) = port_desc {
                        let p_type =
                            pd.get_port_service_name(*p, port_desc::TransportProtocol::Tcp);
                        let p_type_str = format!("({})", p_type);
                        ports_spans.push(p_type_str.clone().light_magenta());
                        line_size += p_type_str.len();
                    }
                    ports_spans.push(", ".yellow());
                    let t_width: usize = (rect.width as usize).saturating_sub(8);
                    if line_size >= t_width {
                        line_size = 0;
                        lines.push(Line::from(ports_spans.clone()));
                        ports_spans.clear();
                        ports_spans.push("       ".gray());
                    }
                }
            }
            lines.push(Line::from(ports_spans.clone()));
            let text = Text::from(lines);
            items.push(text);
        }
        List::new(items)
            .block(
                Block::new()
                    .title(
                        ratatui::widgets::block::Title::from(Line::from(vec![
                            Span::styled("|", Style::default().fg(Color::Yellow)),
                            Span::styled(
                                "s",
                                Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                            ),
                            Span::styled("can network", Style::default().fg(Color::Yellow)),
                            Span::styled("|", Style::default().fg(Color::Yellow)),
                            Span::styled(
                                "a",
                                Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                            ),
                            Span::styled("ll listed", Style::default().fg(Color::Yellow)),
                            Span::styled("|", Style::default().fg(Color::Yellow)),
                            Span::styled(
                                "p",
                                Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                            ),
                            Span::styled("orts input", Style::default().fg(Color::Yellow)),
                            Span::styled("|", Style::default().fg(Color::Yellow)),
                        ]))
                        .alignment(Alignment::Right),
                    )
                    .title(
                        ratatui::widgets::block::Title::from("|Ports|".yellow())
                            .position(ratatui::widgets::block::Position::Top)
                            .alignment(Alignment::Right),
                    )
                    .title(
                        ratatui::widgets::block::Title::from(Line::from(vec![
                            Span::styled("|", Style::default().fg(Color::Yellow)),
                            String::from(char::from_u32(0x25b2).unwrap_or('>')).red(),
                            String::from(char::from_u32(0x25bc).unwrap_or('>')).red(),
                            Span::styled("select|", Style::default().fg(Color::Yellow)),
                        ]))
                        .position(ratatui::widgets::block::Position::Bottom)
                        .alignment(Alignment::Right),
                    )
                    .border_style(Style::default().fg(Color::Rgb(100, 100, 100)))
                    .borders(Borders::ALL)
                    .border_type(crate::config::DEFAULT_BORDER_STYLE)
                    .padding(Padding::new(1, 3, 1, 1)),
            )
            .highlight_symbol("*")
            .highlight_style(
                Style::default()
                    .add_modifier(Modifier::BOLD)
                    .bg(Color::Rgb(100, 100, 100)),
            )
    }

    fn process_ip(&mut self, ip: &str) {
        let ipv4: Ipv4Addr = match ip.parse() {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!("Failed to parse IP {}: {}", ip, e);
                return;
            }
        };
        // Log an error if DNS lookup fails, but don't crash.
        let hostname = lookup_addr(&ipv4.into()).unwrap_or_else(|e| {
            eprintln!("DNS lookup failed for {}: {}", ip, e);
            String::new()
        });
        if let Some(existing) = self.ip_ports.iter_mut().find(|item| item.ip == ip) {
            existing.hostname = hostname;
        } else {
            self.ip_ports.push(ScannedIpPorts {
                ip: ip.to_string(),
                hostname,
                state: PortsScanState::Waiting,
                ports: Vec::new(),
            });
        }
        self.set_scrollbar_height();
    }

    fn set_scrollbar_height(&mut self) {
        let ip_len = if self.ip_ports.is_empty() {
            0
        } else {
            self.ip_ports.len() - 1
        };
        self.scrollbar_state = self.scrollbar_state.content_length(ip_len);
    }

    fn previous_in_list(&mut self) {
        let index = match self.list_state.selected() {
            Some(0) => {
                if self.ip_ports.is_empty() {
                    0
                } else {
                    self.ip_ports.len() - 1
                }
            }
            Some(idx) => idx - 1,
            None => 0,
        };
        self.list_state.select(Some(index));
        self.scrollbar_state = self.scrollbar_state.position(index);
    }

    fn next_in_list(&mut self) {
        let index = match self.list_state.selected() {
            Some(idx) => {
                let max_index = if self.ip_ports.is_empty() {
                    0
                } else {
                    self.ip_ports.len() - 1
                };
                if idx >= max_index { 0 } else { idx + 1 }
            }
            None => 0,
        };
        self.list_state.select(Some(index));
        self.scrollbar_state = self.scrollbar_state.position(index);
    }

    fn parse_ports(port_str: &str) -> Result<Vec<u16>, String> {
        if port_str.contains('-') {
            let parts: Vec<&str> = port_str.split('-').collect();
            if parts.len() != 2 {
                return Err("Invalid range format".into());
            }
            let start: u16 = parts[0].trim().parse().map_err(|_| "Invalid start port")?;
            let end: u16 = parts[1].trim().parse().map_err(|_| "Invalid end port")?;
            if start > end {
                return Err("Start port must be lower than end port".into());
            }
            Ok((start..=end).collect())
        } else {
            port_str
                .split(',')
                .map(|s| {
                    s.trim()
                        .parse::<u16>()
                        .map_err(|_| format!("Invalid port: {}", s))
                })
                .collect()
        }
    }

    fn make_port_input(&self, scroll: usize) -> Paragraph<'_> {
        Paragraph::new(self.port_input.value())
            .style(Style::default().fg(Color::Green))
            .scroll((0, scroll as u16))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(
                        if self.mode == Mode::Input && self.input_target == InputTarget::Ports {
                            Style::default().fg(Color::Green)
                        } else {
                            Style::default().fg(Color::Rgb(100, 100, 100))
                        },
                    )
                    .border_type(DEFAULT_BORDER_STYLE)
                    .title(
                        ratatui::widgets::block::Title::from(Line::from(vec![
                            Span::raw("|"),
                            Span::styled(
                                "p",
                                Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                            ),
                            Span::styled("orts (comma CSV)", Style::default().fg(Color::Yellow)),
                            Span::raw("/"),
                            Span::styled(
                                "ESC",
                                Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                            ),
                            Span::raw("|"),
                        ]))
                        .alignment(Alignment::Right)
                        .position(ratatui::widgets::block::Position::Bottom),
                    )
                    .title(
                        ratatui::widgets::block::Title::from(Line::from(vec![
                            Span::raw("|"),
                            Span::styled(
                                "d",
                                Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                            ),
                            Span::styled(
                                "efaults / TAB switch",
                                Style::default().fg(Color::Yellow),
                            ),
                            Span::raw("|"),
                        ]))
                        .alignment(Alignment::Left)
                        .position(ratatui::widgets::block::Position::Bottom),
                    ),
            )
    }

    fn make_network_input(&self, scroll: usize) -> Paragraph<'_> {
        Paragraph::new(self.network_input.value())
            .style(Style::default().fg(Color::Green))
            .scroll((0, scroll as u16))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(
                        if self.mode == Mode::Input && self.input_target == InputTarget::Network {
                            Style::default().fg(Color::Green)
                        } else {
                            Style::default().fg(Color::Rgb(100, 100, 100))
                        },
                    )
                    .border_type(DEFAULT_BORDER_STYLE)
                    .title(
                        ratatui::widgets::block::Title::from(Line::from(vec![
                            Span::raw("|"),
                            Span::styled(
                                "n",
                                Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                            ),
                            Span::styled("etwork CIDR", Style::default().fg(Color::Yellow)),
                            Span::raw("|"),
                        ]))
                        .alignment(Alignment::Right)
                        .position(ratatui::widgets::block::Position::Bottom),
                    )
                    .title(
                        ratatui::widgets::block::Title::from(Line::from(vec![
                            Span::raw("|"),
                            Span::styled(
                                "s",
                                Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                            ),
                            Span::styled("can network", Style::default().fg(Color::Yellow)),
                            Span::raw("|"),
                        ]))
                        .alignment(Alignment::Left)
                        .position(ratatui::widgets::block::Position::Bottom),
                    ),
            )
    }

    fn parse_network(&self) -> Result<Ipv4Cidr, String> {
        self.network_input
            .value()
            .trim()
            .parse::<Ipv4Cidr>()
            .map_err(|_| format!("Invalid network CIDR: {}", self.network_input.value()))
    }

    fn begin_input_mode(&mut self, target: InputTarget) {
        self.input_target = target;
        self.input_error = None;
        self.mode = Mode::Input;
        if let Some(tx) = &self.action_tx {
            let _ = tx.send(Action::AppModeChange(Mode::Input));
        }
    }

    fn finish_input_mode(&mut self) {
        self.mode = Mode::Normal;
        if let Some(tx) = &self.action_tx {
            let _ = tx.send(Action::AppModeChange(Mode::Normal));
        }
    }

    fn get_ports_to_scan(&self) -> Vec<u16> {
        if let Some(ref ports) = self.specified_ports {
            ports.clone()
        } else {
            DEFAULT_COMMON_PORTS.to_vec()
        }
    }

    fn scan_targets(&mut self, selected_indices: Vec<usize>) {
        if selected_indices.is_empty() {
            return;
        }

        let tx = match self.action_tx.clone() {
            Some(tx) => tx,
            None => {
                eprintln!("Action TX not registered");
                return;
            }
        };
        let default_ports = self.get_ports_to_scan();

        let mut targets: Vec<(String, IpAddr, Vec<u16>)> = Vec::new();
        for index in selected_indices {
            if index >= self.ip_ports.len() {
                continue;
            }
            if self.ip_ports[index].state == PortsScanState::Scanning {
                continue;
            }
            let ip_key = self.ip_ports[index].ip.clone();
            let ip_addr: IpAddr = match ip_key.parse() {
                Ok(addr) => addr,
                Err(e) => {
                    eprintln!("Failed to parse IP address {}: {}", ip_key, e);
                    continue;
                }
            };
            self.ip_ports[index].ports.clear();
            self.ip_ports[index].state = PortsScanState::Scanning;
            targets.push((ip_key, ip_addr, default_ports.clone()));
        }
        if targets.is_empty() {
            return;
        }

        tokio::spawn(async move {
            let ip_semaphore = Arc::new(Semaphore::new(IP_POOL_SIZE));
            let jobs = targets.into_iter().map(|(ip_key, ip_addr, ports_vec)| {
                let tx = tx.clone();
                let ip_semaphore = ip_semaphore.clone();
                tokio::spawn(async move {
                    let _permit = ip_semaphore.acquire_owned().await;
                    stream::iter(ports_vec)
                        .for_each_concurrent(PORT_POOL_SIZE, |port| {
                            Self::scan(tx.clone(), ip_key.clone(), ip_addr, port, 2)
                        })
                        .await;
                    if let Err(e) = tx.send(Action::PortScanDone(ip_key.clone())) {
                        eprintln!("Failed to send PortScanDone for {}: {}", ip_key, e);
                    }
                })
            });
            let _ = join_all(jobs).await;
        });
    }

    fn scan_selected(&mut self) {
        if let Some(index) = self.list_state.selected() {
            self.scan_targets(vec![index]);
        }
    }

    fn scan_ports(&mut self) {
        let mut indices = Vec::new();
        for i in 0..self.ip_ports.len() {
            if self.ip_ports[i].state != PortsScanState::Scanning {
                indices.push(i);
            }
        }
        self.scan_targets(indices);
    }

    fn scan_network_ports(&mut self) {
        let cidr = match self.parse_network() {
            Ok(cidr) => cidr,
            Err(err) => {
                self.input_error = Some(err);
                return;
            }
        };
        self.input_error = None;

        self.ip_ports.clear();
        for ip in get_ips4_from_cidr(cidr) {
            self.ip_ports.push(ScannedIpPorts {
                ip: ip.to_string(),
                state: PortsScanState::Waiting,
                hostname: String::new(),
                ports: Vec::new(),
            });
        }
        self.set_scrollbar_height();
        self.list_state.select(Some(0));
        self.scan_ports();
    }

    fn handle_ports_key_input(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Enter => match Self::parse_ports(self.port_input.value()) {
                Ok(ports) => {
                    self.specified_ports = Some(ports);
                    self.input_error = None;
                    self.finish_input_mode();
                    Some(Action::ModeChange(Mode::Normal))
                }
                Err(err) => {
                    self.input_error = Some(err);
                    None
                }
            },
            KeyCode::Tab => {
                self.input_target = InputTarget::Network;
                None
            }
            _ => {
                self.port_input.handle_event(&Event::Key(key));
                None
            }
        }
    }

    fn handle_network_key_input(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Enter => {
                if let Err(err) = self.parse_network() {
                    self.input_error = Some(err);
                    return None;
                }
                self.input_error = None;
                self.finish_input_mode();
                Some(Action::ModeChange(Mode::Normal))
            }
            KeyCode::Tab => {
                self.input_target = InputTarget::Ports;
                None
            }
            _ => {
                self.network_input.handle_event(&Event::Key(key));
                None
            }
        }
    }

    async fn scan(
        tx: UnboundedSender<Action>,
        ip_key: String,
        ip: IpAddr,
        port: u16,
        timeout: u64,
    ) {
        let timeout_duration = Duration::from_secs(timeout);
        let socket_addr = SocketAddr::new(ip, port);
        match tokio::time::timeout(timeout_duration, TcpStream::connect(&socket_addr)).await {
            Ok(Ok(_stream)) => {
                // Clone ip_key so that the original remains available for logging.
                if let Err(e) = tx.send(Action::PortScan(ip_key.clone(), port)) {
                    eprintln!(
                        "Failed to send PortScan for {} port {}: {}",
                        ip_key, port, e
                    );
                }
            }
            Ok(Err(e)) => {
                eprintln!("Connection error on {}: {}", socket_addr, e);
            }
            Err(e) => {
                eprintln!("Timeout connecting to {}: {}", socket_addr, e);
            }
        }
    }

    fn store_scanned_port(&mut self, ip_key: &str, port: u16) {
        if let Some(entry) = self.ip_ports.iter_mut().find(|item| item.ip == ip_key)
            && !entry.ports.contains(&port)
        {
            entry.ports.push(port);
        }
    }

    fn make_list(&self, rect: Rect) -> List<'static> {
        let mut items = Vec::new();
        for ip in &self.ip_ports {
            let mut lines = Vec::new();
            let mut ip_line_vec = vec!["IP:    ".yellow(), ip.ip.clone().blue()];
            if !ip.hostname.is_empty() {
                ip_line_vec.push(" (".into());
                ip_line_vec.push(ip.hostname.clone().cyan());
                ip_line_vec.push(")".into());
            }
            lines.push(Line::from(ip_line_vec));

            let mut ports_spans = vec!["PORTS: ".yellow()];
            if ip.state == PortsScanState::Waiting {
                ports_spans.push("?".red());
            } else if ip.state == PortsScanState::Scanning {
                let spinner = SPINNER_SYMBOLS[self.spinner_index];
                ports_spans.push(spinner.magenta());
            } else {
                let mut line_size = 0;
                for p in &ip.ports {
                    let port_str = p.to_string();
                    line_size += port_str.len();
                    ports_spans.push(port_str.green());
                    if let Some(pd) = &self.port_desc {
                        let p_type =
                            pd.get_port_service_name(*p, port_desc::TransportProtocol::Tcp);
                        let p_type_str = format!("({})", p_type);
                        ports_spans.push(p_type_str.clone().light_magenta());
                        line_size += p_type_str.len();
                    }
                    ports_spans.push(", ".yellow());
                    let t_width: usize = (rect.width as usize).saturating_sub(8);
                    if line_size >= t_width {
                        line_size = 0;
                        lines.push(Line::from(ports_spans.clone()));
                        ports_spans.clear();
                        ports_spans.push("       ".gray());
                    }
                }
            }
            lines.push(Line::from(ports_spans.clone()));
            let text = Text::from(lines);
            items.push(text);
        }
        List::new(items)
            .block(
                Block::new()
                    .title(
                        ratatui::widgets::block::Title::from(Line::from(vec![
                            Span::styled("|", Style::default().fg(Color::Yellow)),
                            Span::styled(
                                "s",
                                Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                            ),
                            Span::styled("can network", Style::default().fg(Color::Yellow)),
                            Span::styled("|", Style::default().fg(Color::Yellow)),
                            Span::styled(
                                "a",
                                Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                            ),
                            Span::styled("ll listed", Style::default().fg(Color::Yellow)),
                            Span::styled("|", Style::default().fg(Color::Yellow)),
                            Span::styled(
                                "p",
                                Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                            ),
                            Span::styled("orts input", Style::default().fg(Color::Yellow)),
                            Span::styled("|", Style::default().fg(Color::Yellow)),
                        ]))
                        .alignment(Alignment::Right),
                    )
                    .title(
                        ratatui::widgets::block::Title::from("|Ports|".yellow())
                            .position(ratatui::widgets::block::Position::Top)
                            .alignment(Alignment::Right),
                    )
                    .title(
                        ratatui::widgets::block::Title::from(Line::from(vec![
                            Span::styled("|", Style::default().fg(Color::Yellow)),
                            String::from(char::from_u32(0x25b2).unwrap_or('>')).red(),
                            String::from(char::from_u32(0x25bc).unwrap_or('>')).red(),
                            Span::styled("select|", Style::default().fg(Color::Yellow)),
                        ]))
                        .position(ratatui::widgets::block::Position::Bottom)
                        .alignment(Alignment::Right),
                    )
                    .border_style(Style::default().fg(Color::Rgb(100, 100, 100)))
                    .borders(Borders::ALL)
                    .border_type(DEFAULT_BORDER_STYLE)
                    .padding(Padding::new(1, 3, 1, 1)),
            )
            .highlight_symbol("*")
            .highlight_style(
                Style::default()
                    .add_modifier(Modifier::BOLD)
                    .bg(Color::Rgb(100, 100, 100)),
            )
    }

    pub fn make_scrollbar<'a>() -> Scrollbar<'a> {
        Scrollbar::default()
            .orientation(ScrollbarOrientation::VerticalRight)
            .style(Style::default().fg(Color::Rgb(100, 100, 100)))
            .begin_symbol(None)
            .end_symbol(None)
    }
}

impl Component for Ports {
    fn init(&mut self, _area: Size) -> Result<()> {
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.action_tx = Some(tx);
        Ok(())
    }

    fn tab_changed(&mut self, tab: TabsEnum) -> Result<()> {
        self.active_tab = tab;
        Ok(())
    }

    fn handle_key_events(&mut self, key: KeyEvent) -> Result<Option<Action>> {
        if self.active_tab != TabsEnum::Ports || self.mode != Mode::Input {
            return Ok(None);
        }

        if key.code == KeyCode::Esc {
            self.finish_input_mode();
            return Ok(Some(Action::ModeChange(Mode::Normal)));
        }

        let action = match self.input_target {
            InputTarget::Ports => self.handle_ports_key_input(key),
            InputTarget::Network => self.handle_network_key_input(key),
        };
        Ok(action)
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        match &action {
            Action::Tick => {
                self.spinner_index = (self.spinner_index + 1) % SPINNER_SYMBOLS.len();
            }
            Action::TabChange(tab) => {
                self.tab_changed(*tab)?;
            }
            _ => {}
        }

        if self.active_tab == TabsEnum::Ports {
            match &action {
                Action::Down => self.next_in_list(),
                Action::Up => self.previous_in_list(),
                Action::ScanSelected => self.scan_selected(),
                Action::ScanCidr => self.scan_network_ports(),
                Action::ScanAll => self.scan_ports(),
                Action::PortInput => self.begin_input_mode(InputTarget::Ports),
                Action::NetworkInput => self.begin_input_mode(InputTarget::Network),
                Action::ModeChange(mode) if *mode == Mode::Normal && self.mode == Mode::Input => {
                    self.finish_input_mode();
                }
                _ => {}
            }
        }

        match &action {
            Action::PortScan(ip_key, port) => {
                self.store_scanned_port(ip_key, *port);
            }
            Action::PortScanDone(ip_key) => {
                if let Some(entry) = self.ip_ports.iter_mut().find(|item| item.ip == *ip_key) {
                    entry.state = PortsScanState::Done;
                }
            }
            Action::PingIp(ip) => self.process_ip(ip),
            _ => {}
        }

        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        if self.active_tab == TabsEnum::Ports {
            let layout = get_vertical_layout(area);
            let mut list_rect = layout.bottom;
            list_rect.y += 1;
            list_rect.height = list_rect.height.saturating_sub(1);

            let list = self.make_list(list_rect);
            f.render_stateful_widget(list, list_rect, &mut self.list_state);

            let scrollbar = Self::make_scrollbar();
            let mut scroll_rect = list_rect;
            scroll_rect.y += 1;
            scroll_rect.height = scroll_rect.height.saturating_sub(2);
            f.render_stateful_widget(
                scrollbar,
                scroll_rect.inner(Margin {
                    vertical: 1,
                    horizontal: 1,
                }),
                &mut self.scrollbar_state,
            );

            let input_size: u16 = 34;
            let right_x = list_rect.x + list_rect.width.saturating_sub(input_size + 1);
            let ports_rect = Rect::new(right_x, list_rect.y + 1, input_size, 3);
            let network_rect = Rect::new(right_x, list_rect.y + 5, input_size, 3);

            let p_scroll = self.port_input.visual_scroll((input_size - 3) as usize);
            let n_scroll = self.network_input.visual_scroll((input_size - 3) as usize);
            f.render_widget(self.make_port_input(p_scroll), ports_rect);
            f.render_widget(self.make_network_input(n_scroll), network_rect);

            if let Some(err) = &self.input_error {
                let err_rect = Rect::new(right_x, list_rect.y + 9, input_size, 3);
                let err_block = Paragraph::new(err.as_str())
                    .style(Style::default().fg(Color::Red))
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(Color::Red))
                            .border_type(DEFAULT_BORDER_STYLE),
                    );
                f.render_widget(err_block, err_rect);
            }

            if self.mode == Mode::Input {
                match self.input_target {
                    InputTarget::Ports => f.set_cursor_position((
                        ports_rect.x + (self.port_input.visual_cursor() as u16) + 1,
                        ports_rect.y + 1,
                    )),
                    InputTarget::Network => f.set_cursor_position((
                        network_rect.x + (self.network_input.visual_cursor() as u16) + 1,
                        network_rect.y + 1,
                    )),
                }
            }
        }
        Ok(())
    }
}
