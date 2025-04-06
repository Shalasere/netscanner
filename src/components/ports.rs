use cidr::Ipv4Cidr;
use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use crossterm::event::{Event, KeyCode, KeyEvent};
use dns_lookup::{lookup_addr, lookup_host};
use futures::stream;
use futures::StreamExt;
use ratatui::style::Stylize;
use ratatui::{prelude::*, widgets::*};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::{
    net::TcpStream,
    sync::mpsc::{self, UnboundedSender},
};
use tui_input::backend::crossterm::EventHandler; // Brings `handle_event` into scope.
use tui_input::Input; // For port input.

use super::Component;
// Adjust these to match your own definitions:
use crate::enums::{PortsScanState, TabsEnum};
use crate::mode::Mode;
use crate::{
    action::Action, // For example, PortScan(String, u16) and PortScanDone(String)
    config::DEFAULT_BORDER_STYLE,
    layout::get_vertical_layout,
    tui::Frame,
};

pub const DEFAULT_COMMON_PORTS: &[u16] = &[22, 80, 443];

static POOL_SIZE: usize = 64;
const SPINNER_SYMBOLS: [&str; 6] = ["⠷", "⠯", "⠟", "⠻", "⠽", "⠾"];

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
    mode: Mode,                        // Normal or Input mode.
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
                            Span::styled("can selected", Style::default().fg(Color::Yellow)),
                            Span::styled("|", Style::default().fg(Color::Yellow)),
                            Span::styled(
                                "a",
                                Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                            ),
                            Span::styled("ll", Style::default().fg(Color::Yellow)),
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
            Some(idx) if idx == 0 => {
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
                if idx >= max_index {
                    0
                } else {
                    idx + 1
                }
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

    fn make_port_input(&self, scroll: usize) -> Paragraph {
        Paragraph::new(self.port_input.value())
            .style(Style::default().fg(Color::Green))
            .scroll((0, scroll as u16))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(match self.mode {
                        Mode::Input => Style::default().fg(Color::Green),
                        Mode::Normal => Style::default().fg(Color::Rgb(100, 100, 100)),
                    })
                    .border_type(DEFAULT_BORDER_STYLE)
                    .title(
                        ratatui::widgets::block::Title::from(Line::from(vec![
                            Span::raw("|"),
                            Span::styled(
                                "p",
                                Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                            ),
                            Span::styled("orts", Style::default().fg(Color::Yellow)),
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
                            Span::styled("efaults", Style::default().fg(Color::Yellow)),
                            Span::raw("|"),
                        ]))
                        .alignment(Alignment::Left)
                        .position(ratatui::widgets::block::Position::Bottom),
                    ),
            )
    }

    fn handle_port_input(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Enter => match Self::parse_ports(self.port_input.value()) {
                Ok(ports) => {
                    self.specified_ports = Some(ports);
                    self.mode = Mode::Normal; // Exit port input mode.
                    None
                }
                Err(err) => Some(Action::Error(err)),
            },
            _ => {
                self.port_input.handle_event(&Event::Key(key));
                None
            }
        }
    }

    fn scan_ports_for_index(&mut self, index: usize) {
        if index >= self.ip_ports.len() {
            return;
        }
        self.ip_ports[index].state = PortsScanState::Scanning;
        let tx = match self.action_tx.clone() {
            Some(tx) => tx,
            None => {
                eprintln!("Action TX not registered");
                return;
            }
        };
        let ip_key = self.ip_ports[index].ip.clone();
        let ip_addr: IpAddr = match self.ip_ports[index].ip.parse() {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!(
                    "Failed to parse IP address {}: {}",
                    self.ip_ports[index].ip, e
                );
                return;
            }
        };
        let ports_vec: Vec<u16> = if let Some(ref ports) = self.specified_ports {
            ports.clone()
        } else {
            DEFAULT_COMMON_PORTS.to_vec()
        };

        tokio::spawn(async move {
            let ports = stream::iter(ports_vec);
            ports
                .for_each_concurrent(POOL_SIZE, |port| {
                    Self::scan(tx.clone(), ip_key.clone(), ip_addr, port, 2)
                })
                .await;
            if let Err(e) = tx.send(Action::PortScanDone(ip_key.clone())) {
                eprintln!("Failed to send PortScanDone for {}: {}", ip_key, e);
            }
        });
    }

    fn scan_selected(&mut self) {
        if let Some(index) = self.list_state.selected() {
            self.scan_ports_for_index(index);
        }
    }

    fn scan_ports(&mut self) {
        for i in 0..self.ip_ports.len() {
            if self.ip_ports[i].state != PortsScanState::Scanning {
                let tx = match self.action_tx.clone() {
                    Some(tx) => tx,
                    None => {
                        eprintln!("Action TX not registered");
                        return;
                    }
                };
                let ip_key = self.ip_ports[i].ip.clone();
                let ip_addr: IpAddr = match self.ip_ports[i].ip.parse() {
                    Ok(addr) => addr,
                    Err(e) => {
                        eprintln!("Failed to parse IP address {}: {}", self.ip_ports[i].ip, e);
                        continue;
                    }
                };
                let ports_vec: Vec<u16> = if let Some(ref ports) = self.specified_ports {
                    ports.clone()
                } else {
                    DEFAULT_COMMON_PORTS.to_vec()
                };

                tokio::spawn(async move {
                    let ports = stream::iter(ports_vec);
                    ports
                        .for_each_concurrent(POOL_SIZE, |port| {
                            Self::scan(tx.clone(), ip_key.clone(), ip_addr, port, 2)
                        })
                        .await;
                    if let Err(e) = tx.send(Action::PortScanDone(ip_key.clone())) {
                        eprintln!("Failed to send PortScanDone for {}: {}", ip_key, e);
                    }
                });
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
                    eprintln!("Failed to send PortScan for {} port {}: {}", ip_key, port, e);
                }
            },
            Ok(Err(e)) => {
                eprintln!("Connection error on {}: {}", socket_addr, e);
            },
            Err(e) => {
                eprintln!("Timeout connecting to {}: {}", socket_addr, e);
            }
        }
    }
    
    fn store_scanned_port(&mut self, ip_key: &str, port: u16) {
        if let Some(entry) = self.ip_ports.iter_mut().find(|item| item.ip == ip_key) {
            if !entry.ports.contains(&port) {
                entry.ports.push(port);
            }
        }
    }

    fn make_list(&self, rect: Rect) -> List {
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
                            Span::styled("can selected", Style::default().fg(Color::Yellow)),
                            Span::styled("|", Style::default().fg(Color::Yellow)),
                            Span::styled(
                                "a",
                                Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                            ),
                            Span::styled("ll", Style::default().fg(Color::Yellow)),
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
                Action::ScanCidr | Action::ScanSelected => self.scan_selected(),
                Action::ScanAll => self.scan_ports(),
                Action::PortInput => self.mode = Mode::Input,
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

            let ip_ports = self.ip_ports.clone();
            let spinner_index = self.spinner_index;
            let port_desc = self.port_desc.as_ref();
            let list = Self::make_list_from_data(ip_ports, spinner_index, port_desc, list_rect);
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

            if self.mode == Mode::Input {
                let input_size: u16 = 30;
                let input_rect = Rect::new(
                    list_rect.x + list_rect.width - input_size - 1,
                    list_rect.y + 1,
                    input_size,
                    3,
                );
                let scroll = self.port_input.visual_scroll((input_size - 3) as usize);
                let port_input_paragraph = self.make_port_input(scroll);
                f.render_widget(port_input_paragraph, input_rect);
                f.set_cursor_position((
                    input_rect.x + (self.port_input.visual_cursor() as u16) + 1,
                    input_rect.y + 1,
                ));
            }
        }
        Ok(())
    }
}
