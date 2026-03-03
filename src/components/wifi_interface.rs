use color_eyre::eyre::Result;
use pnet::datalink;
use ratatui::{prelude::*, widgets::*};
use std::process::{Command, Output};
use std::time::Instant;
use tokio::sync::mpsc::UnboundedSender;

use super::Component;
use crate::{
    action::Action,
    layout::{get_horizontal_layout, get_vertical_layout},
    tui::Frame,
};

#[derive(Debug, PartialEq)]
struct WifiConn {
    interface: String,
    ifindex: u32,
    mac: String,
    ssid: String,
    channel: String,
    txpower: String,
}

struct CommandError {
    desc: String,
}

pub struct WifiInterface {
    action_tx: Option<UnboundedSender<Action>>,
    last_update: Instant,
    wifi_info: Option<WifiConn>,
}

impl Default for WifiInterface {
    fn default() -> Self {
        Self::new()
    }
}

impl WifiInterface {
    pub fn new() -> Self {
        Self {
            action_tx: None,
            last_update: Instant::now(),
            wifi_info: None,
        }
    }

    fn app_tick(&mut self) -> Result<()> {
        let now = Instant::now();
        let elapsed = (now - self.last_update).as_secs_f64();

        if self.wifi_info.is_none() || elapsed > 5.0 {
            self.last_update = now;
            self.get_connected_wifi_info();
        }
        Ok(())
    }

    fn iw_command(&self, intf_name: &str, query: &str) -> Result<Output, CommandError> {
        let iw_output = Command::new("iw")
            .arg("dev")
            .arg(intf_name)
            .arg(query)
            .output()
            .map_err(|e| CommandError {
                desc: format!("command failed: {}", e),
            })?;
        if iw_output.status.success() {
            Ok(iw_output)
        } else {
            Err(CommandError {
                desc: "command failed".to_string(),
            })
        }
    }

    fn parse_iw_info_output(&self, interface_name: &str, output: &str) -> WifiConn {
        let mut conn = WifiConn {
            interface: interface_name.to_string(),
            ifindex: 0,
            mac: String::new(),
            ssid: String::new(),
            channel: String::new(),
            txpower: String::new(),
        };

        for line in output.lines().map(str::trim) {
            if let Some(v) = line.strip_prefix("ifindex ") {
                conn.ifindex = v.trim().parse::<u32>().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("addr ") {
                conn.mac = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("channel ") {
                conn.channel = v.split_whitespace().next().unwrap_or("").to_string();
            } else if let Some(v) = line.strip_prefix("txpower ") {
                conn.txpower = v.trim().to_string();
            }
        }

        conn
    }

    fn parse_iw_link_ssid(&self, output: &str) -> Option<String> {
        for line in output.lines().map(str::trim) {
            if let Some(v) = line.strip_prefix("SSID:") {
                let ssid = v.trim();
                if !ssid.is_empty() {
                    return Some(ssid.to_string());
                }
            }
        }
        None
    }

    fn get_connected_wifi_info(&mut self) {
        self.wifi_info = None;
        let mut fallback: Option<WifiConn> = None;

        let mut interfaces = datalink::interfaces();
        interfaces.sort_by(|a, b| a.name.cmp(&b.name));

        for intf in interfaces {
            let info = match self.iw_command(&intf.name, "info") {
                Ok(output) => String::from_utf8(output.stdout).unwrap_or_default(),
                Err(_) => continue,
            };

            let mut conn = self.parse_iw_info_output(&intf.name, &info);

            if let Ok(link_output) = self.iw_command(&intf.name, "link") {
                let link = String::from_utf8(link_output.stdout).unwrap_or_default();
                if let Some(ssid) = self.parse_iw_link_ssid(&link) {
                    conn.ssid = ssid;
                }
            }

            if !conn.ssid.is_empty() {
                self.wifi_info = Some(conn);
                return;
            }

            if fallback.is_none() {
                fallback = Some(conn);
            }
        }

        self.wifi_info = fallback;
    }

    fn make_list(&mut self) -> List<'_> {
        if let Some(wifi_info) = &self.wifi_info {
            let interface = &wifi_info.interface;
            let ssid = &wifi_info.ssid;
            let channel = &wifi_info.channel;
            let txpower = &wifi_info.txpower;
            let ssid_text = if ssid.is_empty() {
                "<not connected>"
            } else {
                ssid
            };

            let items: Vec<ListItem> = vec![ListItem::new(vec![
                Line::from(vec![
                    Span::styled(
                        format!("{:<10}", "Interface:"),
                        Style::default().fg(Color::White),
                    ),
                    Span::styled(interface.clone(), Style::default().fg(Color::Green)),
                    Span::raw("  "),
                    Span::styled(format!("{:<6}", "SSID:"), Style::default().fg(Color::White)),
                    Span::styled(ssid_text, Style::default().fg(Color::Green)),
                ]),
                Line::from(vec![
                    Span::styled(
                        format!("{:<10}", "Channel:"),
                        Style::default().fg(Color::White),
                    ),
                    Span::styled(format!("{channel:<12}"), Style::default().fg(Color::Green)),
                    Span::raw("  "),
                    Span::styled(
                        format!("{:<8}", "TxPower:"),
                        Style::default().fg(Color::White),
                    ),
                    Span::styled(txpower.clone(), Style::default().fg(Color::Green)),
                ]),
            ])];

            List::new(items).block(
                Block::default()
                    .borders(Borders::TOP)
                    .title("|WiFi Interface|")
                    .border_style(Style::default().fg(Color::Rgb(100, 100, 100)))
                    .title_style(Style::default().fg(Color::Yellow))
                    .padding(Padding::new(2, 0, 0, 0))
                    .title_alignment(Alignment::Right),
            )
        } else {
            let items: Vec<ListItem> = Vec::new();
            List::new(items)
        }
    }
}

impl Component for WifiInterface {
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.action_tx = Some(tx);
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        if let Action::Tick = action {
            self.app_tick()?
        }
        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        let v_layout = get_vertical_layout(area);
        let h_layout = get_horizontal_layout(area);

        let rect = Rect::new(
            h_layout.right.x + 1,
            (v_layout.top.y + v_layout.top.height) - 3,
            h_layout.right.width - 2,
            4,
        );

        let block = self.make_list();
        f.render_widget(block, rect);

        Ok(())
    }
}
