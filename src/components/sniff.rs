use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use dns_lookup::{lookup_addr, lookup_host};

use ipnetwork::IpNetwork;
use pnet::{
    datalink::NetworkInterface,
    packet::{
        MutablePacket, Packet,
        arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
        ethernet::{EtherTypes, MutableEthernetPacket},
    },
};
use ratatui::style::Stylize;

use ratatui::{prelude::*, widgets::*};
use std::collections::HashSet;
use std::net::IpAddr;
use tokio::sync::mpsc::{self, UnboundedSender};
use tui_scrollview::{ScrollView, ScrollViewState};

use super::Component;
use crate::{
    action::Action,
    config::DEFAULT_BORDER_STYLE,
    enums::{PacketTypeEnum, PacketsInfoTypesEnum, TabsEnum},
    layout::{HORIZONTAL_CONSTRAINTS, get_vertical_layout},
    tui::Frame,
    utils::bytes_convert,
    widgets::scroll_traffic::TrafficScroll,
};

#[derive(Clone, Debug)]
pub struct IPTraffic {
    pub ip: IpAddr,
    pub download: f64,
    pub upload: f64,
    pub hostname: String,
}

pub struct Sniffer {
    active_tab: TabsEnum,
    action_tx: Option<UnboundedSender<Action>>,
    list_state: ListState,
    scrollbar_state: ScrollbarState,
    traffic_ips: Vec<IPTraffic>,
    scrollview_state: ScrollViewState,
    udp_sum: f64,
    tcp_sum: f64,
    active_inft_ips: Vec<IpNetwork>,
    traffic_dirty: bool,
}

impl Default for Sniffer {
    fn default() -> Self {
        Self::new()
    }
}

impl Sniffer {
    pub fn new() -> Self {
        Self {
            active_tab: TabsEnum::Discovery,
            action_tx: None,
            list_state: ListState::default().with_selected(Some(0)),
            scrollbar_state: ScrollbarState::new(0),
            traffic_ips: Vec::new(),
            scrollview_state: ScrollViewState::new(),
            udp_sum: 0.0,
            tcp_sum: 0.0,
            active_inft_ips: Vec::new(),
            traffic_dirty: false,
        }
    }

    fn scroll_down(&mut self) {
        self.scrollview_state.scroll_down();
    }

    fn scroll_up(&mut self) {
        self.scrollview_state.scroll_up();
    }

    fn count_traffic_packet(&mut self, source: IpAddr, destination: IpAddr, length: usize) {
        let length = length as f64;
        Self::update_traffic_entry(&mut self.traffic_ips, destination, length, 0.0);
        Self::update_traffic_entry(&mut self.traffic_ips, source, 0.0, length);
        self.traffic_dirty = true;
    }

    fn update_traffic_entry(
        traffic_ips: &mut Vec<IPTraffic>,
        ip: IpAddr,
        download_inc: f64,
        upload_inc: f64,
    ) {
        if let Some(entry) = traffic_ips.iter_mut().find(|entry| entry.ip == ip) {
            entry.download += download_inc;
            entry.upload += upload_inc;
            return;
        }

        traffic_ips.push(IPTraffic {
            ip,
            download: download_inc,
            upload: upload_inc,
            hostname: lookup_addr(&ip).unwrap_or_else(|_| String::from("unknown")),
        });
    }

    fn ensure_sorted_traffic(&mut self) {
        if !self.traffic_dirty {
            return;
        }

        self.traffic_ips.sort_by(|a, b| {
            let a_sum = a.download + a.upload;
            let b_sum = b.download + b.upload;
            b_sum
                .partial_cmp(&a_sum)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        self.traffic_dirty = false;
    }

    fn process_packet(&mut self, packet: PacketsInfoTypesEnum) {
        match packet {
            PacketsInfoTypesEnum::Tcp(p) => {
                self.count_traffic_packet(p.source, p.destination, p.length);
                self.tcp_sum += p.length as f64;
            }
            PacketsInfoTypesEnum::Udp(p) => {
                self.count_traffic_packet(p.source, p.destination, p.length);
                self.udp_sum += p.length as f64;
            }
            _ => {}
        }
    }

    fn make_charts(&self) -> BarChart<'_> {
        BarChart::default()
            .direction(Direction::Vertical)
            .bar_width(12)
            .bar_gap(4)
            .data(
                BarGroup::default().bars(&[
                    Bar::default()
                        .value(self.udp_sum as u64)
                        .text_value(bytes_convert(self.udp_sum))
                        .label("UDP".into())
                        .style(Color::Yellow),
                    Bar::default()
                        .value(self.tcp_sum as u64)
                        .text_value(bytes_convert(self.tcp_sum))
                        .label("TCP".into())
                        .style(Color::Green),
                ]),
            )
    }

    fn make_ips_block(&self) -> Block<'_> {
        Block::default()
            .title(
                ratatui::widgets::block::Title::from(Line::from(vec![
                    Span::styled("|", Style::default().fg(Color::Yellow)),
                    Span::styled(
                        String::from(char::from_u32(0x25b2).unwrap_or('<')),
                        Style::default().fg(Color::Red),
                    ),
                    Span::styled(
                        String::from(char::from_u32(0x25bc).unwrap_or('>')),
                        Style::default().fg(Color::Red),
                    ),
                    Span::styled("scroll|", Style::default().fg(Color::Yellow)),
                ]))
                .position(ratatui::widgets::block::Position::Bottom)
                .alignment(Alignment::Right),
            )
            .title(
                ratatui::widgets::block::Title::from(Span::styled(
                    "|Download/Upload|",
                    Style::default().fg(Color::Yellow),
                ))
                .position(ratatui::widgets::block::Position::Top)
                .alignment(Alignment::Right),
            )
            .borders(Borders::ALL)
            .border_style(Color::Rgb(100, 100, 100))
            .border_type(BorderType::Rounded)
    }

    fn make_sum_block(&self) -> Block<'_> {
        Block::default()
            .title(
                ratatui::widgets::block::Title::from(Span::styled(
                    "|Summary|",
                    Style::default().fg(Color::Yellow),
                ))
                .position(ratatui::widgets::block::Position::Top)
                .alignment(Alignment::Right),
            )
            .borders(Borders::ALL)
            .border_style(Color::Rgb(100, 100, 100))
            .border_type(BorderType::Rounded)
    }

    fn make_charts_block(&self) -> Block<'_> {
        Block::default()
            .title(
                ratatui::widgets::block::Title::from(Span::styled(
                    "|Protocols sum|",
                    Style::default().fg(Color::Yellow),
                ))
                .position(ratatui::widgets::block::Position::Top)
                .alignment(Alignment::Right),
            )
            .borders(Borders::ALL)
            .border_style(Color::Rgb(100, 100, 100))
            .border_type(BorderType::Rounded)
    }

    fn render_summary(&mut self, f: &mut Frame<'_>, area: Rect) {
        if !self.traffic_ips.is_empty() {
            let total_download = Line::from(vec![
                "Total download: ".into(),
                bytes_convert(self.traffic_ips[0].download).green(),
            ]);
            f.render_widget(
                total_download,
                Rect {
                    x: area.x + 2,
                    y: area.y + 2,
                    width: area.width,
                    height: 1,
                },
            );

            let total_upload = Line::from(vec![
                "Total upload: ".into(),
                bytes_convert(self.traffic_ips[0].upload).red(),
            ]);
            f.render_widget(
                total_upload,
                Rect {
                    x: area.x + 2,
                    y: area.y + 3,
                    width: area.width,
                    height: 1,
                },
            );

            let active_interface_ips: HashSet<IpAddr> =
                self.active_inft_ips.iter().map(IpNetwork::ip).collect();
            let mut top_uploader: Option<&IPTraffic> = None;
            let mut top_downloader: Option<&IPTraffic> = None;

            for traffic in self
                .traffic_ips
                .iter()
                .filter(|item| !active_interface_ips.contains(&item.ip))
            {
                if top_uploader.is_none_or(|current| traffic.upload > current.upload) {
                    top_uploader = Some(traffic);
                }
                if top_downloader.is_none_or(|current| traffic.download > current.download) {
                    top_downloader = Some(traffic);
                }
            }

            let mut tu_ip = String::from("");
            let mut tu_name = String::from("");
            if let Some(tu) = top_uploader {
                tu_ip = tu.ip.to_string();
                tu_name = format!(" ({})", tu.hostname);
            }
            let top_uploader = Line::from(vec![
                "Top uploader: ".into(),
                tu_ip.blue(),
                tu_name.magenta(),
            ]);
            f.render_widget(
                top_uploader,
                Rect {
                    x: area.x + 2,
                    y: area.y + 5,
                    width: area.width,
                    height: 1,
                },
            );

            let mut td_ip = String::from("");
            let mut td_name = String::from("");
            if let Some(td) = top_downloader {
                td_ip = td.ip.to_string();
                td_name = format!(" ({})", td.hostname);
            }
            let top_downloader = Line::from(vec![
                "Top downloader: ".into(),
                td_ip.blue(),
                td_name.magenta(),
            ]);
            f.render_widget(
                top_downloader,
                Rect {
                    x: area.x + 2,
                    y: area.y + 6,
                    width: area.width,
                    height: 1,
                },
            );
        }
    }

    fn tab_changed(&mut self, tab: TabsEnum) -> Result<()> {
        self.active_tab = tab;
        Ok(())
    }
}

impl Component for Sniffer {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.action_tx = Some(tx);
        Ok(())
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        // -- tab change
        if let Action::TabChange(tab) = action {
            self.tab_changed(tab).unwrap();
        }

        if self.active_tab == TabsEnum::Traffic {
            if let Action::Down = action {
                self.scroll_down();
            }

            if let Action::Up = action {
                self.scroll_up();
            }
        }

        if let Action::ActiveInterface(ref interface) = action {
            self.active_inft_ips = interface.ips.clone();
        }

        if let Action::PacketDump(time, packet, packet_type) = action {
            match packet_type {
                PacketTypeEnum::Tcp => self.process_packet(packet),
                PacketTypeEnum::Udp => self.process_packet(packet),
                _ => {}
            }
        }

        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        if self.active_tab == TabsEnum::Traffic {
            self.ensure_sorted_traffic();
            let layout = get_vertical_layout(area);

            // -- IPs block
            let mut ips_block_rect = layout.bottom;
            ips_block_rect.y += 1;
            ips_block_rect.height -= 1;
            let ips_layout = Layout::horizontal(HORIZONTAL_CONSTRAINTS).split(ips_block_rect);
            let b = self.make_ips_block();
            f.render_widget(b, ips_layout[0]);

            // -- scrollview
            let ips_rect = Rect {
                x: ips_layout[0].x + 1,
                y: ips_layout[0].y + 1,
                width: ips_layout[0].width - 2,
                height: ips_layout[0].height - 2,
            };
            let ips_scroll = TrafficScroll {
                traffic_ips: &self.traffic_ips,
            };
            f.render_stateful_widget(ips_scroll, ips_rect, &mut self.scrollview_state);

            // -- summary
            let sum_layout =
                Layout::vertical([Constraint::Percentage(30), Constraint::Percentage(70)])
                    .split(ips_layout[1]);
            let sum_block = self.make_sum_block();
            f.render_widget(sum_block, sum_layout[0]);

            self.render_summary(f, sum_layout[0]);

            // -- charts
            let charts_block = self.make_charts_block();
            f.render_widget(charts_block, sum_layout[1]);

            let charts = self.make_charts();
            let charts_rect = Rect {
                x: sum_layout[1].x + 2,
                y: sum_layout[1].y + 2,
                width: sum_layout[1].width - 5,
                height: sum_layout[1].height - 3,
            };
            f.render_widget(charts, charts_rect);
        }

        Ok(())
    }
}
