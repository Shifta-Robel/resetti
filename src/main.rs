use anyhow::Result;
use configs::Config;
use domains::Resolved;
use filters::Blacklist;
use packet_utils::{
    build_rst_packet_from, get_protocol, src_dst_details, Protocol, TcpFlags, TransportProtocol,
};
use pcap::{Capture, Packet};
use slog::{debug, info, trace, warn};
use slog_scope::logger;

use crate::{filters::PacketAction, logging::init_logger, packet_utils::UdpProtocol};

// use pretty_env_logger::env_logger::Builder;
// use log::{info,trace, warn};

mod configs;
mod domains;
mod errors;
mod filters;
mod logging;
mod packet_utils;

fn main() -> Result<()> {
    let config = Config::build()?;
    let bl = Blacklist::build(&config.filter);
    let mut domains = Resolved::build();

    let _guard = init_logger(config.log);

    info!(logger(), "Starting application");
    trace!(logger(), "Some trace");
    debug!(logger(), "some debug");
    // error!("Failed to resolve DNS of [192.168.0.1]");
    let fils = &config.filter;
    fils.iter().for_each(|f| {
        println!("{f:?}");
    });

    let cap = match config.interface {
        configs::Interface::Lookup => pcap::Device::lookup().unwrap().unwrap(),
        configs::Interface::Custom(dev) => pcap::Device::from(dev.as_str()),
    };

    // let cap = pcap::Device::lookup()?.unwrap();
    info!(logger(), "Sniffing on interface:  [{}]", cap.name);
    let cap = Capture::from_device(cap)
        .unwrap()
        .immediate_mode(true)
        .promisc(true);

    //open and filter
    let mut cap = cap.open().unwrap();
    let filter_tcp_syn = "tcp[13] & 2!=0";
    let filter_tcp_ack = "tcp[13] & 16 != 0";
    let filter_dns_rsp = "udp src port 53 and udp[2] & 0x80 != 0";
    let filter = format!("{filter_tcp_syn} or {filter_tcp_ack} or ({filter_dns_rsp})");
    cap.filter(&filter, true).unwrap();

    while let Ok(packet) = cap.next_packet() {
        let (src, src_port, src_mac, dst, dst_port, dst_mac) = src_dst_details(&packet);
        let src = std::net::IpAddr::V4(src);
        let dst = std::net::IpAddr::V4(dst);
        let arg = (src, src_port, src_mac, dst, dst_port, dst_mac);

        match bl.get_packet_action(arg, &domains) {
            PacketAction::Ignore => {
                continue;
            }
            PacketAction::Monitor => {
                warn!(
                    logger(),
                    "detected connection src:[{}] -> dst:[{}]", src, dst
                );
                continue;
            }
            PacketAction::Reset => {}
            PacketAction::SynReset => {
                unimplemented!()
            }
        };

        let proto = get_protocol(&packet);
        dbg!(proto.clone());
        match proto {
            Protocol::Ipv4(transport) => {
                match transport {
                    TransportProtocol::TCP(tcp) => {
                        match tcp {
                            TcpFlags::SynAck(syn, ack) => {
                                if ack || syn {
                                    let rst = build_rst_packet_from(&packet, syn);
                                    let rp = Packet {
                                        header: packet.header,
                                        data: &rst,
                                    };
                                    println!("sending packet:");
                                    src_dst_details(&rp);
                                    // tcp_details(&rp);
                                    // println!("===========");
                                    if let Err(e) = cap.sendpacket(rst) {
                                        eprintln!("send-error: {e:?}");
                                    }
                                }
                            }
                            TcpFlags::Other => {}
                        }
                    }
                    TransportProtocol::UDP(u) => match u {
                        UdpProtocol::DNS => domains.update_from_dns(packet.data),
                        _ => {}
                    },
                    _ => {}
                }
            }
            Protocol::Ipv6(_) => {}
        }
    }
    let fils = &config.filter;
    fils.iter().for_each(|f| {
        println!("{f:?}");
    });
    Ok(())
}
