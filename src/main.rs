use std::net::IpAddr;

use configs::Config;
use domains::Resolved;
use filters::Blacklist;
use packet_utils::{build_rst_packet_from, src_dst_details, get_protocol, Protocol, TransportProtocol, TcpFlags};
use pcap::{Capture, Packet};
use anyhow::Result;

use crate::{packet_utils::UdpProtocol, filters::PacketAction};

use pretty_env_logger::env_logger::Env;
use log::{info,trace};

mod packet_utils;
mod configs;
mod errors;
mod filters;
mod domains;
// mod pseudo_struct;
// mod resolved_domain;
// mod blacklist;

fn main() -> Result<()> {
    pretty_env_logger::env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    // pretty_env_logger::init();
    info!("Starting application");
    trace!("Some trace");
    // error!("Failed to resolve DNS of [192.168.0.1]");

    let config = Config::build()?;
    let bl = Blacklist::build(&config.filter);
    let mut domains = Resolved::build();

    let fils = &config.filter;
    fils.iter().for_each(|f| {
        println!("{f:?}");
    });

    let cap = pcap::Device::lookup()?.unwrap();
    info!("Device is {}", cap.name);
    let cap = Capture::from_device(cap).unwrap().immediate_mode(true).promisc(true);

    //open and filter
    let mut cap = cap.open().unwrap();
    let filter_tcp_syn = "tcp[13] & 2!=0";
    let filter_tcp_ack = "tcp[13] & 16 != 0";
    let filter_dns_rsp = "udp src port 53 and udp[2] & 0x80 != 0";
    let filter = format!("{filter_tcp_syn} or {filter_tcp_ack} or ({filter_dns_rsp})");
    cap.filter(&filter, true).unwrap();

    while let Ok(packet) = cap.next_packet(){
        let (src,_,_,dst,_,_) = src_dst_details(&packet);
        let (src, dst) = (IpAddr::V4(src),IpAddr::V4(dst));

        match bl.get_packet_action(&src, &dst, &domains) {
            PacketAction::Ignore => {continue;}
            PacketAction::Monitor(fil) => {
                info!("Detected connection src:[{}] -> dst:[{}] matched filter : [{:?}]",src,dst,fil);
                continue;
            }
            PacketAction::Kill => {}
        };

        let proto = get_protocol(&packet);
        dbg!(proto.clone());
        match proto {
            Protocol::Ipv4(transport) => {
                match transport {
                    TransportProtocol::TCP(tcp) => {
                        match tcp {
                            TcpFlags::SynAck(syn,ack) => {
                                if ack || syn {
                                    let rst = build_rst_packet_from(&packet, syn);
                                    let rp = Packet{
                                        header: packet.header,
                                        data: &rst
                                    };
                                    println!("sending packet:");
                                    src_dst_details(&rp);
                                    // tcp_details(&rp);
                                    // println!("===========");
                                    if let Err(e) = cap.sendpacket(rst){
                                        eprintln!("send-error: {e:?}");
                                    }
                                }
                            },
                            TcpFlags::Other => {}
                        }
                    },
                    TransportProtocol::UDP(u) => {
                        match u {
                            UdpProtocol::DNS => {
                                domains.update_from_dns(packet.data)
                            },
                            _ => {}
                        }
                    },
                    _ => {}
                }

            },
            Protocol::Ipv6(_) => {}
        }
    }
    let fils = &config.filter;
    fils.iter().for_each(|f| {
        println!("{f:?}");
    });
    Ok(())
}
