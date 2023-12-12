use std::net::IpAddr;

use configs::Config;
use domains::Resolved;
use filters::Blacklist;
use packet_utils::{build_rst_packet_from, src_dst_details, get_protocol, Protocol, TransportProtocol, TcpFlags};
use pcap::{Capture, Packet};
use anyhow::{Result};

use crate::packet_utils::UdpProtocol;

mod packet_utils;
mod configs;
mod errors;
mod filters;
mod domains;
// mod pseudo_struct;
// mod resolved_domain;
// mod blacklist;

fn main() -> Result<()> {

    let config = Config::build()?;
    let bl = Blacklist::build(&config.filter);
    let mut domains = Resolved::build();

    let cap = pcap::Device::lookup()?.unwrap();
    let cap = Capture::from_device(cap).unwrap().immediate_mode(true).promisc(true);

    //open and filter
    let mut cap = cap.open().unwrap();
    let filter_tcp_syn = "tcp[13] & 2!=0";
    let filter_tcp_ack = "tcp[13] & 16 != 0";
    let filter_dns_rsp = "udp src port 53 and udp[2] & 0x80 != 0";
    let filter = format!("{filter_tcp_syn} or {filter_tcp_ack} or ({filter_dns_rsp})");
    cap.filter(&filter, true).unwrap();

    //
    //
    while let Ok(packet) = cap.next_packet(){
        let (src,_,_,dst,_,_) = src_dst_details(&packet);
        let src = IpAddr::V4(src);
        let dst = IpAddr::V4(dst);
        let should_block = bl.should_block(&src, &dst, &domains);
        println!("src: {src} dst: {dst} should block {should_block}");
        // if  !bl.should_block(&src, &dst, &domains) {continue};
        if !should_block {continue;}

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
    // // start sniffing
    // // let mut count = 0;
    // while let Ok(packet) = cap.next_packet(){
    //     // if count == 1 {break;}
    //     // println!("packet: {:?}", packet.len());
    //     let (is_syn,is_ack) = packet_utils::syn_ack_flags(&packet);
    //
    //     if packet_utils::is_ipv4(&packet) &&(!is_syn || is_ack) {
    //         let (src,_,_,dst,_,_) = src_dst_details(&packet);
    //         let src = IpAddr::V4(src);
    //         let dst = IpAddr::V4(dst);
    //         println!("src: {src} dst: {dst}");
    //         if true || !bl.should_block(&src, &dst, &domains) {continue};
    //
    //         println!("-----------------");
    //         let rst = build_rst_packet_from(&packet, is_syn);
    //         let rp = Packet{
    //             header: packet.header,
    //             data: &rst
    //         };
    //         println!("sending packet:");
    //         src_dst_details(&rp);
    //         tcp_details(&rp);
    //         println!("===========");
    //
    //         if let Err(e) = cap.sendpacket(rst){
    //             eprintln!("send-error: {e:?}");
    //         }
    //     }
    //     else if is_dns(&packet) {
    //         // let resolved = resolved_domain::get_resolved(packet.data);
    //         // for i in &resolved{
    //         //     blacklist.append_resolved_domain(i.clone());
    //         // }
    //         domains.update_from_dns(&packet.data)
    //     }
    //     else{
    //         println!("packet discarded");
    //         continue;
    //     }
    // }
        // count += 1;
        // println!("recieved packets: {}", count);
    //
    //
    //
    //
    let fils = &config.filter;
    fils.iter().for_each(|f| {
        println!("{f:?}");
    });
    Ok(())
}
// fn main() {
    // let cap = pcap::Device::lookup().unwrap().unwrap();
//     println!("dev: {:?}", cap.name);
//     let cap = Capture::from_device(cap).unwrap().immediate_mode(true).promisc(true);
//     // let cap = Capture::from_device("wlp0s20f3").unwrap().promisc(true);
//     // let list: Vec<Device> = pcap::Device::list().unwrap();
//     // println!("list len: {}", list.len());
//     // for i in 0..list.len() {
//     //     println!("device : {:?}", list[i].clone().name);
//     // }
//
//     // let device = Device::from("tun0");
//     // println!("device: {}", device.name);
//
//     //open and filter
//     let mut cap = cap.open().unwrap();
//     let filter_tcp_syn = "tcp[13] & 2!=0";
//     let filter_tcp_ack = "tcp[13] & 16 != 0";
//     let filter_dns_rsp = "udp src port 53 and udp[2] & 0x80 != 0";
//     let filter = format!("{filter_tcp_syn} or {filter_tcp_ack} or ({filter_dns_rsp})");
//     // additional filter logic from config
//     let mut blacklist = pseudo_struct::BlackList::init();
//     cap.filter(&filter, true).unwrap();
//
//     // start sniffing
//     // let mut count = 0;
//     while let Ok(packet) = cap.next_packet(){
//         // if count == 1 {break;}
//         // println!("packet: {:?}", packet.len());
//         let (is_syn,is_ack) = packet_utils::syn_ack_flags(&packet);
//
//         if packet_utils::is_ipv4(&packet) &&(is_syn || is_ack) {
//                 println!("-----------------");
//                 let rst = build_rst_packet_from(&packet, is_syn);
//                 let rp = Packet{
//                     header: packet.header,
//                     data: &rst
//                 };
//                 println!("sending packet:");
//                 src_dst_details(&rp);
//                 tcp_details(&rp);
//                 println!("===========");
//
//                 if let Err(e) = cap.sendpacket(rst){
//                     eprintln!("send-error: {e:?}");
//                 }
//         }
//         else if is_dns(&packet) {
//             let resolved = resolved_domain::get_resolved(packet.data);
//             for i in &resolved{
//                 blacklist.append_resolved_domain(i.clone());
//             }
//         }
//         else{
//             println!("packet discarded");
//             continue;
//         }
//     }
//         // count += 1;
//         // println!("recieved packets: {}", count);
// }
