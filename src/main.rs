use std::{eprintln, println};

use packet_utils::{build_rst_packet_from, src_dst_details, tcp_details};
use pcap::{Capture, Packet};

mod packet_utils;
mod pseudo_struct;

fn main() {
    let cap = pcap::Device::lookup().unwrap().unwrap();
    println!("dev: {:?}", cap.name);
    let cap = Capture::from_device(cap).unwrap().immediate_mode(true).promisc(true);
    // let cap = Capture::from_device("wlp0s20f3").unwrap().promisc(true);
    // let list: Vec<Device> = pcap::Device::list().unwrap();
    // println!("list len: {}", list.len());
    // for i in 0..list.len() {
    //     println!("device : {:?}", list[i].clone().name);
    // }

    // let device = Device::from("tun0");
    // println!("device: {}", device.name);

    //open and filter
    let mut cap = cap.open().unwrap();
    let filter = "tcp";
    // additional filter logic from config
    cap.filter(filter, true).unwrap();

    // start sniffing
    // let mut count = 0;
    while let Ok(packet) = cap.next_packet(){
        // if count == 1 {break;}
        println!("packet: {:?}", packet.len());
        let (is_syn,is_ack) = packet_utils::syn_ack_flags(&packet);

        if packet_utils::is_ipv4(&packet) &&(is_syn || is_ack) {
                println!("-----------------");
                let rst = build_rst_packet_from(&packet, is_syn);
                let rp = Packet{
                    header: packet.header,
                    data: &rst
                };
                println!("sending packet:");
                src_dst_details(&rp);
                tcp_details(&rp);
                println!("===========");

                if let Err(e) = cap.sendpacket(rst){
                    eprintln!("send-error: {:?}", e);
                }
            }else{
                println!("packet discarded");
                continue;
            }
        }
        // count += 1;
        // println!("recieved packets: {}", count);

}
