use packet_utils::{build_rst_packet_from, src_dst_details, tcp_details};
use pcap::{Capture, Packet};

mod packet_utils;

fn main() {
    let cap = pcap::Device::lookup().unwrap().unwrap();
    println!("dev: {:?}", cap.name);
    let cap = Capture::from_device(cap).unwrap().promisc(true);
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
    cap.filter(filter, true).unwrap();

    // start sniffing
    let mut count = 0;
    while let Ok(packet) = cap.next_packet(){
        // if count == 1 {break;}
        if packet_utils::is_ipv4(&packet) && packet_utils::ack_enabled(&packet) {
            println!("-----------------");
            let rst = build_rst_packet_from(&packet);
            // println!("{:X?}", packet.data);
            let rp = Packet{
                header: packet.header,
                data: &rst
            };
            println!("sending packet:");
            // println!("flags for rst_packet: {:#010b}", get_flag(&rp));
            // println!("flags for packet: {:#010b}", get_flag(&packet));
            // println!("rp is ipv4: {}, is ack: {}", is_ipv4(&rp), ack_enabled(&rp));
            // test checksum algo
            // let slice : &[u8] = &[0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06,
            // 0x00, 0x00, 0xac, 0x10, 0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c ];
            // println!("calculted checksum for slice: {:X?}", checksum(slice));
            // println!("calculated checksum : {:#018b}", checksum(slice));
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
        count += 1;
        println!("recieved packets: {}", count);
    }

}
