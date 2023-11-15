use std::net::Ipv4Addr;
use pcap::Packet;

pub fn is_ipv4(packet: &Packet) -> bool {
    let ip_header = &packet.data[14..34];
    let ip_version = (ip_header[0] & 0b11110000) >> 4;
    ip_version == 4
}

pub fn ack_enabled(packet: &Packet) -> bool{ 
    let tcp_header = &packet.data[34..54]; 
    let flags = tcp_header[13]; 
    // let rst = (flags & 0b00000100) != 0; 
    // let fin = (flags & 0b00000001) != 0;
    let ack = (flags & 0b00010000) != 0; 
    ack
}

// pub fn get_flag(packet: &Packet) -> u8 {
//     let tcp_header = &packet.data[34..]; // 34..54
//     let flags = tcp_header[13];
//     // let src_port_bytes = [tcp_header[0], tcp_header[1]];
//     // let src_port = u16::from_be_bytes(src_port_bytes);
//     flags
// }
//
pub fn build_rst_packet_from(packet: &Packet) -> Vec<u8> {
    let (src_ip, _src_port, src_mac, dst_ip, _dst_port, dst_mac) = src_dst_details(&packet);
    let (seq_num, ack_num, _window_size) = tcp_details(&packet);

    let mut pkt = Vec::with_capacity(54);
    pkt.extend_from_slice(dst_mac); 
    pkt.extend_from_slice(src_mac);
    pkt.extend_from_slice(&[0x08, 0x00]);

   // IP header
    pkt.extend_from_slice(&[0x45, 0x00, 0x00, 0x28]); // IP version
    pkt.extend_from_slice(&src_ip.octets());
    pkt.extend_from_slice(&dst_ip.octets());

    // TCP section
    pkt.extend_from_slice(&[0b00000100]);
    pkt.extend_from_slice(&seq_num.to_be_bytes());
    pkt.extend_from_slice(&ack_num.to_be_bytes());

    pkt
}

pub fn src_dst_details<'a>(packet: &'a Packet) -> (Ipv4Addr, u16, &'a [u8], Ipv4Addr, u16, &'a [u8]){
      let eth_header = &packet[0..14];
      let src_mac = eth_header[0..6].try_into().unwrap();
      let dst_mac = eth_header[6..12].try_into().unwrap();

      let ip_header = &packet.data[14..34];
      let src_ip = Ipv4Addr::new(ip_header[12], ip_header[13], ip_header[14], ip_header[15]);
      let dst_ip = Ipv4Addr::new(ip_header[16], ip_header[17], ip_header[18], ip_header[19]);
      // let src_ip = Ipv4Addr::from(ip_header[12..16]);
      // let dst_ip = Ipv4Addr::from(ip_header[16..20]);
      let tcp_header = &packet.data[34..54];
      let src_port_bytes = [tcp_header[0], tcp_header[1]];
      let src_port = u16::from_be_bytes(src_port_bytes);

      let dst_port_bytes = [tcp_header[2], tcp_header[3]];
      let dst_port = u16::from_be_bytes(dst_port_bytes);

      println!(
          "src: {}:{}, src_mac: {:X?}, dst: {}:{}, dst_mac: {:X?}",
          src_ip, src_port, src_mac, dst_ip, dst_port, dst_mac
        );
      (src_ip, src_port, src_mac, dst_ip, dst_port, dst_mac)
}

pub fn tcp_details(packet: &Packet) -> (u32, u32, u16) { 
    let tcp_header = &packet.data[34..54]; 
    let seq_num = u32::from_be_bytes([tcp_header[4], tcp_header[5], tcp_header[6], tcp_header[7]]);
    let window_bytes = &tcp_header[12..16];
    let window_size = u16::from_be_bytes([window_bytes[0], window_bytes[1]]);
    let ack_num = u32::from_be_bytes( [tcp_header[8], tcp_header[9], tcp_header[10], tcp_header[11]]);
    println!(
        "seq_num: {}, ack_num: {}, window_size: {}",
        seq_num, ack_num, window_size
       );
    (seq_num, ack_num, window_size)
}

// fn build_packet(
//     src_ip: Ipv4Addr,
//     src_port: u16,
//     dst_ip: Ipv4Addr,
//     dst_port: u16,
//     seq_num: u32,
//     ack_num: u32,
//  ){
//     
//
// }
//     
