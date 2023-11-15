use std::net::Ipv4Addr;
use pcap::Packet;

pub fn is_ipv4(packet: &Packet) -> bool {
    let ip_header = &packet.data[14..34];
    let ip_version = (ip_header[0] & 0b11110000) >> 4;
    ip_version == 4
}

pub fn ack_enabled(packet: &Packet) -> bool {
    let tcp_header = &packet.data[34..54];
    let flags = tcp_header[13];
    // let rst = (flags & 0b00000100) != 0;
    // let fin = (flags & 0b00000001) != 0;
    let ack = (flags & 0b00010000) == 16;
    println!("checking ack : {:#010b} evaluated {ack}", flags);
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
    let (src_ip, src_port, src_mac, dst_ip, dst_port, dst_mac) = src_dst_details(&packet);
    let (seq_num, ack_num, window_size) = tcp_details(&packet);

    let mut pkt = Vec::with_capacity(54);
    pkt.extend_from_slice(dst_mac);
    pkt.extend_from_slice(src_mac);
    pkt.extend_from_slice(&[0x08, 0x00]);

    // IP header
    pkt.extend_from_slice(&[
                          0x45, // IP version & header length
                          0x00, // DSCP and ECN
                          0x00, 0x14, // Total lenght
                          0x06, 0x50, // Identification - dontt forget to set this to a unique value later !!!!!!
                          0x40, 0x00, // Flags & fragment offset
                          0x3c, 0x06, // TTL adn protocol(TCP)
                          0x00, 0x00, // temporary Header checksum
    ]);
    pkt.extend_from_slice(&src_ip.octets());
    pkt.extend_from_slice(&dst_ip.octets());

    let ip_checksum = checksum(&pkt[14..33]);
    pkt[24..26].copy_from_slice(&ip_checksum.to_be_bytes());

    // TCP section
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&(seq_num + 1).to_be_bytes());
    pkt.extend_from_slice(&(ack_num - ack_num).to_be_bytes());
    // pkt.extend_from_slice(&[0x50, 0x00]); // data offset and reserved
    pkt.extend_from_slice(&[0b00010100]); // data offset and reserved
    pkt.extend_from_slice(&[0b00010100]); // flag
                                          // pkt.push(0b00000100);
    pkt.extend_from_slice(&window_size.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // initial tcp checksum
    pkt.extend_from_slice(&[0x00, 0x00]); // urgency

    let mut pseudo_ip_header: Vec<u8> = Vec::with_capacity(12);
    pseudo_ip_header.extend_from_slice(&src_ip.octets());
    pseudo_ip_header.extend_from_slice(&dst_ip.octets());
    pseudo_ip_header.extend_from_slice(&[0x00]); //fixed 8 bit
    pseudo_ip_header.extend_from_slice(&[0x06]); //protocol field
    pseudo_ip_header.extend_from_slice(&[0x14]); //TCP segment length
    pseudo_ip_header.extend_from_slice(&pkt[34..]);

    let tcp_checksum = checksum(&pseudo_ip_header);
    pkt[50..52].copy_from_slice(&tcp_checksum.to_be_bytes());

    pkt
}

pub fn checksum(bytes: &[u8]) -> u16 {
    let mut checksum: u32 = 0;
    for i in (0..bytes.len()-1).step_by(2) {
        let word = u16::from_be_bytes([bytes[i], bytes[i+1]]);
        checksum = checksum.wrapping_add(word as u32);
    }
    if bytes.len() % 2 == 1 {
        checksum = checksum.wrapping_add(bytes[bytes.len() -1] as u32) << 8;
    }
    while checksum >> 16 != 0 {
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }
    println!("calculated checksum : {:X?}", checksum as u16);
    !checksum as u16
}

pub fn src_dst_details<'a>(
    packet: &'a Packet,
) -> (Ipv4Addr, u16, &'a [u8], Ipv4Addr, u16, &'a [u8]) {
    let eth_header = &packet.data[0..14];
    // println!("ethernet_header size {:?}", eth_header.len());
    let src_mac = eth_header[0..6].try_into().unwrap();
    let dst_mac = eth_header[6..12].try_into().unwrap();

    let ip_header = &packet.data[14..34];
    let src_ip = Ipv4Addr::new(ip_header[12], ip_header[13], ip_header[14], ip_header[15]);
    let dst_ip = Ipv4Addr::new(ip_header[16], ip_header[17], ip_header[18], ip_header[19]);
    // let src_ip = Ipv4Addr::from(ip_header[12..16]);
    // let dst_ip = Ipv4Addr::from(ip_header[16..20]);
    let tcp_header = &packet.data[34..]; // 34..54
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
    let tcp_header = &packet.data[34..]; //54
    // println!("tcp_header size {:?}", tcp_header.len());
    let seq_num = u32::from_be_bytes([tcp_header[4], tcp_header[5], tcp_header[6], tcp_header[7]]);
    // let window_bytes = &tcp_header[12..16];
    let window_bytes = &tcp_header[14..16];
    let window_size = u16::from_be_bytes([window_bytes[0], window_bytes[1]]);
    let ack_num =
        u32::from_be_bytes([tcp_header[8], tcp_header[9], tcp_header[10], tcp_header[11]]);
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
