#![allow(unused)]
use pcap::Packet;
use rayon::{prelude::ParallelIterator, slice::ParallelSlice};
use std::{
    net::Ipv4Addr,
    sync::atomic::{AtomicU32, AtomicU64},
};

#[derive(Debug,Clone)]
pub enum Protocol{
    Ipv4(TransportProtocol),
    Ipv6(TransportProtocol)
}

#[derive(Debug,Clone)]
pub enum TransportProtocol{
    TCP(TcpFlags),
    UDP(UdpProtocol),
    Other
}

#[derive(Debug,Clone)]
pub enum TcpFlags {
    SynAck(bool, bool),
    Other
}

#[derive(Debug,Clone)]
pub enum UdpProtocol {
    DNS,
    Other
}

pub fn is_ipv4(packet: &Packet) -> bool {
    let ip_header = &packet.data[14..34];
    let ip_version = (ip_header[0] & 0b1111_0000) >> 4;
    ip_version == 4
}

pub fn syn_ack_flags(tcp_header: &[u8]) -> (bool, bool) {
    // let tcp_header = &packet.data[34..54];
    let flags = tcp_header[13];
    let ack = (flags & 0b0001_0000) == 16;
    let syn = (flags & 0b0000_0010) == 2;
    (syn, ack)
}

fn tcp_header_idx(packet: &Packet) -> u8{
    let ihl = &packet[14] & 0b0000_1111;
    
    14 + ihl * 4
}

pub fn get_protocol(packet: &Packet) -> Protocol {
    let is_ipv4 = is_ipv4(packet);
    if is_ipv4 {
        let protocol = &packet.data[23];
        match protocol {
            6 => {
                let ix = tcp_header_idx(packet);
                let (syn,ack) = syn_ack_flags(&packet.data[ix.into()..]);
                let transport = if syn || ack {
                    TcpFlags::SynAck(syn, ack)
                }else {
                    TcpFlags::Other
                };
                Protocol::Ipv4(TransportProtocol::TCP(transport))
            },
            17 => {
                Protocol::Ipv4(TransportProtocol::UDP(UdpProtocol::DNS))
            },
            _ => {
                Protocol::Ipv4(TransportProtocol::Other)
            }
        }
    }else {
        // ipv6 logic
        unimplemented!()
    }
}

// pub fn ack_enabled(packet: &Packet) -> bool {
//     let tcp_header = &packet.data[34..54];
//     let flags = tcp_header[13];
//     let ack = (flags & 0b00010000) == 16;
//     println!("checking ack : {:#010b} evaluated {ack}", flags);
//     ack
// }

pub fn build_rst_packet_from(packet: &Packet, is_syn: bool) -> Vec<u8> {
    let (src_ip, src_port, src_mac, dst_ip, dst_port, dst_mac) = src_dst_details(packet);
    let (seq_num, ack_num, window_size) = tcp_details(packet);

    let mut pkt = Vec::with_capacity(54);
    pkt.extend_from_slice(src_mac);
    pkt.extend_from_slice(dst_mac);
    pkt.extend_from_slice(&[0x08, 0x00]);

    // IP header
    pkt.extend_from_slice(&[
        0x45, // IP version & header length
        0x00, // DSCP and ECN
        0x00, 0x28, // Total lenght
        0x06, 0x50, // Identification - dontt forget to set this to a unique value later !!!
        0x40, 0x00, // Flags & fragment offset
        0x3c, 0x06, // TTL adn protocol(TCP)
        0x00, 0x00, // temporary Header checksum
    ]);
    pkt.extend_from_slice(&dst_ip.octets());
    pkt.extend_from_slice(&src_ip.octets());

    let ip_checksum = checksum(&pkt[14..34]);
    pkt[24..26].copy_from_slice(&ip_checksum.to_be_bytes());

    // TCP section
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&src_port.to_be_bytes());
    // pkt.extend_from_slice(&(seq_num + payload_len as u32 + 1).to_be_bytes());
    let rst_seq_num = &(if is_syn { seq_num + 1 } else { ack_num }).to_be_bytes();
    pkt.extend_from_slice(rst_seq_num); // seq num
                                        // pkt.extend_from_slice(&(ack_num + packet.len() as u32).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack 0
                                                      // pkt.extend_from_slice(&[0x50, 0x00]); // data offset and reserved
                                                      // pkt.extend_from_slice(&[0b00010100]); // data offset and reserved
    pkt.extend_from_slice(&[0x50]); // data offset and reserved
    pkt.extend_from_slice(&[0b0000_0100]); // flag

    pkt.extend_from_slice(&window_size.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // initial tcp checksum
    pkt.extend_from_slice(&[0x00, 0x00]); // urgency

    let mut pseudo_ip_header: Vec<u8> = Vec::with_capacity(12);
    pseudo_ip_header.extend_from_slice(&src_ip.octets());
    pseudo_ip_header.extend_from_slice(&dst_ip.octets());
    pseudo_ip_header.extend_from_slice(&[0x00]); //fixed 8 bit
    pseudo_ip_header.extend_from_slice(&[0x06]); //protocol field
    pseudo_ip_header.extend_from_slice(&20u16.to_be_bytes()); //TCP segment length
    pseudo_ip_header.extend_from_slice(&pkt[34..]);
    pseudo_ip_header[28] = 0;
    pseudo_ip_header[29] = 0;
    println!("rst packet");
    for bytes in &pseudo_ip_header {
        print!("{bytes:02X} ");
    }

    let tcp_checksum = checksum(&pseudo_ip_header);
    println!("calculated rst checksum: {tcp_checksum:X?}");
    pkt[50..52].copy_from_slice(&tcp_checksum.to_be_bytes());

    pkt
}

// pub fn packet_checksum(packet: &Packet) -> u16 {
//     let (src_ip, _, _, dst_ip, _, _) = src_dst_details(&packet);
//     let mut pseudo_ip_header: Vec<u8> = Vec::with_capacity(12);
//     pseudo_ip_header.extend_from_slice(&src_ip.octets());
//     pseudo_ip_header.extend_from_slice(&dst_ip.octets());
//     pseudo_ip_header.extend_from_slice(&[0x00]); //fixed 8 bit
//     pseudo_ip_header.extend_from_slice(&[0x06]); //protocol field
//     let tcp_seg_len = packet.data[34..].len() as u16;
//     println!("tcp_seg_len :{tcp_seg_len}");
//     pseudo_ip_header.extend_from_slice(&tcp_seg_len.to_be_bytes()); //TCP segment length
//     // append rest of tcp section on to the pseudo_ip_header
//     println!("pseude header: {} after len",pseudo_ip_header.len());
//     for bytes in &pseudo_ip_header {
//         print!("{:02X} ", bytes);
//     }
//     pseudo_ip_header.extend_from_slice(&packet[34..]);
//     pseudo_ip_header[28] = 0;
//     pseudo_ip_header[29] = 0;
//     println!("pseude header: {} after body",pseudo_ip_header.len());
//     for bytes in &pseudo_ip_header {
//         print!("{:02X} ", bytes);
//     }
//     println!("My tcp checksum : {:X?}",checksum(&pseudo_ip_header));
//     let ics = internet_checksum::checksum(&pseudo_ip_header);
//     println!("crate tcp checksum : {:X?},{:X?}",ics[0], ics[1]);
//     checksum(&pseudo_ip_header)
// }
//
// #[cfg(target_pointer_width = "32")]
pub fn checksum_by2(bytes: &[u8]) -> u16 {
    let mut checksum : u32 = bytes
        .chunks_exact(2)
        .map(|c| u32::from_be_bytes([0, 0, c[0], c[1]]))
        .reduce(|a, b| a + b)
        .unwrap();
    let len = bytes.len();
    if len % 2 == 1 {
        checksum += u32::from(bytes[len - 1]) << 8;
    }
    while checksum >> 16 != 0 {
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }
    !checksum as u16
}

pub fn checksum_2_par(bytes: &[u8]) -> u16 {
    let checksum = AtomicU32::new(0);

    bytes.par_chunks_exact(2).for_each(|chunk| {
        checksum.fetch_add(
            u32::from(u16::from_be_bytes([chunk[0], chunk[1]])),
            std::sync::atomic::Ordering::Relaxed,
        );
    });
    let mut checksum: u32 = checksum.into_inner();

    if bytes.len() % 2 == 1 {
        checksum += u32::from(bytes[bytes.len() - 1]) << 8;
    }
    while checksum >> 16 != 0 {
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }
    !checksum as u16
}

#[cfg(target_pointer_width = "64")]
pub fn checksum(bytes: &[u8]) -> u16 {
    let mut checksum = bytes
        .chunks_exact(4)
        .map(|c| u64::from(u32::from_be_bytes([c[0],c[1],c[2],c[3]])))
        .reduce(|a,b| a + b)
        .unwrap();
    let len = bytes.len();
    if len % 4 != 0 {
        let slice = &bytes[len-len%4..];
        let mut acc: u32 = 0;
        for i in 0..slice.len() { acc |= (slice[i] as u32) << ((3-i)*8); };
        checksum += u64::from(acc);
    }
    while checksum >> 32 != 0 {
        checksum = (checksum & 0xffffffff) + (checksum >> 32)
    }
    let mut checksum = (checksum >> 16) as u32 + (checksum & 0x0000ffff) as u32;
    if checksum > 0xffff { checksum = (checksum & 0xffff) + 1 }
    !checksum as u16
}

pub fn checksum_par(bytes: &[u8]) -> u16 {
    let mut checksum = AtomicU64::new(0);
    let len = bytes.len();
    bytes.par_chunks_exact(4).for_each(|chunk| {
        checksum.fetch_add(
            u64::from(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])),
            std::sync::atomic::Ordering::Relaxed,
        );
    });
    let mut checksum: u64 = checksum.into_inner();
    if len % 4 != 0 {
        let mut octs = [0u8; 4];
        for i in 0..(len % 4) {
            octs[i] = bytes[len - (len % 4) + i]
        }
        checksum += u64::from(u32::from_be_bytes(octs)) << 32;
    };
    while checksum >> 32 != 0 {
        checksum = (checksum & 0xffffffff) + (checksum >> 32)
    }
    let mut checksum = (checksum >> 16) as u32 + (checksum & 0x0000ffff) as u32;
    if checksum > 0xffff {
        checksum = (checksum & 0xffff) + 1
    }
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
    // let tcp_header = &packet.data[34..]; // 34..54
    let tcp_header = &packet.data[tcp_header_idx(packet).into()..]; // 34..54
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

/// Extracts TCP details from a packet
/// # Returns
/// A tuple with
/// * sequence number
/// * ack number
/// * window size
/// * payload len
pub fn tcp_details(tcp_header: &[u8]) -> (u32, u32, u16) {
    // let tcp_header = &packet.data[34..]; //54
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
    // let tcp_data_offset = tcp_header[12] >> 4;
    // let payload_len = packet.len() - (34 + (tcp_data_offset * 4)) as usize;
    (seq_num, ack_num, window_size )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checksum_calculation_valid_for_even_number_of_bytes() {
        let bytes: &[u8] = &[
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        assert_eq!(checksum(bytes), 0xB1E6);
    }

    #[test]
    fn checksum_calculation_valid_for_even_number_of_bytes_2() {
        let bytes: &[u8] = &[
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        assert_eq!(checksum_by2(bytes), 0xB1E6);
    }

    #[test]
    fn checksum_calculation_valid_for_even_number_of_bytes_par() {
        let bytes: &[u8] = &[
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        assert_eq!(checksum_par(bytes), 0xB1E6);
    }

    #[test]
    fn checksum_calculation_valid_for_odd_number_of_bytes() {
        let bytes: &[u8] = &[
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c, 0x34,
        ];
        assert_eq!(checksum(bytes), 0x7DE6);
    }
    #[test]
    fn checksum_calculation_valid_for_odd_number_of_bytes_by_2() {
        let bytes: &[u8] = &[
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c, 0x34,
        ];
        assert_eq!(checksum_by2(bytes), 0x7DE6);
    }

    #[test]
    fn checksum_calculation_valid_for_odd_number_of_bytes_par() {
        let bytes: &[u8] = &[
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c, 0x34,
        ];
        assert_eq!(checksum_par(bytes), 0x7DE6);
    }

    #[test]
    fn rfc_checksum_calculation_valid_for_even_number_of_bytes() {
        let bytes: &[u8] = &[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(!checksum(bytes), 0xddf2);
    }

    // checksum for ip
    // checksum for tcp
    // checksum valid for a packet
}
