use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use simple_dns::rdata::RData;

pub fn get_resolved(packet: &[u8]) -> Vec<(IpAddr, String)> {
    // let udp_header = &packet[42..54];
    // let num_answers_bytes = [packet[48], packet[49]];
    // let num_answers = u16::from_be_bytes(num_answers_bytes);
    // // let answers = [[u8; ]];
    // let mut count = 54;
    // for num in 0..num_answers {
    //     // let answer = simple_dns::Packet::parse(&packet[count..count+16]);
    // }
    //
    let mut answers : Vec<(IpAddr, String)> = vec![];
    let answer = simple_dns::Packet::parse(&packet[42..]).unwrap();
    for i in answer.answers.iter(){
        let ip: Option<IpAddr> = match &i.rdata {
            RData::A(a) => {Some(IpAddr::V4(Ipv4Addr::from(a.address)))},
            RData::AAAA(aaaa) => {Some(IpAddr::V6(Ipv6Addr::from(aaaa.address)))},
            _ => {None}
        };
        if let None = ip {continue;}
        answers.push((ip.unwrap(), i.name.to_string()));
        println!("ip {} for domain {}", ip.unwrap(), i.name);
    };
    answers
}
