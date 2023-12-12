use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use anyhow::Result;
use simple_dns::rdata::RData;


pub struct Resolved{
    resolved: HashMap<IpAddr, String>
}

impl Resolved {
    pub fn build() -> Self {
        Self{resolved: HashMap::new()}
    }
    pub fn get(&self, ip: &IpAddr) -> Option<&String> {
        self.resolved.get(ip)
    }
    pub fn update_from_dns(&mut self,packet: &[u8]) {
        let answer = simple_dns::Packet::parse(&packet[42..]);
        if answer.is_err(){return}
        let answer = answer.unwrap();
        for i in &answer.answers{
            let ip: Option<IpAddr> = match &i.rdata {
                RData::A(a) => {Some(IpAddr::V4(Ipv4Addr::from(a.address)))},
                RData::AAAA(aaaa) => {Some(IpAddr::V6(Ipv6Addr::from(aaaa.address)))},
                _ => {None}
            };
            if ip.is_none() {continue}
            self.resolved.insert(ip.unwrap(), i.name.to_string());
            dbg!(&self.resolved);
        }
    }
    pub fn resolve(&mut self, _ip: IpAddr) -> Result<String> {
        unimplemented!()
    }
}
