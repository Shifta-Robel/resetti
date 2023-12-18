use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use anyhow::Result;
use slog::{info, error};
use slog_scope::logger;
use simple_dns::rdata::RData;
use dns_lookup::lookup_addr;

use crate::errors::DomainError;

pub struct Resolved{
    resolved: HashMap<IpAddr, String>
}

impl Resolved {
    pub fn build() -> Self {
        Self{resolved: HashMap::new()}
    }
    pub fn get(&self, ip: &IpAddr) -> Option<String> {
        self.resolved.get(ip).cloned()
    }
    pub fn update_from_dns(&mut self,packet: &[u8]) {
        let answer = simple_dns::Packet::parse(&packet[42..]);
        if let Ok(answer) = answer {
            for i in &answer.answers{
                let ip: Option<IpAddr> = match &i.rdata {
                    RData::A(a) => {Some(IpAddr::V4(Ipv4Addr::from(a.address)))},
                    RData::AAAA(aaaa) => {Some(IpAddr::V6(Ipv6Addr::from(aaaa.address)))},
                    _ => {None}
                };
                if ip.is_none() {continue}
                let ip = ip.unwrap();
                info!(logger(), "Extracted from DNS packet IP:[{}] Domain:[{}]",ip,i.name);
                self.resolved.insert(ip, i.name.to_string());
                dbg!(&self.resolved);
            }
        }else{
            error!(logger(), "Failed to parse DNS packet");
        }
    }
    pub fn resolve(&self, ip: &IpAddr) -> Result<String,DomainError> {
        // println!("resolving {ip:?} to {:?}",lookup_addr(ip));
        lookup_addr(ip).map_err(|_| DomainError::FailedToResolve(*ip))
    }
}
