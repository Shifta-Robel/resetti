use std::net::IpAddr;
use regex::Regex;
use crate::domains::Resolved;

#[derive(Debug,Clone)]
pub struct Filter {
    pub src: HostFilter,
    pub dst: HostFilter,
    pub kill: bool,
}

impl PartialEq for Filter {
    fn eq(&self, other: &Self) -> bool {
        // discriminant(&self.src) == discriminant(&other.src) &&
        // discriminant(&self.dst) == discriminant(&other.dst)
        self.src.get_sort_val() + self.dst.get_sort_val() ==
        other.src.get_sort_val() + other.dst.get_sort_val()
    }
}
impl Eq for Filter {}

impl PartialOrd for Filter {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let src = self.src.get_sort_val() + self.dst.get_sort_val();
        let dst = other.src.get_sort_val() + other.dst.get_sort_val();
        src.partial_cmp(&dst)
    }
}

impl Ord for Filter {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}

#[derive(Debug,Clone)]
pub enum HostFilter {
    WildCard,
    IncludeIPs(Vec<IpAddr>),
    ExcludeIPs(Vec<IpAddr>),
    IncludeMACs(Vec<MacAddr>),
    ExcludeMACs(Vec<MacAddr>),
    Regex(Regex),
}

#[derive(Debug,Clone,Eq)]
pub struct MacAddr([u8;6]);

impl PartialEq for MacAddr{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl From<&str> for MacAddr {
    fn from(value: &str) -> Self {
        unimplemented!()
    }
}

pub enum PacketAction {
    Kill,
    Monitor(Filter),
    Ignore
}

impl HostFilter {
    pub fn get_sort_val(&self) -> u8 {
        match self {
            Self::WildCard => 0,
            Self::IncludeIPs(_) => 1,
            Self::ExcludeIPs(_) => 1,
            Self::IncludeMACs(_) => 2,
            Self::ExcludeMACs(_) => 2,
            Self::Regex(_) => 4
        }
    }
}

pub struct Blacklist {
    list: Vec<Filter>
}

impl Blacklist {
    pub fn build(list: &[Filter]) -> Self {
        Self {list: list.to_vec()}
    }
    pub fn get_packet_action(
        &self,
        tcp_details: (&IpAddr,  u16, [u8;6], &IpAddr,u16, [u8;6]),
        rd: &Resolved
        ) -> PacketAction {
        let (src, src_port, src_mac, dst, dst_port, dst_mac) = tcp_details;
        let matched = self.list.iter().find( 
            |filter|
            self.in_filter(&filter.src, rd, *src, MacAddr(src_mac)) &&
            self.in_filter(&filter.dst, rd, *dst, MacAddr(dst_mac)));
        if let Some(fil) = matched {
            if fil.kill {PacketAction::Kill} else {PacketAction::Monitor(fil.clone())}
        }else {
            PacketAction::Ignore
        }
    }
    // pub fn get_packet_action(&self, src: &IpAddr, dst: &IpAddr, rd: &Resolved) -> PacketAction {
    //     let matched = self.list.iter().find(|filter| self.in_filter(&filter.src, rd, *src) && self.in_filter(&filter.dst, rd, *dst));
    //     if let Some(fil) = matched {
    //         if fil.kill {PacketAction::Kill} else {PacketAction::Monitor(fil.clone())}
    //     }else {
    //         PacketAction::Ignore
    //     }
    // }
    fn in_filter(&self, filter: &HostFilter, rd: &Resolved, ip_addr: IpAddr, mac_addr: MacAddr) -> bool {
        match filter {
            HostFilter::WildCard => true,
            HostFilter::IncludeIPs(l) => l.iter().any(|i| *i == ip_addr),
            HostFilter::ExcludeIPs(l) => l.iter().any(|i| *i != ip_addr),
            HostFilter::IncludeMACs(l) => l.iter().any(|i| *i == mac_addr),
            HostFilter::ExcludeMACs(l) => l.iter().any(|i| *i == mac_addr),
            HostFilter::Regex(rgx) => {
                let mut domain: Option<String> = rd.get(&ip_addr);
                if domain.is_none() {
                    domain = rd.resolve(&ip_addr).ok();
                };
                if let Some(d) = domain {
                    if rgx.is_match(&d) {return true}
                }

                let ip = match ip_addr {
                    IpAddr::V4(adr) => {
                        let segments: Vec<String> =
                            adr.octets().iter().map(|oct| format!("{oct}")).collect();
                        segments.join(".")
                    }
                    IpAddr::V6(adr) => {
                        let segments: Vec<String> = adr
                            .octets()
                            .iter()
                            .map(|oct| format!("{oct:04X}"))
                            .collect();
                        segments.join(":")
                    }
                };
                rgx.is_match(&ip)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(dead_code)]
    use regex::Regex;

    // use crate::configs::Config;
    use super::{Filter, HostFilter};
    use std::net::{IpAddr, Ipv4Addr};
    enum FilterType {
        WildCard,
        Regex,
        IncludeIPs,
        ExcludeIPs
    }
    // static config :Config = Config::build().unwrap();
    fn create_filter(src:FilterType,dst:FilterType,kill:bool) -> Filter {
        let default = |c| {
            let ip_vec =  vec![
                IpAddr::V4("192.235.32.2".parse::<Ipv4Addr>().unwrap()),
                IpAddr::V4("192.255.32.2".parse::<Ipv4Addr>().unwrap()),
                IpAddr::V4("193.255.32.2".parse::<Ipv4Addr>().unwrap()),
            ];
            let rgx = Regex::new("(httpbin|lobste)").unwrap();
            match c {
                FilterType::WildCard => HostFilter::WildCard,
                FilterType::Regex => HostFilter::Regex(rgx),
                FilterType::IncludeIPs => HostFilter::IncludeIPs(ip_vec),
                FilterType::ExcludeIPs => HostFilter::ExcludeIPs(ip_vec),
            }
        };

        Filter { 
            src: default(src),
            dst: default(dst),
            kill
        }
    }
    #[test]
    fn similar_filters_are_equal() {
        use FilterType::*;
        let a = create_filter(WildCard, Regex, true);
        let b = create_filter(Regex, WildCard, true);
        assert!(a == b);
    }
    #[test]
    fn wildcard_beats_list() {
        use FilterType::*;
        let a = create_filter(WildCard, WildCard, true);
        let b = create_filter(WildCard, IncludeIPs, true);
        assert!(a < b);
    }
}
