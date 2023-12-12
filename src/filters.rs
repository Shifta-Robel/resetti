use std::net::IpAddr;
use regex::Regex;
use crate::domains::Resolved;

#[derive(Debug,Clone)]
pub struct Filter {
    pub src: HostFilter,
    pub dst: HostFilter,
    pub kill: bool,
}

#[derive(Debug,Clone)]
pub enum HostFilter {
    Regex(Regex),
    List(Vec<IpAddr>),
    Exclude(Vec<IpAddr>),
    WildCard,
}

pub struct Blacklist {
    list: Vec<Filter>
}

impl Blacklist {
    pub fn build(list: &Vec<Filter>) -> Self {
        Self {list: list.to_vec()}
    }
    pub fn should_block(&self, src: &IpAddr, dst: &IpAddr, rd: &Resolved) -> bool {
        self.list.iter().any(|filter| {
            
            // println!("checking {src} in {:?}, and {dst} in {:?} evaluated {b}",&filter.src,&filter.dst);
            self.in_filter(&filter.src, rd, *src) && self.in_filter(&filter.dst, rd, *dst)
        })
    }
    fn in_filter(&self, filter: &HostFilter, rd: &Resolved, ip_addr: IpAddr) -> bool {
        match filter {
            HostFilter::WildCard => true,
            HostFilter::List(l) => l.iter().any(|i| *i == ip_addr),
            HostFilter::Exclude(l) => l.iter().any(|i| *i != ip_addr),
            HostFilter::Regex(rgx) => {
                let domain = rd.get(&ip_addr);
                // todo!("if no domain found resolve it");
                // let domain = domain.unwrap();
                let domain = domain.map_or("", |v| v);
                // rgx.is_match(domain.unwrap()) || // check host name
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
                // println!("\t check {domain} against {rgx}, eval {}",rgx.is_match(domain));
                // println!("\t check {ip} against {rgx}, eval {}",rgx.is_match(&ip));
                rgx.is_match(domain) || rgx.is_match(&ip)
            }
        }
    }
}
