use regex::Regex;
use std::{collections::HashMap, net::IpAddr};
use rayon::prelude::*;

pub struct Filter {
    src: HostFilter,
    dst: HostFilter,
}

enum HostFilter {
    Regex(Regex),
    List(Vec<IpAddr>),
    WildCard,
}

pub struct BlackList {
    list: Vec<Filter>,
    resolved_domains: HashMap<IpAddr, String>,
}

impl BlackList {
    pub fn init() -> Self {
        unimplemented!()
    }
    pub fn should_block_par(&mut self, src: &IpAddr, dst: &IpAddr) -> bool {
        self.list.par_iter().any(|filter|{
            self.in_filter(&filter.src,*src) && self.in_filter(&filter.dst, *dst)
        })
    }
    pub fn should_block(&mut self, src: &IpAddr, dst: &IpAddr) -> bool {
        self.list.iter().any(|filter| {
            self.in_filter(&filter.src, *src) && self.in_filter(&filter.dst, *dst)
        })
    }
    pub fn append_resolved_domain(&mut self, resolved: (IpAddr, String)) {
        self.resolved_domains.insert(resolved.0, resolved.1);
    }
    fn in_filter(&self, filter: &HostFilter, ip_addr: IpAddr) -> bool {
        match filter {
            HostFilter::WildCard => true,
            HostFilter::List(l) => l.iter().any(|i| *i == ip_addr),
            HostFilter::Regex(rgx) => {
                let domain = self.resolved_domains.get(&ip_addr);
                // todo!("if no domain found resolve it");
                let domain = domain.unwrap();
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
                rgx.is_match(domain) || rgx.is_match(&ip)
            }
        }
    }
}

fn find_domain(dst: &IpAddr, rgx: &Regex, resolved: &mut HashMap<IpAddr, String>) -> bool {
    let domain = resolved.get(dst).unwrap();
    // let rg = Regex::new(rgx).unwrap();
    rgx.is_match(domain)
}
