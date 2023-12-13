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
    List(Vec<IpAddr>),
    Exclude(Vec<IpAddr>),
    Regex(Regex),
}

impl HostFilter {
    pub fn get_sort_val(&self) -> u8 {
        match self {
            Self::WildCard => 0,
            Self::List(_) => 1,
            Self::Exclude(_) => 2,
            Self::Regex(_) => 4
        }
    }
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

#[cfg(test)]
mod tests {
    use regex::Regex;

    use crate::configs::Config;
    use super::{Filter, HostFilter};
    use std::net::{IpAddr, Ipv4Addr};
    enum FilterType {
        WildCard,
        Regex,
        List,
        Exclude
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
                FilterType::List => HostFilter::List(ip_vec),
                FilterType::Exclude => HostFilter::Exclude(ip_vec),
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
        let b = create_filter(WildCard, List, true);
        assert!(a < b);
    }
}
