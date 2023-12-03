use regex::Regex;
use std::{net::IpAddr, collections::HashMap};

pub struct Filter {
    src: HostFilter,
    dst: HostFilter,
}

enum HostFilter {
    Regex(Regex),
    List(Vec<IpAddr>),
    WildCard
}

pub struct BlackList {
    list: Vec<Filter>,
    resolved_domains: HashMap<IpAddr, String>,
}

impl BlackList {
    pub fn init() -> Self{unimplemented!()}
    pub fn should_block(&mut self, src: &IpAddr, dst: &IpAddr) -> bool {
        // filter by src
        //  
        let mut matched_srcs = self.list.iter().filter(|i| {
            return match &i.src {
                HostFilter::WildCard => {true},
                HostFilter::List(list) => {
                    list.contains(src)
                },
                HostFilter::Regex(_rgx) => {
                    unreachable!("Can't be a regex");
                }
            }
        } );
        // filter by dst
        //
        let matched = matched_srcs.any(|i| {
            return match &i.dst {
                HostFilter::WildCard => {true},
                HostFilter::List(list) => {
                    list.contains(dst)
                },
                HostFilter::Regex(rgx) => {
                    find_domain(dst, rgx, &mut self.resolved_domains)
                }
            }

        }
        );
        matched
    }
    pub fn append_resolved_domain(&mut self,resolved: (IpAddr, String)) {
        self.resolved_domains.insert(resolved.0, resolved.1);
    }
}

fn find_domain(dst: &IpAddr, rgx: &Regex, resolved: &mut HashMap<IpAddr, String>) -> bool {
    let domain = resolved.get(dst).unwrap();
    // let rg = Regex::new(rgx).unwrap();
    rgx.is_match(domain)
}
