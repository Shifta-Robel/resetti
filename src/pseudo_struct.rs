use regex::Regex;
use std::{net::SocketAddrV4, collections::HashMap, hint::unreachable_unchecked};

struct Filter {
    src: HostFilter,
    dst: HostFilter,
}

enum HostFilter {
    Regex(Regex),
    List(Vec<SocketAddrV4>),
    WildCard
}

struct BlackList {
    list: Vec<Filter>,
    resolved_domains: HashMap<SocketAddrV4, String>,
}

impl BlackList {
    fn should_block(&mut self, src: &SocketAddrV4, dst: &SocketAddrV4) -> bool {
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
}

fn find_domain(dst: &SocketAddrV4, rgx: &Regex, resolved: &mut HashMap<SocketAddrV4, String>) -> bool {
    let domain = resolved.get(dst).unwrap();
    // let rg = Regex::new(rgx).unwrap();
    rgx.is_match(domain)
}
