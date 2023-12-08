use std::{net::IpAddr, str::FromStr};
use regex::Regex;
use serde::Deserialize;
use toml::Value;

const CONFIG_FILE : &str = "./test_config.toml";

#[derive(Debug)]
pub struct Filter {
    src: HostFilter,
    dst: HostFilter,
    kill: bool,
}


#[derive(Deserialize, Debug)]
struct MidFilter{
    src: Option<Vec<String>>,
    dst: Option<Vec<String>>,
    src_regex: Option<String>,
    dst_regex: Option<String>,
    src_exclude: Option<Vec<String>>,
    dst_exclude: Option<Vec<String>>,
    kill: Option<bool>,
}

impl MidFilter {
    fn to_mid_filter(item: &Value) -> Self {
        Self {
            src: {
                item.get("src").map(|v| v.as_array().unwrap().iter().map(|i| String::from(i.as_str().unwrap())).collect::<Vec<String>>())
            },
            dst: {
                item.get("dst").map(|v| v.as_array().unwrap().iter().map(|i| String::from(i.as_str().unwrap())).collect::<Vec<String>>())
            },
            src_regex: {
                item.get("src_regex").map(|val| val.as_str().unwrap().to_string())
            },
            dst_regex: {
                item.get("dst_regex").map(|val| val.as_str().unwrap().to_string())
            },
            src_exclude:  { 
                item.get("src_exclude").map( 
                    |v| v.as_array().unwrap().iter().map(|i| String::from(i.as_str().unwrap())).collect::<Vec<String>>())
            },
            dst_exclude:  {
                item.get("dst_exclude").map( 
                    |v| v.as_array().unwrap().iter().map(|i| String::from(i.as_str().unwrap())).collect::<Vec<String>>())
            },
            kill: {
                item.get("kill").map(|b| b.as_bool().unwrap())
            } 
        }
    }
    fn get_filter(&self) -> Filter {
        // error on multiple src
        // if no src wildcard
        // default kill to true
        // if self.src.is_none() && self.src_regex.is_none() && self.src_exclude
        // a && b, a && c, b && c
        if self.src.is_some() && self.src_regex.is_some() ||
        self.src.is_some() && self.src_exclude.is_some() ||
        self.src_regex.is_some() && self.src_exclude.is_some() {
            //error out
        }
        if self.dst.is_some() && self.dst_regex.is_some() ||
        self.dst.is_some() && self.dst_exclude.is_some() ||
        self.dst_regex.is_some() && self.dst_exclude.is_some() {
            //error out
        }

        let mut fil = Filter{
            src: HostFilter::WildCard,
            dst: HostFilter::WildCard,
            kill: true
        };

        if let Some(l) = &self.src {
            fil.src = HostFilter::List( l.iter().map(|ip| IpAddr::from_str(ip).unwrap()).collect::<Vec<IpAddr>>())
        }
        if let Some(l) = &self.src_regex { 
            fil.src = HostFilter::Regex( Regex::new(&l).unwrap())
        }
        if let Some(l) = &self.src_exclude {
            fil.src = HostFilter::Exclude( l.iter().map(|ip| IpAddr::from_str(ip).unwrap()).collect::<Vec<IpAddr>>())
        }


        if let Some(l) = &self.dst {
            fil.dst = HostFilter::List( l.iter().map(|ip| IpAddr::from_str(ip).unwrap()).collect::<Vec<IpAddr>>())
        }
        if let Some(l) = &self.dst_regex { 
            fil.dst = HostFilter::Regex( Regex::new(&l).unwrap())
        }
        if let Some(l) = &self.dst_exclude {
            fil.dst = HostFilter::Exclude( l.iter().map(|ip| IpAddr::from_str(ip).unwrap()).collect::<Vec<IpAddr>>())
        }

        if let Some(b) = self.kill { if !b {fil.kill = false} }
        fil
    }
}

#[derive(Debug)]
pub enum HostFilter {
    Regex(Regex),
    List(Vec<IpAddr>),
    Exclude(Vec<IpAddr>),
    WildCard,
}


pub struct Config{
    pub filter: Vec<Filter>,
}

impl Config{
    pub fn build() -> Self {
        let contents = get_contents(CONFIG_FILE).unwrap();
            // .map_err(|a| ConfigError::IOError(a.to_string()))?;
        
        let val = contents.parse::<Value>().unwrap();
        let vals = val.as_table().unwrap().get("filter").unwrap();
        let mids: Vec<_> = vals.as_array().unwrap().iter().map(|item|  MidFilter::to_mid_filter(item)).collect();
        Self {
            filter: mids.iter().map(|m| m.get_filter()).collect()
        }
    }
}

fn get_contents(path: &str) -> Result<String, std::io::Error> {
    std::fs::read_to_string(path)
}
