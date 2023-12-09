use std::{net::IpAddr, str::FromStr};
use regex::Regex;
use serde::Deserialize;
use toml::Value;

use crate::errors::ConfigError;

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
    fn to_mid_filter(item: &Value) -> Result<Self, ConfigError> {
        let src = match item.get("src") {
            Some(v) => Some(Self::string_vec_from_value(v)?),
            None => None
        };
        let dst = match item.get("dst") {
            Some(v) => Some(Self::string_vec_from_value(v)?),
            None => None
        };
        let src_exclude = match item.get("src_exclude") {
            Some(v) => Some(Self::string_vec_from_value(v)?),
            None => None
        };
        let dst_exclude = match item.get("dst_exclude") {
            Some(v) => Some(Self::string_vec_from_value(v)?),
            None => None
        };
        let src_regex = match item.get("src_regex") {
           Some(v) => Some(Self::string_from_value(v)?),
           None => None
        };
        let dst_regex = match item.get("dst_regex") {
           Some(v) => Some(Self::string_from_value(v)?),
           None => None
        };
        let kill = match item.get("kill"){
            Some(v) => Some(Self::bool_from_value(v)?),
            None => None
        };

        Ok( Self {
            src,
            dst,
            src_regex,
            dst_regex,
            src_exclude,
            dst_exclude,
            kill
        })
    }

    fn get_filter(&self) -> Filter {
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

    fn string_vec_from_value(item: &Value) -> Result<Vec<String>, ConfigError> {
        let v = item.as_array().ok_or(ConfigError::ConfigParseError("src should be a list".to_string()))?;
        let mut vec: Vec<String> = vec![];
        for i in v {
            let s = i.as_str().ok_or(ConfigError::ConfigParseError("Invalid element in src list".to_string()))?;
            vec.push(s.to_string())
        }
        Ok(vec)
    }
    fn string_from_value(item: &Value) -> Result<String, ConfigError> {
        Ok(item.as_str().ok_or(ConfigError::ConfigParseError("Invalid string for regex".to_string()))?.to_string())
    }
    fn bool_from_value(item: &Value) -> Result<bool, ConfigError> {
        Ok(item.as_bool().ok_or(ConfigError::ConfigParseError("Expected boolean for kill".to_string()))?)
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
    pub fn build() -> Result<Self, ConfigError> {
        let contents = get_contents(CONFIG_FILE)?;
            // .map_err(|a| ConfigError::IOError(a.to_string()))?;
        
        let val = contents.parse::<Value>().unwrap();
        let vals = val.as_table().unwrap().get("filter").unwrap();
        // let mids: Vec<_> = vals.as_array().unwrap().iter().map(|item|  MidFilter::to_mid_filter(item).unwrap()).collect();
        let vals = vals.as_array().ok_or(ConfigError::ConfigParseError("Invalid config".to_string()))?;
        let mut vec: Vec<_> = vec![];
        for i in vals {
            vec.push(MidFilter::to_mid_filter(i)?);
        }
        Ok( Self {
            filter: vec.iter().map(|i| MidFilter::get_filter(i)).collect()
        })
    }
}

// fn get_contents(path: &str) -> Result<String,ConfigError> {
//     let m = String::from("dfd");
//     std::fs::read_to_string(path)
//         .map_err(ConfigError::ConfigParseError(m))
// }
fn get_contents(path: &str) -> Result<String,ConfigError> {
    let m = String::from("dfd");
    let s = std::fs::read_to_string(path);
    if let Err(e) = s {return Err(ConfigError::ConfigParseError(m))}
    else {return Ok(s.unwrap())}
}
