use std::fs::{OpenOptions, File};
use std::{net::IpAddr, str::FromStr};
use regex::Regex;
use serde::Deserialize;
use toml::Value;
use anyhow::Result;

use crate::errors::ConfigError;
use crate::filters::{Filter, HostFilter};

const CONFIG_FILE : &str = "./test_config.toml";
const DEFAULT_LOG_LEVEL: &str = "info";

#[derive(Debug)]
pub struct Config{
    pub filter: Vec<Filter>,
    pub interface: Interface,
    pub log: LogConfig,
}

impl Config{
    pub fn build() -> Result<Self, ConfigError> {
        let contents = get_contents(CONFIG_FILE)?;
        let val = contents.parse::<Value>().map_err(|e| ConfigError::FailedToParseConfig(e.to_string()))?;
        let table = val.as_table().ok_or_else(|| ConfigError::FailedToParseConfig("Failed to parse config as a table".to_string()))?;
        let vals = table.get("filter").ok_or_else(|| ConfigError::FailedToParseConfig("No filters found".to_string()))?;
        let vals = vals.as_array().ok_or_else(|| ConfigError::FailedToParseConfig("Failed to parse filters as an array".to_string()))?;

        let interface = match table.get("device") {
            Some(value) => {
                if let Some(v) = value.get("interface"){
                    match v.as_str() {
                        Some(s) => Interface::Custom(s.to_string()),
                        None => Err(ConfigError::FailedToParseAsString(value.clone()))?,
                    }
                }else {
                    Interface::Lookup
                }
            },
            None => Interface::Lookup,
        };

        let log = match table.get("log") {
            Some(value) => {
                let filter_level = match value.get("log-level") {
                    Some(v) => v.as_str().ok_or(ConfigError::FailedToParseAsString(v.clone()))?,
                    None => DEFAULT_LOG_LEVEL
                };
                let log_level = slog::Level::from_str(filter_level);
                let log_level = match log_level {
                    Ok(s) => Ok(Some(s)),
                    Err(_) => {
                        if filter_level == "off" {
                            Ok(None)
                        }else{
                            Err(ConfigError::InvalidLogLevel(filter_level.to_string()))
                        }
                    }
                }?;
                    // .map_err(|_| ConfigError::InvalidLogLevel(String::from(filter_level)));
                let log_file = match value.get("log-file") {
                    Some(v) => {
                        let st = v.as_str().ok_or(ConfigError::FailedToParseAsString(v.clone()))?;
                        Some(
                            OpenOptions::new().create(true).write(true).truncate(true).open(st).unwrap()
                            )
                        // Some(OsString::from(st))
                    },
                    None => None
                };
                LogConfig{
                    log_level,
                    log_file
                }
            },
            None => LogConfig::default()
        };
        // let log = 
        let mut vec: Vec<_> = Vec::with_capacity(vals.len());
        for i in vals { vec.push(MidFilter::to_mid_filter(i)?); }
        let mut filter: Vec<Filter> = Vec::with_capacity(vec.len());
        for i in vec { filter.push(i.get_filter()?); }
        filter.sort();
        Ok(Self {filter, interface,log })
    }
}

#[derive(Debug,Clone)]
pub enum Interface {
    Lookup,
    Custom(String)
}

#[derive(Debug)]
pub struct LogConfig {
    pub log_level: Option<slog::Level>,
    pub log_file: Option<File>
}

impl Default for LogConfig {
    fn default() -> Self {
        Self{
            log_level: Some(slog::Level::Info),
            log_file: None
        }
    }
}


#[derive(Deserialize, Debug)]
struct MidFilter{
    src: Option<Vec<IpAddr>>,
    dst: Option<Vec<IpAddr>>,
    src_regex: Option<String>,
    dst_regex: Option<String>,
    src_exclude: Option<Vec<IpAddr>>,
    dst_exclude: Option<Vec<IpAddr>>,
    kill: Option<bool>,
}

impl MidFilter {
    fn to_mid_filter(item: &Value) -> Result<Self, ConfigError> {
        let src = match item.get("src") {
            Some(v) => Some(Self::ip_vec_from_value(v)?),
            None => None
        };
        let dst = match item.get("dst") {
            Some(v) => Some(Self::ip_vec_from_value(v)?),
            None => None
        };
        let src_exclude = match item.get("src_exclude") {
            Some(v) => Some(Self::ip_vec_from_value(v)?),
            None => None
        };
        let dst_exclude = match item.get("dst_exclude") {
            Some(v) => Some(Self::ip_vec_from_value(v)?),
            None => None
        };
        let src_regex = match item.get("src_regex") {
           Some(v) => Some(Self::string_from_value(v)?.to_string()),
           None => None
        };
        let dst_regex = match item.get("dst_regex") {
           Some(v) => Some(Self::string_from_value(v)?.to_string()),
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

    fn get_filter(&self) -> Result<Filter, ConfigError> {
        if self.src.is_some() && self.src_regex.is_some() ||
        self.src.is_some() && self.src_exclude.is_some() ||
        self.src_regex.is_some() && self.src_exclude.is_some() {
            return Err(ConfigError::MultipleFiltersFound);
        }
        if self.dst.is_some() && self.dst_regex.is_some() ||
        self.dst.is_some() && self.dst_exclude.is_some() ||
        self.dst_regex.is_some() && self.dst_exclude.is_some() {
            return Err(ConfigError::MultipleFiltersFound);
        }
        let mut fil = Filter{
            src: HostFilter::WildCard,
            dst: HostFilter::WildCard,
            kill: true
        };
        if let Some(l) = &self.src {
            fil.src = HostFilter::List(l.to_vec())
        }
        if let Some(l) = &self.src_regex { 
            fil.src = HostFilter::Regex(Regex::new(l).map_err(ConfigError::InvalidRegex)?)
        }
        if let Some(l) = &self.src_exclude {
            fil.src = HostFilter::Exclude(l.to_vec())
        }
        if let Some(l) = &self.dst {
            fil.dst = HostFilter::List(l.to_vec())
        }
        if let Some(l) = &self.dst_regex { 
            fil.dst = HostFilter::Regex(Regex::new(l).map_err(ConfigError::InvalidRegex)?)
        }
        if let Some(l) = &self.dst_exclude {
            fil.dst = HostFilter::Exclude(l.to_vec())
        }
        if let Some(b) = self.kill { if !b {fil.kill = false} }
        Ok(fil)
    }

    fn ip_vec_from_value(item: &Value) -> Result<Vec<IpAddr>, ConfigError> {
        let v= item.as_array().ok_or(ConfigError::ExpectedAList)?;
        let mut vec: Vec<IpAddr> = Vec::with_capacity(v.len());
        for i in v {
            let s = i.as_str().ok_or(ConfigError::FailedToParseAsString(i.clone()))?;
            let s = IpAddr::from_str(s).map_err(|e| ConfigError::FailedToParseAsIpAddr(format!("{} : {}",e ,s )))?;
            vec.push(s)
        }
        Ok(vec)
    }

    fn bool_from_value(item: &Value) -> Result<bool, ConfigError> {
        item.as_bool().ok_or(ConfigError::InvalidValueForKill)
    }

    fn string_from_value(item: &Value) -> Result<&str, ConfigError> {
        item.as_str().ok_or(ConfigError::FailedToParseAsString(item.clone()))
    }
}


fn get_contents(path: &str) -> Result<String, std::io::Error> {
    std::fs::read_to_string(path)
}
