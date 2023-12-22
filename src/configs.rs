use anyhow::Result;
use regex::Regex;
use serde::Deserialize;
use std::fs::{File, OpenOptions};
use std::{net::IpAddr, str::FromStr};
use toml::Value;

use crate::errors::ConfigError;
use crate::filters::{Filter, HostFilter, MacAddr, PacketAction};

const CONFIG_FILE: &str = "./test_config.toml";
const DEFAULT_LOG_LEVEL: &str = "info";

#[derive(Debug, Clone)]
pub enum Interface {
    Lookup,
    Custom(String),
}

#[derive(Debug)]
pub struct LogConfig {
    pub log_level: Option<slog::Level>,
    pub log_file: Option<File>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            log_level: Some(slog::Level::Info),
            log_file: None,
        }
    }
}

#[derive(Debug)]
pub struct Config {
    pub filter: Vec<Filter>,
    pub interface: Interface,
    pub log: LogConfig,
}

impl Config {
    pub fn build() -> Result<Self, ConfigError> {
        let contents =
            std::fs::read_to_string(CONFIG_FILE).map_err(ConfigError::FailedToReadConfig)?;
        let val = contents
            .parse::<Value>()
            .map_err(|e| ConfigError::FailedToParseConfig(e.to_string()))?;
        let table = val.as_table().ok_or_else(|| {
            ConfigError::FailedToParseConfig("Failed to parse config as a table".to_string())
        })?;

        let interface = get_interface(table)?;
        let log = get_log(table)?;

        let vals = table
            .get("filter")
            .ok_or_else(|| ConfigError::NoFiltersFound)?;
        let vals = vals.as_array().ok_or_else(|| {
            ConfigError::FailedToParseConfig("Failed to parse filters as an array".to_string())
        })?;
        let vec: Vec<MidFilter> = vals.iter().try_fold(
            Vec::with_capacity(vals.len()),
            |mut acc, i| -> Result<Vec<_>, ConfigError> {
                acc.push(MidFilter::try_from(i)?);
                Ok(acc)
            },
        )?;
        let mut filter: Vec<Filter> = vec.iter().try_fold(
            Vec::with_capacity(vec.len()),
            |mut acc, i| -> Result<Vec<Filter>, ConfigError> {
                acc.push(i.try_into()?);
                Ok(acc)
            },
        )?;
        filter.sort();

        Ok(Self {
            filter,
            interface,
            log,
        })
    }
}

fn get_interface(table: &toml::map::Map<String, Value>) -> Result<Interface, ConfigError> {
    match table.get("device") {
        Some(value) => {
            if let Some(v) = value.get("interface") {
                match v.as_str() {
                    Some(s) => Ok(Interface::Custom(s.to_string())),
                    None => Err(ConfigError::FailedToParseAsString(value.clone()))?,
                }
            } else {
                Ok(Interface::Lookup)
            }
        }
        None => Ok(Interface::Lookup),
    }
}

fn get_log(table: &toml::map::Map<String, Value>) -> Result<LogConfig, ConfigError> {
    match table.get("log") {
        Some(value) => {
            let filter_level = match value.get("log-level") {
                Some(v) => v
                    .as_str()
                    .ok_or(ConfigError::FailedToParseAsString(v.clone()))?,
                None => DEFAULT_LOG_LEVEL,
            };
            let log_level = slog::Level::from_str(filter_level);
            let log_level = match log_level {
                Ok(s) => Ok(Some(s)),
                Err(_) => {
                    if filter_level == "off" {
                        Ok(None)
                    } else {
                        Err(ConfigError::InvalidLogLevel(filter_level.to_string()))
                    }
                }
            }?;
            let log_file = match value.get("log-file") {
                Some(v) => {
                    let st = v
                        .as_str()
                        .ok_or(ConfigError::FailedToParseAsString(v.clone()))?;
                    Some(
                        OpenOptions::new()
                            .create(true)
                            .write(true)
                            .truncate(true)
                            .open(st)
                            .unwrap(),
                    )
                }
                None => None,
            };
            Ok(LogConfig {
                log_level,
                log_file,
            })
        }
        None => Ok(LogConfig::default()),
    }
}

#[derive(Deserialize, Debug)]
struct MidFilter {
    src: Option<Vec<IpAddr>>,
    dst: Option<Vec<IpAddr>>,
    src_regex: Option<String>,
    dst_regex: Option<String>,
    src_exclude: Option<Vec<IpAddr>>,
    dst_exclude: Option<Vec<IpAddr>>,
    src_mac: Option<Vec<MacAddr>>,
    dst_mac: Option<Vec<MacAddr>>,
    src_mac_exclude: Option<Vec<MacAddr>>,
    dst_mac_exclude: Option<Vec<MacAddr>>,
    mode: Option<PacketAction>,
    // prob: Option<f64>
}

impl TryFrom<&toml::Value> for MidFilter {
    type Error = ConfigError;
    fn try_from(value: &toml::Value) -> std::result::Result<Self, Self::Error> {
        let src = value.get("src").map(ip_vec_from_value).transpose()?;
        let dst = value.get("dst").map(ip_vec_from_value).transpose()?;
        let src_exclude = value
            .get("src_exclude")
            .map(ip_vec_from_value)
            .transpose()?;
        let dst_exclude = value
            .get("dst_exclude")
            .map(ip_vec_from_value)
            .transpose()?;
        let src_mac = value.get("src_mac").map(mac_vec_from_value).transpose()?;
        let dst_mac = value.get("dst_mac").map(mac_vec_from_value).transpose()?;
        let src_mac_exclude = value.get("src_mac_exclude").map(mac_vec_from_value).transpose()?;
        let dst_mac_exclude = value.get("dst_mac_exclude").map(mac_vec_from_value).transpose()?;
        let src_regex = value.get("src_regex").map(string_from_value).transpose()?;
        let dst_regex = value.get("dst_regex").map(string_from_value).transpose()?;
        let mode = value.get("mode").map(string_from_value).transpose()?
            .map(|s| PacketAction::try_from(s.as_str())).transpose()?;
        // let prob = match value.get("prob"){
        //     Some(v) => Some(prob_from_value(v).and_then(op)?),
        //     None => None
        // };
        // option<Result<f32, ConfigError>>
        let _prob = value.get("prob").map(prob_from_value).transpose()?;

        Ok(Self {
            src,
            dst,
            src_regex,
            dst_regex,
            src_exclude,
            dst_exclude,
            src_mac,
            dst_mac,
            src_mac_exclude,
            dst_mac_exclude,
            mode,
            // prob
        })
    }
}

impl TryInto<Filter> for &MidFilter {
    type Error = ConfigError;
    fn try_into(self) -> std::result::Result<Filter, Self::Error> {
        if self.src.is_some() && self.src_regex.is_some()
            || self.src.is_some() && self.src_exclude.is_some()
            || self.src_regex.is_some() && self.src_exclude.is_some()
        {
            return Err(ConfigError::MultipleFiltersFound);
        }
        if self.dst.is_some() && self.dst_regex.is_some()
            || self.dst.is_some() && self.dst_exclude.is_some()
            || self.dst_regex.is_some() && self.dst_exclude.is_some()
        {
            return Err(ConfigError::MultipleFiltersFound);
        }
        let mut fil = Filter {
            src: HostFilter::WildCard,
            dst: HostFilter::WildCard,
            mode: PacketAction::Reset,
        };
        if let Some(l) = &self.src {
            fil.src = HostFilter::IncludeIPs(l.to_vec())
        }
        if let Some(l) = &self.src_regex {
            fil.src = HostFilter::Regex(Regex::new(l).map_err(ConfigError::InvalidRegex)?)
        }
        if let Some(l) = &self.src_exclude {
            fil.src = HostFilter::ExcludeIPs(l.to_vec())
        }
        if let Some(l) = &self.src_mac {
            fil.src = HostFilter::IncludeMACs(l.to_vec())
        }
        if let Some(l) = &self.src_mac_exclude {
            fil.src = HostFilter::ExcludeMACs(l.to_vec())
        }
        if let Some(l) = &self.dst {
            fil.dst = HostFilter::IncludeIPs(l.to_vec())
        }
        if let Some(l) = &self.dst_regex {
            fil.dst = HostFilter::Regex(Regex::new(l).map_err(ConfigError::InvalidRegex)?)
        }
        if let Some(l) = &self.dst_exclude {
            fil.dst = HostFilter::ExcludeIPs(l.to_vec())
        }
        if let Some(l) = &self.dst_mac {
            fil.dst = HostFilter::IncludeMACs(l.to_vec())
        }
        if let Some(l) = &self.dst_mac_exclude {
            fil.dst = HostFilter::ExcludeMACs(l.to_vec())
        }
        if let Some(m) = &self.mode {
            fil.mode = m.clone()
        }
        Ok(fil)
    }
}

fn ip_vec_from_value(item: &Value) -> Result<Vec<IpAddr>, ConfigError> {
    let v = item.as_array().ok_or(ConfigError::ExpectedAList)?;
    let mut vec: Vec<IpAddr> = Vec::with_capacity(v.len());
    for i in v {
        let s = i
            .as_str()
            .ok_or(ConfigError::FailedToParseAsString(i.clone()))?;
        let s = IpAddr::from_str(s)
            .map_err(|e| ConfigError::FailedToParseAsIpAddr(format!("{} : {}", e, s)))?;
        vec.push(s)
    }
    Ok(vec)
}

fn mac_vec_from_value(item: &Value) -> Result<Vec<MacAddr>, ConfigError> {
    let v = item.as_array().ok_or(ConfigError::ExpectedAList)?;
    let mut vec: Vec<MacAddr> = Vec::with_capacity(v.len());
    for i in v {
        let s = i.as_str().ok_or(ConfigError::FailedToParseAsString(i.clone()))?;
        let s = MacAddr::try_from(s)?;
        vec.push(s)
    }
    Ok(vec)
}

fn string_from_value(item: &Value) -> Result<String, ConfigError> {
    item.as_str()
        .map(|v| v.to_string())
        .ok_or(ConfigError::FailedToParseAsString(item.clone()))
}

fn prob_from_value(item: &Value) -> Result<f64, ConfigError> {
    let i = item
        .as_float()
        .ok_or(ConfigError::FailedToParseAsString(item.clone()))?;
    if !(0. ..1.).contains(&i) {
        Err(ConfigError::InvalidProbValue(item.clone()))
    } else {
        Ok(i)
    }
}
