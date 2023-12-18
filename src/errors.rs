#![allow(dead_code)]
use std::{io, net::IpAddr};
use thiserror::Error;
use toml::Value;

#[derive(Debug, Error)]
pub enum ConfigError{
    #[error("Failed to find config file")]
    NoConfigFound,
    #[error("Failed to read config file")]
    FailedToReadConfig(#[from] io::Error),
    #[error("Failed to parse config: {}",.0)]
    FailedToParseConfig(String),
    #[error("Expected only one source or destination filter, inside a filter at a time")]
    MultipleFiltersFound,
    #[error("Expected value to be a list")]
    ExpectedAList,
    #[error("Invalid Regex value found")]
    InvalidRegex(#[from] regex::Error),
    #[error("Kill can only be 'true' or 'false'")]
    InvalidValueForKill,
    #[error("Failed to parse value as an IP address [{}]", .0)]
    FailedToParseAsIpAddr(String),
    #[error("Failed to parse value as String: {}",.0)]
    FailedToParseAsString(Value),
    #[error("Invalid log level provided : {}",.0)]
    InvalidLogLevel(String)
}


#[derive(Debug,Error)]
pub enum DomainError{
    #[error("Failed to resolve addr: {0}")]
    FailedToResolve(IpAddr)
}
