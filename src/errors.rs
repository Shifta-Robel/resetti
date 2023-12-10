use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError{
    #[error("Failed to find config file")]
    NoConfigFound,
    #[error("Failed to read config file")]
    FailedToReadConfig(#[from] io::Error),
    #[error("Failed to parse config")]
    FailedToParseConfig,
    #[error("Expected only one source or destination filter, inside a filter at a time")]
    MultipleFiltersFound,
    #[error("Expected value to be a list")]
    ExpectedAList,
    #[error("Invalid Regex value found")]
    InvalidRegex,
    #[error("Kill can only be 'true' or 'false'")]
    InvalidValueForKill,
    #[error("Failed to parse value as an IP address")]
    FailedToParseAsIpAddr,
}
