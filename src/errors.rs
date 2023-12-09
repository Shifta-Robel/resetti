use std::{io,fmt};

#[derive(Debug)]
pub enum ConfigError{
    NoConfigFound,
    FailedToReadConfig,
    FailedToParseConfig,
    MultipleFiltersFound,
    ExpectedAList,
    InvalidRegex,
    InvalidValueForKill,
    FailedToParseAsIpAddr,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let data: &str = match self{
            Self::NoConfigFound => {"Failed to find config file"},
            Self::FailedToReadConfig => {"Failed to read config file"}
            Self::FailedToParseConfig => {"Failed to parse config"},
            Self::MultipleFiltersFound => {"Expected only one source or destination filter, inside a filter at a time"},
            Self::InvalidRegex => {"Invalid Regex value found"},
            Self::InvalidValueForKill => {"Kill can only be 'true' or 'false'"},
            Self::ExpectedAList => {""},
            Self::FailedToParseAsIpAddr => {"Failed to parse value as an IP address"},
        };
        write!(f, "{:?}", data)
    }
}

impl From<io::Error> for ConfigError {
    fn from(_value: io::Error) -> Self {
        ConfigError::FailedToReadConfig
    }
}

impl std::error::Error for ConfigError {}
