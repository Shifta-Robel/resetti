use std::{io,fmt,error};

#[derive(Debug)]
pub enum ConfigError{
    NoConfigFound(String),
    ConfigParseError(String)
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

//
// impl From<ConfigError> for io::Error {
//   fn from(err: ConfigError) -> io::Error {
//     io::Error::new(io::ErrorKind::InvalidData, err.to_string()) 
//   }
// }
