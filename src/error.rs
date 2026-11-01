//! The core's error type. `Config` is a problem with the project's configuration or declarations, `Rule` a rule
//! that broke its contract (the engine's output checks); the CLI prints both as `dcp: msg` and exits 2. The others
//! are failures of a command (exit 1); `Value` and `Os` keep apart what was a bad argument and what an OS call
//! refused.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Config(String),
    Rule(String),
    Runtime(String),
    Value(String),
    Os(String),
}

/// `Result<T>` is the core's result; `Result<T, E>` stays the standard one.
pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub fn runtime(m: impl fmt::Display) -> Error {
        Error::Runtime(m.to_string())
    }
    pub fn value(m: impl fmt::Display) -> Error {
        Error::Value(m.to_string())
    }
    pub fn os(m: impl fmt::Display) -> Error {
        Error::Os(m.to_string())
    }
    pub fn config(m: impl fmt::Display) -> Error {
        Error::Config(m.to_string())
    }
    pub fn rule(m: impl fmt::Display) -> Error {
        Error::Rule(m.to_string())
    }
    pub fn message(&self) -> &str {
        match self {
            Error::Config(m) | Error::Rule(m) | Error::Runtime(m) | Error::Value(m) | Error::Os(m) => m,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for Error {}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Error {
        Error::Runtime(e.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::Os(e.to_string())
    }
}

impl From<String> for Error {
    fn from(e: String) -> Error {
        Error::Runtime(e)
    }
}
