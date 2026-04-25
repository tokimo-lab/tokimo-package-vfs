use thiserror::Error;

#[derive(Error, Debug)]
pub enum TokimoVfsError {
    #[error("connection error: {0}")]
    ConnectionError(String),

    #[error("path not found: {0}")]
    NotFound(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("not implemented: {0}")]
    NotImplemented(String),

    #[error("driver not found: {0}")]
    DriverNotFound(String),

    #[error("invalid config: {0}")]
    InvalidConfig(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, TokimoVfsError>;
