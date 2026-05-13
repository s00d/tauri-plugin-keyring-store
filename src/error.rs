//! Error types returned by the plugin (IPC-safe).

use serde::{ser::Serializer, Serialize};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("session not initialized: {0}")]
    SessionNotInitialized(String),
    #[error("credential entry not found")]
    NoEntry,
    #[error("plugin initialization failed: {0}")]
    Init(String),
    #[error("keyring error: {0}")]
    Keyring(String),
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("crypto procedure error: {0}")]
    Crypto(String),
}

impl Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_ref())
    }
}
