//! Managed application state for the plugin (`KeyringStore` + open snapshot sessions).
//!
//! Obtain it from any [`tauri::Manager`] via [`crate::KeyringExt::keyring`].

use std::sync::Arc;

use crate::store::{KeyringStore, SessionRegistry};

/// Root plugin state registered with Tauri ([`tauri::Manager::manage`]).
pub struct KeyringPlugin {
    /// Shared OS keyring accessor for the configured service name.
    pub store: Arc<KeyringStore>,
    /// Snapshot paths that have been initialized for this process (Stronghold-compatible session ids).
    pub sessions: SessionRegistry,
}

impl KeyringPlugin {
    /// Builds plugin state; normally done inside [`crate::Builder::build`].
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            store: Arc::new(KeyringStore::new(service)),
            sessions: SessionRegistry::default(),
        }
    }
}
