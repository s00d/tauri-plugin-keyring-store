//! High-level keyring access for a fixed service name.
//!
//! Account strings are deterministic hashes so snapshot paths and binary ids stay short and safe for OS limits.
//!
//! ## Example
//!
//! ```rust,no_run
//! use tauri_plugin_keyring_store::KeyringStore;
//! use tauri_plugin_keyring_store::BytesDto;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let store = KeyringStore::new("com.example.app");
//! let client = BytesDto::Text("my-client".into());
//! let account = store.account_store_key("/data/main", &client, "settings.json");
//! store.set_bytes(&account, b"{\"theme\":\"dark\"}")?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use keyring_core::Entry;
use sha2::{Digest, Sha256};

use crate::backend::{ensure_init, map_keyring_err};
use crate::error::{Error, Result};
use crate::models::BytesDto;

fn digest16(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    hex::encode(&out[..8])
}

/// Managed snapshot sessions (Stronghold-compatible “initialized paths”).
#[derive(Default, Clone)]
pub struct SessionRegistry(pub Arc<Mutex<HashSet<String>>>);

impl SessionRegistry {
    /// Marks `path` as initialized for this process.
    pub fn insert(&self, path: String) {
        self.0.lock().expect("session mutex poisoned").insert(path);
    }

    /// Removes a path; returns whether it was present.
    pub fn remove(&self, path: &str) -> bool {
        self.0.lock().expect("session mutex poisoned").remove(path)
    }

    /// Returns whether `path` is currently tracked.
    pub fn contains(&self, path: &str) -> bool {
        self.0
            .lock()
            .expect("session mutex poisoned")
            .contains(path)
    }
}

/// OS-backed credential storage scoped to one service identifier (bundle id / custom).
#[derive(Debug, Clone)]
pub struct KeyringStore {
    service: String,
}

impl KeyringStore {
    /// Creates a store handle; no I/O until the first read/write (backend registers lazily).
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    /// Keyring **service** / namespace string passed to the native backend.
    pub fn service(&self) -> &str {
        &self.service
    }

    fn entry(&self, account: &str) -> Result<Entry> {
        ensure_init().map_err(Error::Init)?;
        Entry::new(&self.service, account).map_err(|e| Error::Keyring(e.to_string()))
    }

    /// Persists a UTF-8 secret (use [`Self::set_bytes`] for arbitrary bytes).
    pub fn set_password(&self, account: &str, password: &str) -> Result<()> {
        let entry = self.entry(account)?;
        entry.set_password(password).map_err(map_keyring_err)
    }

    /// Encodes `value` as Base64 and stores it via [`Self::set_password`].
    pub fn set_bytes(&self, account: &str, value: &[u8]) -> Result<()> {
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, value);
        self.set_password(account, &encoded)
    }

    /// Returns stored UTF-8, or [`None`] if the entry is missing.
    pub fn get_password(&self, account: &str) -> Result<Option<String>> {
        let entry = self.entry(account)?;
        match entry.get_password() {
            Ok(p) => Ok(Some(p)),
            Err(e) => {
                if matches!(&e, keyring_core::error::Error::NoEntry) {
                    Ok(None)
                } else {
                    Err(map_keyring_err(e))
                }
            }
        }
    }

    /// Decodes Base64 from [`Self::get_password`]; returns [`None`] if missing.
    pub fn get_bytes(&self, account: &str) -> Result<Option<Vec<u8>>> {
        match self.get_password(account)? {
            None => Ok(None),
            Some(s) => {
                let raw =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s.trim())
                        .map_err(|e| Error::Encoding(e.to_string()))?;
                Ok(Some(raw))
            }
        }
    }

    /// Deletes the credential if present; missing entries are treated as success.
    pub fn delete(&self, account: &str) -> Result<()> {
        let entry = self.entry(account)?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(e) => {
                if matches!(&e, keyring_core::error::Error::NoEntry) {
                    Ok(())
                } else {
                    Err(map_keyring_err(e))
                }
            }
        }
    }

    /// `true` if a non-empty password exists for `account`.
    pub fn exists_nonempty(&self, account: &str) -> Result<bool> {
        Ok(self
            .get_password(account)?
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false))
    }

    /// Stable account id for an unstructured secret key under a snapshot + client namespace.
    ///
    /// # Example
    ///
    /// ```
    /// use tauri_plugin_keyring_store::{BytesDto, KeyringStore};
    ///
    /// let store = KeyringStore::new("com.example.app");
    /// let client = BytesDto::Text("cli".into());
    /// let account = store.account_raw("/data/main", &client, "token");
    /// assert!(account.starts_with("kp:v1:"));
    /// ```
    pub fn account_raw(&self, snapshot_path: &str, client: &BytesDto, suffix: &str) -> String {
        let sd = digest16(snapshot_path.as_bytes());
        let cd = digest16(client.as_ref());
        let xd = digest16(suffix.as_bytes());
        format!("kp:v1:{sd}:{cd}:x:{xd}")
    }

    /// Account key for a JSON **store record** (`store_key` is a logical filename).
    pub fn account_store_key(
        &self,
        snapshot_path: &str,
        client: &BytesDto,
        store_key: &str,
    ) -> String {
        let sd = digest16(snapshot_path.as_bytes());
        let cd = digest16(client.as_ref());
        let kd = digest16(store_key.as_bytes());
        format!("kp:v1:{sd}:{cd}:st:{kd}")
    }

    /// Account key for binary **vault** payload at `vault` / `record_path`.
    pub fn account_vault_record(
        &self,
        snapshot_path: &str,
        client: &BytesDto,
        vault: &BytesDto,
        record_path: &BytesDto,
    ) -> String {
        let sd = digest16(snapshot_path.as_bytes());
        let cd = digest16(client.as_ref());
        let vd = digest16(vault.as_ref());
        let rd = digest16(record_path.as_ref());
        format!("kp:v1:{sd}:{cd}:v:{vd}:{rd}")
    }
}
