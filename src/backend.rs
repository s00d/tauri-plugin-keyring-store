//! Platform-specific registration of the default [`keyring_core`] store.
//!
//! See the crate README for the matrix of OS backends.

use std::sync::OnceLock;

use keyring_core::error::Error as KeyringError;

/// Cached outcome of one-time backend registration.
static INIT: OnceLock<Result<(), String>> = OnceLock::new();

/// Ensures the OS keyring backend is registered exactly once.
pub(crate) fn ensure_init() -> Result<(), String> {
    let stored = INIT.get_or_init(register_default_store);
    stored.clone()
}

#[cfg(target_os = "macos")]
fn register_default_store() -> Result<(), String> {
    let store = apple_native_keyring_store::keychain::Store::new()
        .map_err(|e| format!("apple keychain init failed: {e}"))?;
    keyring_core::set_default_store(store);
    Ok(())
}

#[cfg(target_os = "ios")]
fn register_default_store() -> Result<(), String> {
    let store = apple_native_keyring_store::protected::Store::new()
        .map_err(|e| format!("apple protected store init failed: {e}"))?;
    keyring_core::set_default_store(store);
    Ok(())
}

#[cfg(target_os = "windows")]
fn register_default_store() -> Result<(), String> {
    let store = windows_native_keyring_store::Store::new()
        .map_err(|e| format!("windows credential store init failed: {e}"))?;
    keyring_core::set_default_store(store);
    Ok(())
}

#[cfg(all(target_os = "linux", not(doc)))]
fn register_default_store() -> Result<(), String> {
    let store = dbus_secret_service_keyring_store::Store::new()
        .map_err(|e| format!("dbus secret service init failed: {e}"))?;
    keyring_core::set_default_store(store);
    Ok(())
}

/// Documentation builds have no system GLib/Secret Service; the D-Bus crate is not linked (see `Cargo.toml`).
#[cfg(all(target_os = "linux", doc))]
fn register_default_store() -> Result<(), String> {
    Err("linux keyring backend is not built for documentation (docs.rs has no host keyring stack)".into())
}

#[cfg(target_os = "android")]
fn register_default_store() -> Result<(), String> {
    let store = android_native_keyring_store::Store::new()
        .map_err(|e| format!("android keystore init failed: {e}"))?;
    keyring_core::set_default_store(store);
    Ok(())
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "windows",
    target_os = "linux",
    target_os = "android",
)))]
fn register_default_store() -> Result<(), String> {
    Err("no keyring backend compiled for this target".to_string())
}

pub(crate) fn map_keyring_err(e: KeyringError) -> crate::Error {
    match e {
        KeyringError::NoEntry => crate::Error::NoEntry,
        other => crate::Error::Keyring(other.to_string()),
    }
}
