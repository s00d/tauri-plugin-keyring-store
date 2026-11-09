//! Platform-specific registration of the default [`keyring_core`] store.
//!
//! Platform matrix: <https://s00d.github.io/tauri-plugin-keyring-store/platforms/overview>.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use keyring_core::error::Error as KeyringError;

/// Registration state. Only success is cached; a failure (e.g. no D-Bus session yet) is
/// retried once its pause is over, so the app recovers without a restart.
enum InitState {
    Pending,
    Ready,
    Failed { at: Instant, err: String },
}

/// Pause before a failed registration is tried again.
const RETRY_PAUSE: Duration = Duration::from_secs(2);

struct Init(Mutex<InitState>);

impl Init {
    const fn new() -> Self {
        Self(Mutex::new(InitState::Pending))
    }

    fn ensure(&self, register: impl FnOnce() -> Result<(), String>) -> Result<(), String> {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        match &*state {
            InitState::Ready => return Ok(()),
            InitState::Failed { at, err } if at.elapsed() < RETRY_PAUSE => return Err(err.clone()),
            _ => {}
        }
        let result = register();
        *state = match &result {
            Ok(()) => InitState::Ready,
            Err(err) => InitState::Failed {
                at: Instant::now(),
                err: err.clone(),
            },
        };
        result
    }
}

static INIT: Init = Init::new();

/// Ensures the OS keyring backend is registered (once it succeeds, never again).
pub(crate) fn ensure_init() -> Result<(), String> {
    INIT.ensure(register_default_store)
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
    Err(
        "linux keyring backend is not built for documentation (docs.rs has no host keyring stack)"
            .into(),
    )
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

/// Unit tests run against keyring-core's in-memory mock store instead of the OS keyring.
#[cfg(test)]
pub(crate) fn use_mock_store_for_tests() {
    INIT.ensure(|| {
        keyring_core::set_default_store(keyring_core::mock::Store::new().expect("mock store"));
        Ok(())
    })
    .expect("mock store");
}

fn is_keychain_locked_platform(err: &(dyn std::error::Error + Send + Sync)) -> bool {
    let msg = format!("{err}");
    msg.contains("-25291")
        || msg.contains("-25292")
        || msg.contains("-25308")
        || msg.contains("errSecNotAvailable")
        || msg.contains("errSecReadOnly")
        || msg.contains("interaction not allowed")
}

pub(crate) fn is_keychain_locked_error(e: &KeyringError) -> bool {
    match e {
        KeyringError::NoStorageAccess(_) => true,
        KeyringError::PlatformFailure(inner) => is_keychain_locked_platform(inner.as_ref()),
        _ => false,
    }
}

pub(crate) fn map_keyring_err(e: KeyringError) -> crate::Error {
    match e {
        KeyringError::NoEntry => crate::Error::NoEntry,
        e if is_keychain_locked_error(&e) => crate::Error::KeychainLocked,
        other => crate::Error::Keyring(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyring_core::error::Error as KE;
    use std::io;

    use crate::Error;

    #[test]
    fn no_storage_access_maps_to_keychain_locked() {
        let e = KE::NoStorageAccess(Box::new(io::Error::other("OSStatus -25291")));
        assert!(matches!(map_keyring_err(e), Error::KeychainLocked));
    }

    #[test]
    fn platform_failure_err_sec_not_available() {
        let e = KE::PlatformFailure(Box::new(io::Error::other("errSecNotAvailable (-25291)")));
        assert!(matches!(map_keyring_err(e), Error::KeychainLocked));
    }

    #[test]
    fn platform_failure_interaction_not_allowed() {
        let e = KE::PlatformFailure(Box::new(io::Error::other("interaction not allowed")));
        assert!(matches!(map_keyring_err(e), Error::KeychainLocked));
    }

    #[test]
    fn unrelated_platform_failure_stays_keyring() {
        let e = KE::PlatformFailure(Box::new(io::Error::other(
            "errSecMissingEntitlement (-34018)",
        )));
        assert!(matches!(map_keyring_err(e), Error::Keyring(_)));
    }

    #[test]
    fn init_error_is_retried_then_success_is_cached() {
        let init = Init::new();
        let calls = std::cell::Cell::new(0);
        let register = |ok: bool| {
            calls.set(calls.get() + 1);
            if ok {
                Ok(())
            } else {
                Err("no D-Bus".to_string())
            }
        };
        assert_eq!(init.ensure(|| register(false)), Err("no D-Bus".into()));
        // Inside the pause the error is returned without a new attempt.
        assert!(init.ensure(|| register(true)).is_err());
        assert_eq!(calls.get(), 1);
        // After the pause the next call retries; the success then sticks.
        if let InitState::Failed { at, .. } = &mut *init.0.lock().unwrap() {
            *at -= RETRY_PAUSE;
        }
        assert_eq!(init.ensure(|| register(true)), Ok(()));
        assert_eq!(init.ensure(|| register(false)), Ok(()));
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn no_entry_unchanged() {
        assert!(matches!(map_keyring_err(KE::NoEntry), Error::NoEntry));
    }
}
