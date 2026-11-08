//! Write / read / delete against the real OS credential store.
//!
//! Skipped (with a note) when no store is reachable, e.g. headless Linux without a Secret
//! Service. Set `KEYRING_LIVE_REQUIRED=1` (CI does) to turn that skip into a failure.

use tauri_plugin_keyring_store::{Error, KeyringStore};

/// Deletes the entry even when an assertion fails.
struct Cleanup<'a>(&'a KeyringStore, &'a str);

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        let _ = self.0.delete(self.1);
    }
}

#[test]
fn os_keyring_write_read_delete() {
    // Unique service per run: parallel or crashed runs never collide or leave shared state.
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let service = format!(
        "tauri-plugin-keyring-store.test.{}.{nonce}",
        std::process::id()
    );
    let store = KeyringStore::new(service);
    let account = "live.roundtrip";
    let secret = "s3cr\u{e9}t \u{43f}\u{430}\u{440}\u{43e}\u{43b}\u{44c} \u{1f511}";

    match store.set_password(account, secret) {
        Ok(()) => {}
        Err(e @ (Error::Init(_) | Error::NoStorageAccess(_) | Error::Keyring(_)))
            if std::env::var_os("KEYRING_LIVE_REQUIRED").is_none() =>
        {
            eprintln!("skipping: OS keyring unavailable: {e}");
            return;
        }
        Err(e) => panic!("set_password: {e}"),
    }
    let _cleanup = Cleanup(&store, account);

    assert_eq!(
        store.get_password(account).unwrap().as_deref(),
        Some(secret)
    );
    assert!(store.exists_nonempty(account).unwrap());

    store.set_bytes(account, &[0, 159, 255]).unwrap();
    assert_eq!(store.get_bytes(account).unwrap(), Some(vec![0, 159, 255]));

    store.delete(account).unwrap();
    assert_eq!(store.get_password(account).unwrap(), None);
    // Deleting a missing entry is not an error.
    store.delete(account).unwrap();
}
