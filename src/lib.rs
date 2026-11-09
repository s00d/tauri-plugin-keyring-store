#![doc(
    html_logo_url = "https://raw.githubusercontent.com/s00d/tauri-plugin-keyring-store/main/assets/docs-logo.png",
    html_favicon_url = "https://raw.githubusercontent.com/s00d/tauri-plugin-keyring-store/main/assets/docs-logo.png"
)]

//! OS keychain / credential-manager storage with a Stronghold-shaped API (sessions, vault
//! locations, optional SLIP10/BIP39 procedures). Guides, IPC and guest-js: <https://s00d.github.io/tauri-plugin-keyring-store/>.
//!
//! ## Rust usage
//!
//! ```rust,no_run
//! use tauri::Manager;
//! use tauri_plugin_keyring_store::KeyringExt;
//!
//! fn example<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
//!   let _svc = app.keyring().store.service();
//! }
//! ```
//!
//! ## Examples (naming helpers)
//!
//! ```rust
//! use tauri_plugin_keyring_store::{join_prefix, split_prefixed};
//!
//! # fn main() -> Result<(), tauri_plugin_keyring_store::Error> {
//! let account = join_prefix("billing", "stripe_sk")?;
//! assert_eq!(split_prefixed(&account)?, ("billing".into(), "stripe_sk".into()));
//! # Ok(())
//! # }
//! ```

mod backend;
mod commands;
mod error;
mod models;
pub mod naming;
mod plugin;
mod store;

mod backup_crypto;

#[cfg(feature = "crypto")]
mod crypto;

pub use error::{Error, Result};
pub use models::*;
pub use naming::{PREFIX_SEPARATOR, join_prefix, split_prefixed};
pub use plugin::KeyringPlugin;
#[cfg(any(target_os = "ios", target_os = "macos"))]
pub use store::WriteAccessibility;
pub use store::{INTERNAL_ACCOUNT_PREFIX, KeyringAvailability, KeyringStore, SessionRegistry};

use tauri::plugin::{Builder as PluginBuilder, TauriPlugin};
use tauri::{Manager, Runtime};

/// Access managed [`KeyringPlugin`] state from [`tauri::App`], [`tauri::AppHandle`], or [`tauri::WebviewWindow`].
///
/// Registered by [`init`] or [`Builder::build`].
pub trait KeyringExt<R: Runtime> {
    /// Returns the shared plugin state (store + session registry).
    fn keyring(&self) -> &KeyringPlugin;
}

impl<R: Runtime, T: Manager<R>> KeyringExt<R> for T {
    fn keyring(&self) -> &KeyringPlugin {
        self.state::<KeyringPlugin>().inner()
    }
}

/// Configure [`KeyringPlugin`] before mounting (service name defaults to the app identifier).
///
/// # Example
///
/// ```rust,no_run
/// use tauri_plugin_keyring_store::Builder;
///
/// fn plugin() -> tauri::plugin::TauriPlugin<tauri::Wry> {
///     Builder::new()
///         .service("com.example.myapp.keyring")
///         .build()
/// }
/// ```
#[derive(Default)]
pub struct Builder {
    service: Option<String>,
    #[cfg(target_os = "ios")]
    ios_write_accessibility: Option<WriteAccessibility>,
}

impl Builder {
    /// Same as [`Default::default`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the keychain/credential-manager **service** string (Stronghold has no direct equivalent).
    pub fn service(mut self, service: impl Into<String>) -> Self {
        self.service = Some(service.into());
        self
    }

    /// iOS Data Protection policy for new credential writes (default: [`WriteAccessibility::AfterFirstUnlock`]).
    #[cfg(target_os = "ios")]
    pub fn ios_write_accessibility(mut self, policy: WriteAccessibility) -> Self {
        self.ios_write_accessibility = Some(policy);
        self
    }

    /// Build the plugin for registration via [`tauri::Builder::plugin`].
    pub fn build<R: Runtime>(self) -> TauriPlugin<R> {
        let service_hint = self.service;
        #[cfg(target_os = "ios")]
        let ios_write_accessibility = self.ios_write_accessibility;
        PluginBuilder::new("keyring-store")
            .setup(move |app, _api| {
                let service = service_hint.unwrap_or_else(|| app.config().identifier.clone());
                #[cfg(target_os = "ios")]
                {
                    let mut store = KeyringStore::new(service);
                    if let Some(policy) = ios_write_accessibility {
                        store = store.with_write_accessibility(policy);
                    }
                    app.manage(KeyringPlugin::from_store(store));
                }
                #[cfg(not(target_os = "ios"))]
                app.manage(KeyringPlugin::new(service));
                Ok(())
            })
            .invoke_handler(tauri::generate_handler![
                commands::get_passwords,
                commands::set_passwords,
                commands::delete_passwords,
                commands::password_exists,
                commands::export_passwords_plain,
                commands::import_passwords_plain,
                commands::export_passwords_encrypted,
                commands::import_passwords_encrypted,
                commands::ping,
                commands::initialize,
                commands::destroy,
                commands::save,
                commands::create_client,
                commands::load_client,
                commands::get_store_record,
                commands::save_store_record,
                commands::remove_store_record,
                commands::save_secret,
                commands::remove_secret,
                commands::execute_procedure,
            ])
            .build()
    }
}

/// Registers the plugin with default options (`service` = bundle identifier).
///
/// Shorthand for `Builder::default().build()`. Use [`Builder`] to set a custom service name.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::default().build()
}

#[cfg(test)]
mod ipc_tests {
    use serde_json::{Value, json};
    use tauri::ipc::{CallbackFn, InvokeBody};
    use tauri::test::{
        INVOKE_KEY, MockRuntime, get_ipc_response, mock_builder, mock_context, noop_assets,
    };
    use tauri::webview::InvokeRequest;
    use tauri::{Manager, WebviewWindow};

    const COMMANDS: &[&str] = &[
        "set_passwords",
        "get_passwords",
        "delete_passwords",
        "password_exists",
        "import_passwords_plain",
        "initialize",
        "destroy",
        "get_store_record",
        "save_store_record",
        "remove_store_record",
    ];

    fn app() -> (tauri::App<MockRuntime>, WebviewWindow<MockRuntime>) {
        crate::backend::use_mock_store_for_tests();
        let mut context = mock_context(noop_assets());
        // The mock context carries no plugin ACL manifests: allow the commands under test the
        // way a capability with `keyring-store:default` would (local origin only).
        for cmd in COMMANDS {
            context.runtime_authority_mut().__allow_command(
                format!("plugin:keyring-store|{cmd}"),
                tauri::utils::acl::ExecutionContext::Local,
            );
        }
        let app = mock_builder()
            .plugin(
                crate::Builder::new()
                    .service("keyring-store.ipc-test")
                    .build(),
            )
            .build(context)
            .expect("build mock app");
        let webview = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .expect("build webview");
        (app, webview)
    }

    fn call(webview: &WebviewWindow<MockRuntime>, cmd: &str, body: Value) -> Result<Value, String> {
        let request = InvokeRequest {
            cmd: format!("plugin:keyring-store|{cmd}"),
            callback: CallbackFn(0),
            error: CallbackFn(1),
            // The app's own (local) origin; tauri rejects calls from other origins.
            url: if cfg!(windows) {
                "http://tauri.localhost"
            } else {
                "tauri://localhost"
            }
            .parse()
            .expect("valid invoke URL"),
            body: InvokeBody::Json(body),
            headers: Default::default(),
            invoke_key: INVOKE_KEY.to_string(),
        };
        get_ipc_response(webview, request)
            .map(|r| r.deserialize::<Value>().expect("json response"))
            .map_err(|e| e.to_string())
    }

    #[test]
    fn password_commands_roundtrip_and_guard_internal_accounts() {
        let (_app, w) = app();
        call(
            &w,
            "set_passwords",
            json!({"entries": [{"account": "ipc.a", "secret": "s1"}]}),
        )
        .unwrap();
        let got = call(
            &w,
            "get_passwords",
            json!({"accounts": ["ipc.a", "ipc.missing"]}),
        )
        .unwrap();
        assert_eq!(got, json!(["s1", null]));

        // Vault key material lives under `kp:` accounts: the password API must not reach it.
        // In any letter case: Windows credential names are case-insensitive.
        for acc in ["kp:v1:x", "KP:v1:x", "Kp:v1:x", " kP:x"] {
            let err = call(&w, "get_passwords", json!({"accounts": [acc]})).unwrap_err();
            assert!(err.contains("reserved"), "{acc}: {err}");
            let set = json!({"entries": [{"account": acc, "secret": "x"}]});
            assert!(call(&w, "set_passwords", set).is_err(), "{acc}");
        }

        // Import validates every row before writing any of them.
        let backup = json!({"backup": {"formatVersion": 1, "entries": [
            {"account": "ipc.b", "secret": "s2"},
            {"account": "kp:evil", "secret": "x"}
        ]}});
        assert!(call(&w, "import_passwords_plain", backup).is_err());
        let got = call(&w, "get_passwords", json!({"accounts": ["ipc.b"]})).unwrap();
        assert_eq!(got, json!([null]));

        call(&w, "delete_passwords", json!({"accounts": ["ipc.a"]})).unwrap();
        assert_eq!(
            call(&w, "password_exists", json!({"account": "ipc.a"})).unwrap(),
            json!(false)
        );
    }

    #[test]
    fn store_records_need_a_session_and_accept_byte_keys() {
        let (app, w) = app();
        let rec = |key: Value| json!({"snapshotPath": "/s", "client": "c", "key": key});
        let err = call(&w, "get_store_record", rec(json!("k"))).unwrap_err();
        assert!(err.contains("session not initialized"), "{err}");

        call(
            &w,
            "initialize",
            json!({"snapshotPath": "/s", "password": "pw"}),
        )
        .unwrap();
        let mut save = rec(json!("k"));
        save["value"] = json!([1, 2, 3]);
        assert_eq!(call(&w, "save_store_record", save).unwrap(), Value::Null);
        // A byte key equal to the UTF-8 of a text key addresses the same record.
        assert_eq!(
            call(&w, "get_store_record", rec(json!([107]))).unwrap(),
            json!([1, 2, 3])
        );
        assert_eq!(
            call(&w, "remove_store_record", rec(json!("k"))).unwrap(),
            json!([1, 2, 3])
        );
        assert_eq!(
            call(&w, "get_store_record", rec(json!("k"))).unwrap(),
            Value::Null
        );

        call(&w, "destroy", json!({"snapshotPath": "/s"})).unwrap();
        assert!(!app.state::<crate::KeyringPlugin>().sessions.contains("/s"));
    }
}
