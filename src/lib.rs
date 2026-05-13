#![doc(
    html_logo_url = "https://raw.githubusercontent.com/s00d/tauri-plugin-keyring-store/main/assets/docs-logo.png",
    html_favicon_url = "https://raw.githubusercontent.com/s00d/tauri-plugin-keyring-store/main/assets/docs-logo.png"
)]

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
pub use naming::{join_prefix, split_prefixed, PREFIX_SEPARATOR};
pub use plugin::KeyringPlugin;
pub use store::{KeyringStore, SessionRegistry};

use tauri::plugin::{Builder as PluginBuilder, TauriPlugin};
use tauri::{Manager, Runtime};

/// Access managed [`KeyringPlugin`] state from [`tauri::App`], [`tauri::AppHandle`], or [`tauri::WebviewWindow`].
pub trait KeyringExt<R: Runtime> {
    fn keyring(&self) -> &KeyringPlugin;
}

impl<R: Runtime, T: Manager<R>> KeyringExt<R> for T {
    fn keyring(&self) -> &KeyringPlugin {
        self.state::<KeyringPlugin>().inner()
    }
}

/// Configure [`KeyringPlugin`] before mounting (service name defaults to the app identifier).
#[derive(Default)]
pub struct Builder {
    service: Option<String>,
}

impl Builder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the keychain/credential-manager **service** string (Stronghold has no direct equivalent).
    pub fn service(mut self, service: impl Into<String>) -> Self {
        self.service = Some(service.into());
        self
    }

    /// Build the plugin for registration via [`tauri::Builder::plugin`].
    pub fn build<R: Runtime>(self) -> TauriPlugin<R> {
        let service_hint = self.service;
        PluginBuilder::new("keyring-store")
            .setup(move |app, _api| {
                let service = service_hint.unwrap_or_else(|| app.config().identifier.clone());
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
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::default().build()
}
