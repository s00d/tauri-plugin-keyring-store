//! Example app: demonstrates **Rust-first** keyring access via [`tauri_plugin_keyring::KeyringExt`]
//! plus optional guest API flows from the webview.

use tauri_plugin_keyring::{BytesDto, KeyringExt};

/// Writes a UTF-8 secret directly via [`KeyringStore`] (no IPC session required).
#[tauri::command]
fn demo_write_secret(app: tauri::AppHandle) -> Result<(), String> {
  app
    .keyring()
    .store
    .set_password("example.rust.demo.token", "hello-from-rust")
    .map_err(|e| e.to_string())
}

/// Reads the demo secret written by [`demo_write_secret`].
#[tauri::command]
fn demo_read_secret(app: tauri::AppHandle) -> Result<Option<String>, String> {
  app
    .keyring()
    .store
    .get_password("example.rust.demo.token")
    .map_err(|e| e.to_string())
}

/// Opens a logical Stronghold-style session and writes a namespaced store record (same hashing as IPC store commands).
#[tauri::command]
fn demo_session_store(app: tauri::AppHandle) -> Result<String, String> {
  let kr = app.keyring();
  kr.sessions.insert("demo-snapshot".into());
  let client = BytesDto::Text("rust-demo".into());
  let account = kr
    .store
    .account_store_key("demo-snapshot", &client, "hello-key");
  kr.store
    .set_bytes(&account, b"session-from-rust")
    .map_err(|e| e.to_string())?;
  let raw = kr
    .store
    .get_bytes(&account)
    .map_err(|e| e.to_string())?
    .unwrap_or_default();
  Ok(String::from_utf8_lossy(&raw).into_owned())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  tauri::Builder::default()
    .invoke_handler(tauri::generate_handler![
      demo_write_secret,
      demo_read_secret,
      demo_session_store,
    ])
    .plugin(tauri_plugin_keyring::init())
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
