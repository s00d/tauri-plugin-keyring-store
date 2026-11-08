//! Tauri IPC handlers; mirror [`crate::store::KeyringStore`] for frontend access.
//!
//! Every keyring call runs on a blocking thread: OS stores may block for a long time (macOS
//! keychain prompt, unlocking a Secret Service collection) and must not stall the async runtime.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tauri::{State, command};
use zeroize::{Zeroize, Zeroizing};

use crate::Result;
use crate::models::*;
use crate::plugin::KeyringPlugin;
use crate::store::{INTERNAL_ACCOUNT_PREFIX, KeyringStore};

/// Max items per bulk / backup list (DoS / IPC payload guard).
const MAX_BULK_ITEMS: usize = 256;

const BACKUP_FORMAT_VERSION: u32 = 1;

/// Runs keyring I/O off the async runtime.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| crate::Error::Keyring(format!("keyring worker failed: {e}")))?
}

pub(crate) fn normalize_account(account: &str) -> Result<String> {
    let account = account.trim();
    if account.is_empty() {
        return Err(crate::Error::Naming("account must not be empty".into()));
    }
    if account.len() > 512 {
        return Err(crate::Error::Naming(
            "account string too long (max 512)".into(),
        ));
    }
    // Case-insensitive: Windows credential names ignore case, so `KP:` would reach `kp:` records.
    let head: String = account
        .chars()
        .take(3)
        .flat_map(char::to_lowercase)
        .collect();
    if head == INTERNAL_ACCOUNT_PREFIX {
        return Err(crate::Error::Naming(format!(
            "accounts starting with '{INTERNAL_ACCOUNT_PREFIX}' are reserved for session records"
        )));
    }
    Ok(account.to_owned())
}

fn normalize_accounts(accounts: &[String]) -> Result<Vec<String>> {
    ensure_bulk_len(accounts.len())?;
    accounts.iter().map(|a| normalize_account(a)).collect()
}

fn ensure_bulk_len(n: usize) -> Result<()> {
    if n > MAX_BULK_ITEMS {
        return Err(crate::Error::Naming(format!(
            "too many items (max {MAX_BULK_ITEMS})"
        )));
    }
    Ok(())
}

/// Validates the whole backup first, so a bad row never leaves a half-applied import.
fn apply_plain_backup(store: &KeyringStore, backup: PasswordBackupPlainDto) -> Result<()> {
    if backup.format_version != BACKUP_FORMAT_VERSION {
        return Err(crate::Error::Encoding(format!(
            "unsupported backup format version {} (expected {BACKUP_FORMAT_VERSION})",
            backup.format_version
        )));
    }
    ensure_bulk_len(backup.entries.len())?;
    let rows = backup
        .entries
        .into_iter()
        .filter_map(|row| {
            let secret = Zeroizing::new(row.secret?);
            Some(normalize_account(&row.account).map(|a| (a, secret)))
        })
        .collect::<Result<Vec<_>>>()?;
    for (account, secret) in rows {
        store.set_password(&account, &secret)?;
    }
    Ok(())
}

fn collect_plain_backup(
    store: &KeyringStore,
    accounts: Vec<String>,
) -> Result<PasswordBackupPlainDto> {
    let mut entries = Vec::with_capacity(accounts.len());
    for account in accounts {
        let secret = store.get_password(&account)?;
        entries.push(PasswordBackupEntryDto { account, secret });
    }
    Ok(PasswordBackupPlainDto {
        format_version: BACKUP_FORMAT_VERSION,
        entries,
    })
}

fn store_of(state: &State<'_, KeyringPlugin>) -> Arc<KeyringStore> {
    state.store.clone()
}

#[command]
pub(crate) async fn get_passwords(
    state: State<'_, KeyringPlugin>,
    accounts: Vec<String>,
) -> Result<Vec<Option<String>>> {
    let accounts = normalize_accounts(&accounts)?;
    let store = store_of(&state);
    blocking(move || accounts.iter().map(|a| store.get_password(a)).collect()).await
}

#[command]
pub(crate) async fn set_passwords(
    state: State<'_, KeyringPlugin>,
    entries: Vec<PasswordEntryDto>,
) -> Result<()> {
    ensure_bulk_len(entries.len())?;
    let rows = entries
        .into_iter()
        .map(|e| Ok((normalize_account(&e.account)?, Zeroizing::new(e.secret))))
        .collect::<Result<Vec<_>>>()?;
    let store = store_of(&state);
    blocking(move || {
        rows.iter()
            .try_for_each(|(account, secret)| store.set_password(account, secret))
    })
    .await
}

#[command]
pub(crate) async fn delete_passwords(
    state: State<'_, KeyringPlugin>,
    accounts: Vec<String>,
) -> Result<()> {
    let accounts = normalize_accounts(&accounts)?;
    let store = store_of(&state);
    blocking(move || accounts.iter().try_for_each(|a| store.delete(a))).await
}

#[command]
pub(crate) async fn password_exists(
    state: State<'_, KeyringPlugin>,
    account: String,
) -> Result<bool> {
    let account = normalize_account(&account)?;
    let store = store_of(&state);
    blocking(move || store.exists_nonempty(&account)).await
}

#[command]
pub(crate) async fn export_passwords_plain(
    state: State<'_, KeyringPlugin>,
    accounts: Vec<String>,
) -> Result<PasswordBackupPlainDto> {
    let accounts = normalize_accounts(&accounts)?;
    let store = store_of(&state);
    blocking(move || collect_plain_backup(&store, accounts)).await
}

#[command]
pub(crate) async fn import_passwords_plain(
    state: State<'_, KeyringPlugin>,
    backup: PasswordBackupPlainDto,
) -> Result<()> {
    let store = store_of(&state);
    blocking(move || apply_plain_backup(&store, backup)).await
}

#[command]
pub(crate) async fn export_passwords_encrypted(
    state: State<'_, KeyringPlugin>,
    accounts: Vec<String>,
    passphrase: String,
) -> Result<PasswordBackupEncryptedDto> {
    let passphrase = Zeroizing::new(passphrase);
    let accounts = normalize_accounts(&accounts)?;
    let store = store_of(&state);
    blocking(move || {
        let plain = collect_plain_backup(&store, accounts)?;
        let json = Zeroizing::new(
            serde_json::to_vec(&plain).map_err(|e| crate::Error::Encoding(e.to_string()))?,
        );
        for mut e in plain.entries {
            e.secret.zeroize();
        }
        crate::backup_crypto::encrypt_plain_bytes(&json, passphrase.as_bytes())
    })
    .await
}

#[command]
pub(crate) async fn import_passwords_encrypted(
    state: State<'_, KeyringPlugin>,
    backup: PasswordBackupEncryptedDto,
    passphrase: String,
) -> Result<()> {
    let passphrase = Zeroizing::new(passphrase);
    let store = store_of(&state);
    blocking(move || {
        let plain = crate::backup_crypto::decrypt_to_plain(&backup, passphrase.as_bytes())?;
        let backup: PasswordBackupPlainDto =
            serde_json::from_slice(&plain).map_err(|e| crate::Error::Encoding(e.to_string()))?;
        apply_plain_backup(&store, backup)
    })
    .await
}

#[command]
pub(crate) async fn ping(payload: PingRequest) -> Result<PingResponse> {
    Ok(PingResponse {
        value: payload.value,
    })
}

/// The password is accepted for Stronghold API parity only and is **not verified** (any
/// password opens any session): secrets are protected by the OS
/// store, so it is wiped immediately and never stored or compared.
#[command]
pub(crate) async fn initialize(
    state: State<'_, KeyringPlugin>,
    snapshot_path: PathBuf,
    password: String,
) -> Result<()> {
    drop(Zeroizing::new(password));
    state
        .sessions
        .insert(snapshot_path.to_string_lossy().into_owned());
    Ok(())
}

#[command]
pub(crate) async fn destroy(state: State<'_, KeyringPlugin>, snapshot_path: PathBuf) -> Result<()> {
    state.sessions.remove(&snapshot_path.to_string_lossy());
    Ok(())
}

#[command]
pub(crate) async fn save(state: State<'_, KeyringPlugin>, snapshot_path: PathBuf) -> Result<()> {
    require_session(&state, &snapshot_path).map(drop)
}

#[command]
pub(crate) async fn create_client(
    state: State<'_, KeyringPlugin>,
    snapshot_path: PathBuf,
    #[allow(unused_variables)] client: BytesDto,
) -> Result<()> {
    require_session(&state, &snapshot_path).map(drop)
}

#[command]
pub(crate) async fn load_client(
    state: State<'_, KeyringPlugin>,
    snapshot_path: PathBuf,
    #[allow(unused_variables)] client: BytesDto,
) -> Result<()> {
    require_session(&state, &snapshot_path).map(drop)
}

#[command]
pub(crate) async fn get_store_record(
    state: State<'_, KeyringPlugin>,
    snapshot_path: PathBuf,
    client: BytesDto,
    key: BytesDto,
) -> Result<Option<Vec<u8>>> {
    let snap = require_session(&state, &snapshot_path)?;
    let store = store_of(&state);
    blocking(move || store.get_bytes(&store.account_store_key(&snap, &client, &key))).await
}

/// `lifetime` is accepted for Stronghold parity and ignored: OS stores have no expiry.
#[command]
pub(crate) async fn save_store_record(
    state: State<'_, KeyringPlugin>,
    snapshot_path: PathBuf,
    client: BytesDto,
    key: BytesDto,
    value: Vec<u8>,
    #[allow(unused_variables)] lifetime: Option<DurationDto>,
) -> Result<Option<Vec<u8>>> {
    let snap = require_session(&state, &snapshot_path)?;
    let value = Zeroizing::new(value);
    let store = store_of(&state);
    blocking(move || {
        let account = store.account_store_key(&snap, &client, &key);
        let prev = store.get_bytes(&account)?;
        store.set_bytes(&account, &value)?;
        Ok(prev)
    })
    .await
}

#[command]
pub(crate) async fn remove_store_record(
    state: State<'_, KeyringPlugin>,
    snapshot_path: PathBuf,
    client: BytesDto,
    key: BytesDto,
) -> Result<Option<Vec<u8>>> {
    let snap = require_session(&state, &snapshot_path)?;
    let store = store_of(&state);
    blocking(move || {
        let account = store.account_store_key(&snap, &client, &key);
        let prev = store.get_bytes(&account)?;
        store.delete(&account)?;
        Ok(prev)
    })
    .await
}

#[command]
pub(crate) async fn save_secret(
    state: State<'_, KeyringPlugin>,
    snapshot_path: PathBuf,
    client: BytesDto,
    vault: BytesDto,
    record_path: BytesDto,
    secret: Vec<u8>,
) -> Result<()> {
    let snap = require_session(&state, &snapshot_path)?;
    let secret = Zeroizing::new(secret);
    let store = store_of(&state);
    blocking(move || {
        let account = store.account_vault_record(&snap, &client, &vault, &record_path);
        store.set_bytes(&account, &secret)
    })
    .await
}

#[command]
pub(crate) async fn remove_secret(
    state: State<'_, KeyringPlugin>,
    snapshot_path: PathBuf,
    client: BytesDto,
    vault: BytesDto,
    record_path: BytesDto,
) -> Result<()> {
    let snap = require_session(&state, &snapshot_path)?;
    let store = store_of(&state);
    blocking(move || {
        store.delete(&store.account_vault_record(&snap, &client, &vault, &record_path))
    })
    .await
}

#[cfg(feature = "crypto")]
#[command]
pub(crate) async fn execute_procedure(
    state: State<'_, KeyringPlugin>,
    snapshot_path: PathBuf,
    client: BytesDto,
    procedure: ProcedureDto,
) -> Result<Vec<u8>> {
    let snap = require_session(&state, &snapshot_path)?;
    let store = store_of(&state);
    blocking(move || crate::crypto::execute_procedure(&store, &snap, &client, procedure)).await
}

#[cfg(not(feature = "crypto"))]
#[command]
pub(crate) async fn execute_procedure(
    #[allow(unused_variables)] procedure: ProcedureDto,
) -> Result<Vec<u8>> {
    Err(crate::Error::Crypto(
        "tauri-plugin-keyring-store was built without the `crypto` feature".into(),
    ))
}

/// Returns the session id for `snapshot` if `initialize` was called for it.
fn require_session(state: &KeyringPlugin, snapshot: &Path) -> Result<String> {
    let s = snapshot.to_string_lossy().into_owned();
    if state.sessions.contains(&s) {
        Ok(s)
    } else {
        Err(crate::Error::SessionNotInitialized(s))
    }
}
