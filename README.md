<p align="center">
  <img src="assets/docs-logo.svg" width="128" height="128" alt="tauri-plugin-keyring logo" />
</p>

[![npm version](https://img.shields.io/npm/v/tauri-plugin-keyring-api/latest?style=for-the-badge)](https://www.npmjs.com/package/tauri-plugin-keyring-api)
[![Crates.io](https://img.shields.io/crates/v/tauri-plugin-keyring?style=for-the-badge)](https://crates.io/crates/tauri-plugin-keyring)
[![Documentation](https://img.shields.io/badge/docs-docs.rs-blue?style=for-the-badge)](https://docs.rs/tauri-plugin-keyring/)
[![GitHub issues](https://img.shields.io/github/issues/s00d/tauri-plugin-keyring?style=for-the-badge)](https://github.com/s00d/tauri-plugin-keyring/issues)
[![GitHub stars](https://img.shields.io/github/stars/s00d/tauri-plugin-keyring?style=for-the-badge)](https://github.com/s00d/tauri-plugin-keyring/stargazers)
[![Donate](https://img.shields.io/badge/Donate-Donationalerts-ff4081?style=for-the-badge)](https://www.donationalerts.com/r/s00d88)

# Tauri Plugin Keyring

Store secrets and wallet-style procedures using the **OS credential store** (macOS Keychain, Windows Credential Manager, Linux Secret Service, Android Keystore, iOS Data Protection). The guest API mirrors [`tauri-plugin-stronghold`](https://github.com/tauri-apps/plugins-workspace/tree/v2/plugins/stronghold) sessions, clients, store, vault, and crypto procedures — but **there is no encrypted snapshot file**: everything maps to hashed keyring entries under your app **service** name (defaults to the Tauri bundle identifier).

---

## Table of contents

1. [Features](#features)
2. [Platform support](#platform-support)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Cargo features](#cargo-features)
6. [Permissions](#permissions)
7. [Relationship to Stronghold](#relationship-to-tauri-plugin-stronghold)
8. [Development](#development)
9. [Testing](#testing)
10. [Contributing](#contributing)
11. [Partners](#partners)
12. [License](#license)

---

## Features

- **Cross-platform keyring** via [`keyring-core`](https://crates.io/crates/keyring-core) `1.x` and official backend crates (native stores only — no silent in-memory fallback).
- **Rust-first API**: `app.keyring()` exposes [`KeyringPlugin`] with [`KeyringStore`] for backend code without IPC.
- **Stronghold-shaped JS API**: [`KeyringSession`](guest-js/index.ts), [`KeyringClient`](guest-js/index.ts), [`KeyringStoreView`](guest-js/index.ts), [`KeyringVault`](guest-js/index.ts) + SLIP10 / BIP39 / Ed25519 procedures when the `crypto` feature is enabled.
- **Optional `crypto` feature** (default): SLIP10/BIP39/Ed25519 via [`iota-crypto`](https://crates.io/crates/iota-crypto); secrets stored as Base64 in the OS vault.

---

## Platform support

| Platform | Backend |
|----------|---------|
| macOS | Login Keychain |
| iOS | Protected (Data Protection) Keychain |
| Windows | Credential Manager |
| Linux | Secret Service (DBus; `crypto-rust` — no host OpenSSL required to **build**) |
| Android | Android Keystore + SharedPreferences |

Linux desktops need a Secret Service (e.g. GNOME Keyring / KWallet). Headless CI often has no user session — avoid relying on the live keyring there (see [Testing](#testing)). On Android, transitive deps may pull OpenSSL; your app may need `openssl-sys` with `vendored` for cross-builds (see Subly-style setups).

---

## Installation

### Automatic (recommended)

```bash
pnpm exec tauri add keyring
# or: npm run tauri add keyring / cargo tauri add keyring
```

### Manual — Rust

```bash
cd src-tauri
cargo add tauri-plugin-keyring
```

Disable crypto (storage IPC only):

```toml
tauri-plugin-keyring = { version = "0.1", default-features = false }
```

### Manual — JavaScript

```bash
pnpm add tauri-plugin-keyring-api
```

---

## Usage

### Backend

```rust
fn main() {
  tauri::Builder::default()
    .plugin(tauri_plugin_keyring::init())
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
```

Custom **service** name (defaults to `identifier` in `tauri.conf.json`):

```rust
tauri_plugin_keyring::Builder::new()
  .service("com.mycompany.myapp.credentials")
  .build()
```

### Rust — access the store from commands / plugins

```rust
use tauri::Manager;
use tauri_plugin_keyring::KeyringExt;

#[tauri::command]
fn save_api_token(app: tauri::AppHandle, token: String) -> Result<(), String> {
  app.keyring().store
    .set_password("manual.example.token", &token)
    .map_err(|e| e.to_string())
}
```

Sessions opened from the frontend (`initialize`) are tracked separately; low-level [`KeyringStore`] calls use whatever account string you pass.

### Frontend (Stronghold-like flow)

```typescript
import { KeyringSession, KeyringClient } from 'tauri-plugin-keyring-api'

const session = await KeyringSession.load('/logical/path', 'ignored-password')
const client = await session.createClient('main')
await client.getStore().insert('prefs', Array.from(new TextEncoder().encode('{}')))
await session.unload()
```

`initialize` accepts a password for Stronghold API compatibility; it is **zeroed on the Rust side** and does not unlock a file snapshot.

---

## Direct account API (bulk, exists, naming, backup)

Raw **account** strings are the OS keyring entry names under your app **service** (defaults to the bundle identifier). These commands avoid session hashing — useful for app-controlled keys.

| IPC command | Purpose |
|-------------|---------|
| `get_passwords` | Read many UTF-8 secrets (parallel `Vec`, max **256** accounts per call). |
| `set_passwords` | Write many `{ account, secret }` pairs. |
| `delete_passwords` | Delete many accounts. |
| `password_exists` | `true` if a non-empty secret exists (`exists_nonempty`). |
| `export_passwords_plain` / `import_passwords_plain` | JSON backup blob over IPC. |
| `export_passwords_encrypted` / `import_passwords_encrypted` | Argon2id + ChaCha20-Poly1305 envelope (always compiled; independent of the `crypto` feature). |

**Naming (application convention):** use `prefix.name` with a single dot — helpers [`join_prefix`](https://docs.rs/tauri-plugin-keyring/latest/tauri_plugin_keyring/fn.join_prefix.html) / [`split_prefixed`](https://docs.rs/tauri-plugin-keyring/latest/tauri_plugin_keyring/fn.split_prefixed.html) in Rust, and `joinKeyPrefix` / `splitKeyPrefix` in guest-js. The OS keyring still does **not** support listing by prefix; keep your own index of logical keys if needed.

**Security — plaintext backup:** `export_passwords_plain` / `import_passwords_plain` move secrets **in the clear** across IPC to the webview. Use only in trusted UI flows, or prefer `export_passwords_encrypted` / disk encryption.

Guest-js exports: `getPasswords`, `setPasswords`, `deletePasswords`, `passwordExists`, `exportPasswordsPlain`, `importPasswordsPlain`, `exportPasswordsEncrypted`, `importPasswordsEncrypted`.

---

## Cargo features

| Feature | Default | Description |
|---------|---------|-------------|
| `crypto` | yes | SLIP10 / BIP39 / Ed25519 `execute_procedure` via [`iota-crypto`](https://crates.io/crates/iota-crypto). Encrypted backup (Argon2 + ChaCha) is **always** available without this flag. |

---

## Permissions

Use `keyring:default` or granular `keyring:allow-*` (see [`permissions/default.toml`](permissions/default.toml)). Commands: `plugin:keyring|<command>`.

---

## Relationship to `tauri-plugin-stronghold`

| Stronghold | This plugin |
|------------|-------------|
| Password-derived snapshot | No snapshot file; OS stores secrets |
| `save()` writes snapshot | `save()` is a **no-op** (compat) |
| Procedures in Stronghold VM | In-process crypto; outputs in keyring |

---

## Development

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build --no-default-features

pnpm install
pnpm build
pnpm test
```

Rustdoc logo (after push to `main`): PNG is generated from [`assets/docs-logo.svg`](assets/docs-logo.svg):

```bash
rsvg-convert -w 128 -h 128 assets/docs-logo.svg -o assets/docs-logo.png
```

---

## Testing

- **Rust**: `cargo test` — deterministic account-key tests and serde roundtrips do not need D-Bus. Tests that call the real OS store are `#[ignore]`; run locally where Secret Service / Keychain is available.
- **JavaScript**: `pnpm test` (Vitest) mocks `@tauri-apps/api/core`.

---

## Contributing

Issues and pull requests are welcome on [GitHub](https://github.com/s00d/tauri-plugin-keyring).

---

## Partners

Contributions and sponsorship help maintain this and related plugins. Thank you for your support.

---

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

`SPDX-License-Identifier: MIT OR Apache-2.0`
