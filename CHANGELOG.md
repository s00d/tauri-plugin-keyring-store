# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.2] - 2026-11-09

No behaviour changes.

### Documentation

- Documentation site at https://s00d.github.io/tauri-plugin-keyring-store/ (guides, platforms, security notes, generated API / command / permission reference). The README is now a short overview.
- JSDoc for every `tauri-plugin-keyring-store-api` export (shows up in editor hints) and doc comments for every Tauri command.
- `homepage` in `Cargo.toml` and `package.json` points to the site.

### Fixed

- `split_prefixed` error message: missing `;` in "only one separator allowed; use nested naming in the app layer" (now the same text as `splitKeyPrefix` in JS).

## [0.3.1] - 2026-11-08

No API changes.

### Security

- **`kp:` guard ignores case.** The password commands rejected only lowercase `kp:` accounts. Windows credential names are case-insensitive, so `KP:…` reached session store records and vault keys there. Now any letter case is rejected.

### Fixed

- **Backend init is retried.** A failed keyring backend start (e.g. no D-Bus session yet) was cached for the life of the process. Now only success is cached; after a failure the next call tries again after a 2-second pause.
- **`KeyringVault.remove(location)`** deleted from the vault the `KeyringVault` was opened for and ignored the vault in `location`. It now uses the location's vault.

### Added

- `KeyringStore::with_store(...)`: use any `keyring-core` store (e.g. `linux-keyutils-keyring-store`) for one handle; `init()` is unchanged.

### Documentation

- Linux without a desktop session: a Secret Service unlock prompt can block a call for a very long time.
- The session password is not verified.
- Windows: real limit for store records and vault secrets is about 960 bytes (Base64, then UTF-16 in a 2560-byte blob).
- Counter location `7` and generic record `"7"` are the same record.

## [0.3.0] - 2026-11-08

### Security

- **Vault procedures no longer return private keys to the webview.** `SLIP10Generate` and `BIP39Recover` returned the 65-byte extended private key, `SLIP10Derive` the derived private key. They now return nothing / the chain code, as Stronghold does.
- **Password commands reject `kp:` accounts.** Vault keys and store records live under `kp:v1:…` accounts in the same service, so `getPasswords` could read vault key material directly and `setPasswords` could overwrite it.
- **No mnemonic words in errors.** An invalid BIP39 mnemonic produced an error that named the unknown word (sent to JS and easy to log). Crypto errors now use fixed messages.
- **No secrets in `Debug` output.** `PasswordEntryDto`, `PasswordBackupEntryDto` and `ProcedureDto` redact secrets, mnemonics and passphrases.
- Secrets, passphrases, decrypted backups, derived keys and seed buffers are wiped after use (`zeroize`, also enabled in `argon2` / `chacha20poly1305`).
- `SLIP10Generate` `sizeBytes` must be within 16..=64 (any size was allocated before).

### Fixed

- **`generateBIP39` returned key bytes instead of the mnemonic**, so the generated phrase could never be backed up. It now returns the 24-word mnemonic (UTF-8 bytes) and writes the master key to the output location.
- **Binary ids were broken in guest-js.** `Uint8Array` / `ArrayBuffer` / iterable client, vault, record and store keys were serialized as JSON objects and rejected by Rust; they are now sent as byte arrays. Values accept `Uint8Array` too.
- **Byte store keys** (`StoreKey` allowed them in TS) failed because Rust expected a string; a byte key now addresses the same record as the equal UTF-8 text key.
- **Imports were partial on error.** `import_passwords_plain` / `import_passwords_encrypted` wrote rows until the first invalid one and had no item limit; the whole backup is now validated first (max 256 rows).
- Keyring I/O ran on async worker threads and could stall the runtime while the OS showed a keychain prompt or unlocked a collection; it now runs on blocking threads.
- `save` now requires a loaded session, like Stronghold.

### Changed

- **Breaking:** procedure return values above; `Error` is `#[non_exhaustive]`; `KeyringStore::account_store_key` takes `impl AsRef<[u8]>`.
- Edition 2024, MSRV 1.88. `KeyringStore` errors on entry creation (including iOS write modifiers) go through the same mapping, so a locked store reports `KeychainLocked` there too. `argon2` 0.6, `chacha20poly1305` 0.11 (encrypted backups from 0.1.x still decrypt), `base64` 0.23; removed unused `log`, `rand` and the `generic-array` pin.
- guest-js built with Vite 8 (ESM + CJS), TypeScript 6, Vitest 5; separate `index.d.cts`, nested `exports`, `sideEffects: false`; dist checked with publint, attw and an export smoke test. Rollup and tslib removed.
- Tests: IPC tests through `tauri::test`, procedure tests on the keyring-core mock store, and a live write/read/delete test against the real OS store.
- CI on Linux (gnome-keyring), macOS and Windows plus Android and iOS builds. Windows test binaries embed the Common-Controls v6 manifest.
- Example: tauri 2.12, password API from JS, vault demo, log rendered as text (it used `v-html` with secret values), autocorrect / autocapitalize off.
## [0.2.0] - 2026-05-22

### Added

- **`WriteAccessibility`** (iOS/macOS): configure Data Protection for new writes; default on iOS is **`AfterFirstUnlock`** via `access-policy` modifiers on `set_password` / `set_bytes`.
- **`Builder::ios_write_accessibility`** to set the write policy at plugin init.
- **`Error::KeychainLocked`**: distinct from generic `Keyring(String)` when the protected store is unavailable (device locked, `errSecNotAvailable`, etc.).
- **`KeyringAvailability`** and **`KeyringStore::availability()`** — probe-read without UIKit in the host app.
- **Background helpers**: `get_password_for_background`, `get_bytes_for_background`, `exists_nonempty_for_background` return `None` / `false` when locked instead of surfacing `KeychainLocked`.

### Changed

- iOS writes use `Entry::new_with_modifiers` with `after-first-unlock` by default; reads still use `Entry::new` (same service/account).
- **npm** [`tauri-plugin-keyring-store-api`](https://www.npmjs.com/package/tauri-plugin-keyring-store-api) bumped to **0.2.0** (aligned with the Rust crate; guest-js API unchanged).

### Notes

- Credentials written before 0.2.0 keep their previous accessibility until re-saved (`set_password` / `set_bytes`). No automatic migration command in this release.
- Downstream apps with exhaustive `match` on `Error` must handle `KeychainLocked` (minor breaking within 0.x).

## [0.1.5] - 2026-05-13

### Changed

- **README:** Recommend `pnpm run tauri add keyring-store` (and npm/yarn/cargo equivalents) instead of a bare `cargo add` “automatic” block; clarify **snapshot path** for all OSes; document guest-js API with examples for `ping`, session/client/store/vault, `Location`, naming helpers, and direct account backup helpers.

## [0.1.4] - 2026-05-13

### Fixed

- **docs.rs:** Drop `package.metadata.docs.rs` `rustc-args = ["--cfg", "docsrs"]`. That flag was applied to the whole dependency graph and broke serde / serde_json / derives on nightly (see [serde-rs/serde#2994](https://github.com/serde-rs/serde/issues/2994)). Skip the Linux D-Bus dependency using **`cfg(doc)`** in `Cargo.toml` and `backend.rs` instead of `cfg(docsrs)`, so normal builds still link dbus while `cargo rustdoc` / docs.rs do not.

## [0.1.3] - 2026-05-13

### Fixed

- **docs.rs:** Pin `generic-array` to **0.14.9** so `cargo rustdoc` under nightly `--cfg docsrs` does not compile **0.14.7** (still uses removed `doc_auto_cfg`). Keeps `default-target = "x86_64-apple-darwin"` from 0.1.2.

## [0.1.2] - 2026-05-13

### Fixed

- **docs.rs:** Set `package.metadata.docs.rs` `default-target = "x86_64-apple-darwin"` so documentation builds do not use the default Linux graph (GTK/WebKit → old `winnow`/`toml` crates failing under nightly `--cfg docsrs`). Linux dbus stub + `not(docsrs)` deps remain for developers running `cargo doc` on Linux.

## [0.1.1] - 2026-05-13

### Fixed

- **docs.rs:** Skip linking `dbus-secret-service-keyring-store` when `cfg(docsrs)` so documentation builds on Linux without host GLib/pkg-config (0.1.0 rustdoc build failed for this reason).

## [0.1.0] - 2026-05-13

### Changed

- **Breaking:** Renamed distribution packages to avoid collisions on crates.io/npm: Rust crate **`tauri-plugin-keyring-store`** (import `tauri_plugin_keyring_store`), npm **`tauri-plugin-keyring-store-api`**. Tauri plugin id is **`keyring-store`** — IPC `plugin:keyring-store|<command>`, capability prefix **`keyring-store:`** (e.g. `keyring-store:default`).

### Added

- Initial release: OS keyring backend (`keyring-core` + platform stores).
- Stronghold-shaped IPC and guest-js API (`KeyringSession`, store, vault).
- Optional `crypto` feature: SLIP10 / BIP39 / Ed25519 procedures via `iota-crypto`.
- Encrypted backup (Argon2id + ChaCha20-Poly1305) is always available; it does not depend on the `crypto` feature.
- Rust `KeyringExt` / `KeyringPlugin` for direct store access from backend code.
- Permissions autogeneration and default capability set.
- Direct account IPC: `get_passwords`, `set_passwords`, `delete_passwords`, `password_exists` (max 256 items per bulk call).
- Plaintext backup: `export_passwords_plain` / `import_passwords_plain` (secrets cross IPC in the clear — see README).
- Encrypted backup: `export_passwords_encrypted` / `import_passwords_encrypted`.
- Rust [`naming`](https://docs.rs/tauri-plugin-keyring-store/latest/tauri_plugin_keyring_store/naming/index.html) helpers (`join_prefix`, `split_prefixed`) and guest-js `joinKeyPrefix` / `splitKeyPrefix`.
- Guest-js: `getPasswords`, `setPasswords`, `deletePasswords`, `passwordExists`, `exportPasswordsPlain`, `importPasswordsPlain`, `exportPasswordsEncrypted`, `importPasswordsEncrypted`.

[0.3.2]: https://github.com/s00d/tauri-plugin-keyring-store/releases/tag/v0.3.2
[0.3.1]: https://github.com/s00d/tauri-plugin-keyring-store/releases/tag/v0.3.1
[0.3.0]: https://github.com/s00d/tauri-plugin-keyring-store/releases/tag/v0.3.0
[0.2.0]: https://github.com/s00d/tauri-plugin-keyring-store/releases/tag/v0.2.0
[0.1.5]: https://github.com/s00d/tauri-plugin-keyring-store/releases/tag/v0.1.5
[0.1.4]: https://github.com/s00d/tauri-plugin-keyring-store/releases/tag/v0.1.4
[0.1.3]: https://github.com/s00d/tauri-plugin-keyring-store/releases/tag/v0.1.3
[0.1.2]: https://github.com/s00d/tauri-plugin-keyring-store/releases/tag/v0.1.2
[0.1.1]: https://github.com/s00d/tauri-plugin-keyring-store/releases/tag/v0.1.1
[0.1.0]: https://github.com/s00d/tauri-plugin-keyring-store/releases/tag/v0.1.0
