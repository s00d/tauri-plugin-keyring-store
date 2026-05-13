# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/s00d/tauri-plugin-keyring/releases/tag/v0.1.0
