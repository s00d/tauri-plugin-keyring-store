# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-05-13

### Added

- Initial release: OS keyring backend (`keyring-core` + platform stores).
- Stronghold-shaped IPC and guest-js API (`KeyringSession`, store, vault).
- Optional `crypto` feature: SLIP10 / BIP39 / Ed25519 procedures via `iota-crypto`.
- Rust `KeyringExt` / `KeyringPlugin` for direct store access from backend code.
- Permissions autogeneration and default capability set.

[0.1.0]: https://github.com/s00d/tauri-plugin-keyring/releases/tag/v0.1.0
