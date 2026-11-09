<p align="center">
  <img src="assets/docs-logo.svg" width="128" height="128" alt="tauri-plugin-keyring-store logo" />
</p>

[![npm version](https://img.shields.io/npm/v/tauri-plugin-keyring-store-api/latest?style=for-the-badge)](https://www.npmjs.com/package/tauri-plugin-keyring-store-api)
[![Crates.io](https://img.shields.io/crates/v/tauri-plugin-keyring-store?style=for-the-badge)](https://crates.io/crates/tauri-plugin-keyring-store)
[![Documentation](https://img.shields.io/badge/docs-site-7c3aed?style=for-the-badge)](https://s00d.github.io/tauri-plugin-keyring-store/)
[![docs.rs](https://img.shields.io/badge/docs-docs.rs-blue?style=for-the-badge)](https://docs.rs/tauri-plugin-keyring-store/)
[![GitHub issues](https://img.shields.io/github/issues/s00d/tauri-plugin-keyring-store?style=for-the-badge)](https://github.com/s00d/tauri-plugin-keyring-store/issues)
[![GitHub stars](https://img.shields.io/github/stars/s00d/tauri-plugin-keyring-store?style=for-the-badge)](https://github.com/s00d/tauri-plugin-keyring-store/stargazers)
[![Donate](https://img.shields.io/badge/Donate-Donationalerts-ff4081?style=for-the-badge)](https://www.donationalerts.com/r/s00d88)

# Tauri Plugin Keyring Store

Store secrets and wallet keys in the **OS credential store** (macOS Keychain, Windows Credential Manager, Linux Secret Service, Android Keystore, iOS Data Protection) from your Tauri 2 frontend or backend. The JS API mirrors [`tauri-plugin-stronghold`](https://github.com/tauri-apps/plugins-workspace/tree/v2/plugins/stronghold) (sessions, clients, store, vault, SLIP10 / BIP39 / Ed25519 procedures), but there is **no snapshot file**: every record is an OS keyring entry under your app's service name.

**Documentation: https://s00d.github.io/tauri-plugin-keyring-store/**

- [Installation](https://s00d.github.io/tauri-plugin-keyring-store/getting-started/installation) · [Quick start](https://s00d.github.io/tauri-plugin-keyring-store/getting-started/quick-start)
- Guides: [sessions and store](https://s00d.github.io/tauri-plugin-keyring-store/guides/sessions), [vault and procedures](https://s00d.github.io/tauri-plugin-keyring-store/guides/vault), [password accounts and backups](https://s00d.github.io/tauri-plugin-keyring-store/guides/passwords), [Rust backend](https://s00d.github.io/tauri-plugin-keyring-store/guides/rust), [security notes](https://s00d.github.io/tauri-plugin-keyring-store/guides/security), [permissions](https://s00d.github.io/tauri-plugin-keyring-store/guides/permissions), [coming from Stronghold](https://s00d.github.io/tauri-plugin-keyring-store/guides/stronghold)
- [Platforms](https://s00d.github.io/tauri-plugin-keyring-store/platforms/overview) · [API reference](https://s00d.github.io/tauri-plugin-keyring-store/reference/javascript-api) · [Changelog](https://s00d.github.io/tauri-plugin-keyring-store/changelog)

## Install

```bash
pnpm tauri add keyring-store
```

Or by hand: `cargo add tauri-plugin-keyring-store` in `src-tauri`, `pnpm add tauri-plugin-keyring-store-api`, then register the plugin and allow `keyring-store:default` in a capability:

```rust
tauri::Builder::default()
    .plugin(tauri_plugin_keyring_store::init())
```

Requires Rust 1.88+. Linux needs a running Secret Service (and `libdbus-1-dev` + `pkg-config` to build); iOS needs a signed app.

## Example

```typescript
import { KeyringSession, Location, setPasswords, getPasswords } from 'tauri-plugin-keyring-store-api'

await setPasswords([{ account: 'app.api_token', secret: 's3cr3t' }])
const [token] = await getPasswords(['app.api_token'])

const session = await KeyringSession.load('/wallet/main', '') // logical id, not a file; password is not checked
const client = await session.createClient('main')
await client.getStore().insert('prefs', new TextEncoder().encode('{}'))

const vault = client.getVault('PRIMARY')
const master = Location.generic('PRIMARY', 'master')
const words = new TextDecoder().decode(await vault.generateBIP39(master)) // private key stays in Rust
const signature = await vault.signEd25519(master, 'hello')
```

From Rust: `app.keyring().store.set_password("app.api_token", &token)` (via `tauri_plugin_keyring_store::KeyringExt`).

## Contributing

Issues and pull requests are welcome on [GitHub](https://github.com/s00d/tauri-plugin-keyring-store). Build and test commands: [Development](https://s00d.github.io/tauri-plugin-keyring-store/getting-started/development).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

`SPDX-License-Identifier: MIT OR Apache-2.0`
