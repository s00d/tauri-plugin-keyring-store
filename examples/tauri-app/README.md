# Example: tauri-plugin-keyring-store

Demonstrates:

1. **Rust-first usage** — `demo_write_secret`, `demo_read_secret`, and `demo_session_store` in [`src-tauri/src/lib.rs`](src-tauri/src/lib.rs) call [`KeyringExt`](../../src/lib.rs) / [`KeyringStore`](../../src/store.rs) without going through the plugin IPC surface for basic secrets.
2. **Guest API** — “JS: KeyringSession store” uses [`KeyringSession`](../../guest-js/index.ts) / store insert (same logical snapshot id as the Rust session demo where applicable).

Frontend stack: **Vue 3** + **TypeScript** + Vite. IPC session lifecycle (`KeyringSession` / client / store): [`src/ipc-session.ts`](src/ipc-session.ts); commands and demos: [`src/keyring.ts`](src/keyring.ts); [`src/App.vue`](src/App.vue) is the UI only.

## Run

From repository root:

```bash
cd examples/tauri-app
pnpm install
pnpm tauri dev
```

## Permissions

[`src-tauri/capabilities/default.json`](src-tauri/capabilities/default.json) includes `keyring-store:default` for plugin IPC. Application commands are registered on the app — adjust ACL if your setup restricts `invoke` for local commands.
