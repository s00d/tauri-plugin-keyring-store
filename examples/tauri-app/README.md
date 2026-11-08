# Example: tauri-plugin-keyring-store

Demonstrates:

1. **JS password API** — Write / Read / Delete use `setPasswords`, `getPasswords` and `deletePasswords` from [`tauri-plugin-keyring-store-api`](../../guest-js/index.ts).
2. **Rust-first usage** — `demo_write_secret`, `demo_read_secret` and `demo_session_store` in [`src-tauri/src/lib.rs`](src-tauri/src/lib.rs) call [`KeyringExt`](../../src/lib.rs) / [`KeyringStore`](../../src/store.rs) directly, without plugin IPC.
3. **Sessions and store records** — [`KeyringSession`](../../guest-js/index.ts) / client / store, see [`src/ipc-session.ts`](src/ipc-session.ts).
4. **Vault** — "JS: vault BIP39 + sign" generates a mnemonic into the keyring, signs with it and removes the key; only the mnemonic, public key and signature reach JS.

Frontend: **Vue 3** + TypeScript + Vite. Demos live in [`src/keyring.ts`](src/keyring.ts); [`src/App.vue`](src/App.vue) is the UI. The log shows values read back from the keyring as plain text.

## Run

The example uses the plugin's JS package from this repository (`file:../../`), so build it first:

```bash
pnpm install && pnpm build    # repository root: builds dist-js
cd examples/tauri-app
pnpm install
pnpm tauri dev
```

Mobile (after `pnpm tauri android init` / `pnpm tauri ios init`):

```bash
pnpm tauri android dev
pnpm tauri ios dev "iPhone 17"
```

On the iOS simulator use `tauri ios dev`: it signs the app, which the keychain requires. An unsigned `tauri ios build --target aarch64-sim` build fails every keychain call with `A required entitlement is not present`.

## Permissions

[`src-tauri/capabilities/default.json`](src-tauri/capabilities/default.json) grants `keyring-store:default` (every plugin command) to the `main` window. The `demo_*` commands are the app's own commands.
