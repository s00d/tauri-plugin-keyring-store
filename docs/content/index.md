---
title: tauri-plugin-keyring-store
description: Secrets, records and wallet keys in the OS credential store for Tauri 2 apps, with a Stronghold-shaped API.
navigation: false
---

```ts [main.ts]
import { KeyringSession, Location, setPasswords, getPasswords } from "tauri-plugin-keyring-store-api";

// Plain accounts: one OS keyring entry each.
await setPasswords([{ account: "app.api_token", secret: "s3cr3t" }]);
const [token] = await getPasswords(["app.api_token"]);

// Stronghold-style session, store and vault.
const session = await KeyringSession.load("/wallet/main", "");
const client = await session.createClient("main");
await client.getStore().insert("prefs", new TextEncoder().encode("{}"));

const vault = client.getVault("PRIMARY");
const master = Location.generic("PRIMARY", "master");
const words = new TextDecoder().decode(await vault.generateBIP39(master)); // show once for backup
const signature = await vault.signEd25519(master, "hello");                // 64 bytes
```
