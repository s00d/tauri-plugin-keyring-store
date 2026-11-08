/**
 * App layer on top of `tauri-plugin-keyring-store-api`, local `invoke` commands, and {@link ./ipc-session}.
 */

import { invoke } from "@tauri-apps/api/core";
import {
  deletePasswords,
  getPasswords,
  Location,
  ping,
  setPasswords,
} from "tauri-plugin-keyring-store-api";

import {
  closeSession,
  EXAMPLE_CLIENT_NAME,
  EXAMPLE_SNAPSHOT_ID,
  openSession,
  requireStore,
  UI_CLIENT_NAME,
} from "./ipc-session";
import { KeyringSession } from "tauri-plugin-keyring-store-api";

export type { SessionStatus } from "./ipc-session";
export {
  closeSession,
  getSessionStatus,
  openSession,
  requireStore,
} from "./ipc-session";

export function formatError(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export async function pluginPing(): Promise<string> {
  const v = await ping("Pong!");
  return v != null ? String(v) : "ok";
}

export async function setUserSecret(
  account: string,
  secret: string,
): Promise<string> {
  await setPasswords([{ account, secret }]);
  return `Write OK for account "${account.trim()}"`;
}

export async function getUserSecret(account: string): Promise<string> {
  const [v] = await getPasswords([account]);
  return `Read [${account.trim()}]: ${JSON.stringify(v)}`;
}

export async function deleteUserSecret(account: string): Promise<string> {
  await deletePasswords([account]);
  return `Delete OK for account "${account.trim()}"`;
}

/** Examples wired in `src-tauri`: fixed Rust-side accounts. */
export async function rustExampleWrite(): Promise<string> {
  await invoke("demo_write_secret");
  return "Rust: demo_write_secret OK";
}

export async function rustExampleRead(): Promise<string> {
  const v = await invoke<string | null>("demo_read_secret");
  return `Rust read: ${JSON.stringify(v)}`;
}

export async function rustExampleSession(): Promise<string> {
  const v = await invoke<string>("demo_session_store");
  return `Rust session store: ${v}`;
}

/**
 * Guest store demo: fixed snapshot/client via the shared session module.
 */
export async function jsExampleStore(): Promise<string> {
  await openSession(EXAMPLE_SNAPSHOT_ID, "", EXAMPLE_CLIENT_NAME);
  const store = requireStore();
  const enc = new TextEncoder();
  await store.insert("hello", Array.from(enc.encode("keyring")));
  const raw = await store.get("hello");
  const text = raw ? new TextDecoder().decode(raw) : "(empty)";
  return `JS store get: ${text}`;
}

/**
 * Write/read using UI fields; same session model, client {@link UI_CLIENT_NAME}.
 */
export async function jsSessionRoundtrip(
  snapshotId: string,
  storeKey: string,
  secret: string,
): Promise<string> {
  const snap = snapshotId.trim() || "custom-demo";
  const key = storeKey.trim();
  if (!key) {
    throw new Error(
      "JS store: set a non-empty account (used as store record key)",
    );
  }
  await openSession(snap, "", UI_CLIENT_NAME);
  const store = requireStore();
  const enc = new TextEncoder();
  await store.insert(key, Array.from(enc.encode(secret)));
  const raw = await store.get(key);
  const text = raw ? new TextDecoder().decode(raw) : "(empty)";
  return `JS session [${snap}] store["${key}"] → ${JSON.stringify(text)}`;
}

/** Explicit session open from form fields (snapshot + UI client id). */
export async function jsOpenSessionFromUi(
  snapshotId: string,
): Promise<string> {
  const snap = snapshotId.trim() || "custom-demo";
  await openSession(snap, "", UI_CLIENT_NAME);
  return `IPC session open: snapshot="${snap}", client="${UI_CLIENT_NAME}"`;
}

/**
 * Vault demo: generate a mnemonic into the keyring, sign with it, then remove the key.
 * Only the mnemonic (for backup), public key and signature come back to JS.
 */
export async function jsVaultDemo(): Promise<string> {
  const session = await KeyringSession.load("vault-demo", "");
  try {
    const client = await session.createClient("vault-demo");
    const vault = client.getVault("keys");
    const master = Location.generic("keys", "master");
    const words = new TextDecoder().decode(await vault.generateBIP39(master));
    const pk = await vault.getEd25519PublicKey(master);
    const sig = await vault.signEd25519(master, "hello");
    await vault.remove(master);
    return `Vault: ${words.split(" ").length}-word mnemonic, pk ${pk.length} B, signature ${sig.length} B, key removed`;
  } finally {
    await session.unload();
  }
}
