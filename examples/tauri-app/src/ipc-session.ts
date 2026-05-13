/**
 * Stronghold-compatible IPC session lifecycle: a single `KeyringSession.load` + `createClient`,
 * then work through {@link requireStore}. If snapshot or client changes, `unload` and reopen.
 */

import type { KeyringClient } from "tauri-plugin-keyring-store-api";
import { KeyringSession, type KeyringStoreView } from "tauri-plugin-keyring-store-api";

/** Plugin README values for the built-in JS demo button. */
export const EXAMPLE_SNAPSHOT_ID = "demo-snapshot";
export const EXAMPLE_CLIENT_NAME = "demo";

/** Client id for the form-driven flow (UI snapshot + store records). */
export const UI_CLIENT_NAME = "ui-demo";

export type SessionStatus =
  | { state: "closed" }
  | { state: "open"; snapshotId: string; clientName: string };

let activeSession: KeyringSession | null = null;
let activeClient: KeyringClient | null = null;
let boundSnapshotId = "";
let boundClientName = "";

export function getSessionStatus(): SessionStatus {
  if (!activeSession || !activeClient) {
    return { state: "closed" };
  }
  return {
    state: "open",
    snapshotId: boundSnapshotId,
    clientName: boundClientName,
  };
}

/**
 * Opens the logical session and client. Same snapshot + client: no-op.
 * Different snapshot or client name: {@link closeSession} first, then load.
 */
export async function openSession(
  snapshotId: string,
  password: string,
  clientName: string,
): Promise<void> {
  const snap = snapshotId.trim() || "custom-demo";
  const cli = clientName.trim();
  if (!cli) {
    throw new Error("client name must not be empty");
  }

  if (
    activeSession &&
    boundSnapshotId === snap &&
    boundClientName === cli
  ) {
    return;
  }

  await closeSession();

  activeSession = await KeyringSession.load(snap, password);
  activeClient = await activeSession.createClient(cli);
  boundSnapshotId = snap;
  boundClientName = cli;
}

/** Unregisters the session in the plugin (`destroy`) and clears local handles. */
export async function closeSession(): Promise<void> {
  if (activeSession) {
    await activeSession.unload();
  }
  activeSession = null;
  activeClient = null;
  boundSnapshotId = "";
  boundClientName = "";
}

/** Current {@link KeyringStoreView}; only valid after a successful {@link openSession}. */
export function requireStore(): KeyringStoreView {
  if (!activeClient) {
    throw new Error(
      'IPC session is not open — use "Open IPC session" or run a JS store action that opens it.',
    );
  }
  return activeClient.getStore();
}
