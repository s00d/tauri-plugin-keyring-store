<script setup lang="ts">
import { nextTick, onMounted, ref } from "vue";
import type { SessionStatus } from "./keyring";
import {
  closeSession,
  deleteUserSecret,
  formatError,
  getSessionStatus,
  getUserSecret,
  jsExampleStore,
  jsOpenSessionFromUi,
  jsSessionRoundtrip,
  pluginPing,
  rustExampleRead,
  rustExampleSession,
  rustExampleWrite,
  setUserSecret,
} from "./keyring";

const response = ref("");
const logEl = ref<HTMLElement | null>(null);

const customAccount = ref("example.user.my.token");
const customSecret = ref("");
const customSnapshot = ref("custom-demo");

const sessionStatus = ref<SessionStatus>(getSessionStatus());

function syncSessionStatus(): void {
  sessionStatus.value = getSessionStatus();
}

function scrollLogToBottom(): void {
  const el = logEl.value;
  if (el) {
    el.scrollTop = el.scrollHeight;
  }
}

function appendLog(line: string): void {
  response.value += `[${new Date().toLocaleTimeString()}] ${line}<br>`;
  void nextTick(scrollLogToBottom);
}

function clearLog(): void {
  response.value = "";
}

async function run(fn: () => Promise<string>): Promise<void> {
  try {
    appendLog(await fn());
  } catch (e: unknown) {
    appendLog(formatError(e));
  }
}

onMounted(() => {
  syncSessionStatus();
});

const onPing = () => run(() => pluginPing());

const onUserWrite = () =>
  run(() => setUserSecret(customAccount.value, customSecret.value));

const onUserRead = () => run(() => getUserSecret(customAccount.value));

const onUserDelete = () => run(() => deleteUserSecret(customAccount.value));

const onRustWrite = () => run(() => rustExampleWrite());
const onRustRead = () => run(() => rustExampleRead());
const onRustSession = () => run(() => rustExampleSession());

const onDemoStoreJs = () =>
  run(async () => {
    const msg = await jsExampleStore();
    syncSessionStatus();
    return msg;
  });

const onUserJsRoundtrip = () =>
  run(async () => {
    const msg = await jsSessionRoundtrip(
      customSnapshot.value,
      customAccount.value,
      customSecret.value,
    );
    syncSessionStatus();
    return msg;
  });

const onSessionOpen = () =>
  run(async () => {
    const msg = await jsOpenSessionFromUi(customSnapshot.value);
    syncSessionStatus();
    return msg;
  });

const onSessionClose = () =>
  run(async () => {
    await closeSession();
    syncSessionStatus();
    return "IPC session closed";
  });
</script>

<template>
  <div class="app-shell">
    <main class="content">
    <h1>tauri-plugin-keyring-store example</h1>

    <section class="panel">
      <h2>Your data (Rust → OS keyring)</h2>
      <p class="hint">
        <strong>Account</strong> is the credential entry name inside your app service (bundle id). Use one stable string per secret you store.
      </p>
      <div class="fields">
        <label class="field">
          <span>Account</span>
          <input v-model="customAccount" type="text" autocomplete="off" spellcheck="false" />
        </label>
        <label class="field">
          <span>Secret (plain text)</span>
          <input v-model="customSecret" type="password" autocomplete="off" />
        </label>
      </div>
      <div class="row">
        <button type="button" @click="onUserWrite">Write</button>
        <button type="button" @click="onUserRead">Read</button>
        <button type="button" class="danger" @click="onUserDelete">Delete</button>
      </div>
    </section>

    <section class="panel">
      <h2>Your data (JS session store — IPC)</h2>
      <p class="hint">
        <strong>KeyringSession</strong> + <strong>client</strong> live in <code>src/ipc-session.ts</code>: one <code>load</code> / <code>createClient</code>, then reuse the same store. Changing snapshot or client restarts the session.
      </p>
      <p v-if="sessionStatus.state === 'open'" class="session-line">
        Session:
        <code>{{ sessionStatus.snapshotId }}</code>
        · client
        <code>{{ sessionStatus.clientName }}</code>
      </p>
      <p v-else class="session-line muted">IPC session closed</p>
      <div class="row">
        <button type="button" @click="onSessionOpen">Open IPC session</button>
        <button type="button" class="danger" @click="onSessionClose">Close session</button>
      </div>
      <label class="field inline">
        <span>Snapshot id</span>
        <input v-model="customSnapshot" type="text" autocomplete="off" spellcheck="false" placeholder="custom-demo" />
      </label>
      <div class="row">
        <button type="button" @click="onUserJsRoundtrip">JS: write secret then read back</button>
      </div>
    </section>

    <section class="panel muted">
      <h2>Built-in demos</h2>
      <p class="hint">
        <strong>Rust</strong> fixed accounts and <strong>JS</strong> canned snapshot — useful to sanity-check the plugin.
      </p>
      <div class="row">
        <button type="button" @click="onPing">Ping plugin</button>
        <button type="button" @click="onRustWrite">Rust: write demo secret</button>
        <button type="button" @click="onRustRead">Rust: read demo secret</button>
        <button type="button" @click="onRustSession">Rust: session-scoped store</button>
        <button type="button" @click="onDemoStoreJs">JS: KeyringSession store</button>
      </div>
    </section>
    </main>

    <aside class="log-dock" aria-label="Activity log">
      <div class="log-toolbar">
        <span class="log-title">Log</span>
        <button type="button" class="log-clear" @click="clearLog">Clear</button>
      </div>
      <div ref="logEl" class="log-body" v-html="response" />
    </aside>
  </div>
</template>

<style scoped>
.app-shell {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

.content {
  flex: 1;
  padding: 1.5rem 1rem 12rem;
  max-width: 48rem;
  margin: 0 auto;
  width: 100%;
  box-sizing: border-box;
}

.log-dock {
  position: fixed;
  left: 0;
  right: 0;
  bottom: 0;
  z-index: 20;
  display: flex;
  flex-direction: column;
  height: 10.5rem;
  border-top: 1px solid color-mix(in srgb, CanvasText 14%, transparent);
  background: color-mix(in srgb, Canvas 92%, CanvasText 8%);
  box-shadow: 0 -4px 24px color-mix(in srgb, CanvasText 8%, transparent);
}

.log-toolbar {
  flex: 0 0 auto;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
  padding: 0.35rem 1rem;
  border-bottom: 1px solid color-mix(in srgb, CanvasText 10%, transparent);
}

.log-title {
  font-size: 0.75rem;
  font-weight: 700;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: color-mix(in srgb, CanvasText 70%, transparent);
}

.log-clear {
  padding: 0.2rem 0.65rem;
  font-size: 0.78rem;
}

.log-body {
  flex: 1;
  overflow-y: auto;
  padding: 0.5rem 1rem 0.65rem;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.8rem;
  line-height: 1.45;
  text-align: left;
  white-space: pre-wrap;
  word-break: break-word;
}

.panel {
  max-width: 42rem;
  margin: 1.25rem auto;
  padding: 1rem 1.25rem;
  text-align: left;
  border-radius: 10px;
  background: color-mix(in srgb, Canvas 96%, CanvasText 4%);
  border: 1px solid color-mix(in srgb, CanvasText 12%, transparent);
}
.panel.muted {
  opacity: 0.95;
}
.panel h2 {
  margin: 0 0 0.5rem;
  font-size: 1.1rem;
  text-align: left;
}
.hint {
  margin: 0 0 0.75rem;
  font-size: 0.88rem;
  line-height: 1.45;
  color: color-mix(in srgb, CanvasText 78%, transparent);
}
.session-line {
  margin: 0 0 0.75rem;
  font-size: 0.85rem;
}
.session-line.muted {
  color: color-mix(in srgb, CanvasText 65%, transparent);
}
.session-line code {
  font-size: 0.82rem;
}
.fields {
  display: flex;
  flex-direction: column;
  gap: 0.65rem;
}
.field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  text-align: left;
}
.field.inline {
  flex-direction: row;
  align-items: center;
  gap: 0.75rem;
  margin-bottom: 0.5rem;
}
.field.inline span {
  flex: 0 0 6.5rem;
}
.field span {
  font-size: 0.82rem;
  font-weight: 600;
}
.field input {
  width: 100%;
  max-width: 100%;
  box-sizing: border-box;
}
.field.inline input {
  flex: 1;
}
.row {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin-top: 0.75rem;
}
button.danger {
  border-color: #c44;
  color: #b33;
}
@media (prefers-color-scheme: dark) {
  button.danger {
    color: #f88;
    border-color: #a44;
  }
}
</style>
