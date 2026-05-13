<script setup lang="ts">
import { onMounted, ref } from "vue";
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

const customAccount = ref("example.user.my.token");
const customSecret = ref("");
const customSnapshot = ref("custom-demo");

const sessionStatus = ref<SessionStatus>(getSessionStatus());

function syncSessionStatus(): void {
  sessionStatus.value = getSessionStatus();
}

function appendLog(line: string): void {
  response.value += `[${new Date().toLocaleTimeString()}] ${line}<br>`;
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
  <main class="container">
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

    <div class="log" v-html="response" />
  </main>
</template>

<style scoped>
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
.log {
  margin-top: 1rem;
  font-family: ui-monospace, monospace;
  font-size: 0.85rem;
  white-space: pre-wrap;
  max-width: 42rem;
  margin-left: auto;
  margin-right: auto;
  text-align: left;
}
</style>
