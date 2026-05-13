<script setup>
import { ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { ping, KeyringSession } from "tauri-plugin-keyring-api";

const response = ref("");

function updateResponse(returnValue) {
  response.value +=
    `[${new Date().toLocaleTimeString()}] ` +
    (typeof returnValue === "string"
      ? returnValue
      : JSON.stringify(returnValue)) +
    "<br>";
}

function onPing() {
  ping("Pong!")
    .then(updateResponse)
    .catch((e) => updateResponse(String(e)));
}

async function onRustWrite() {
  try {
    await invoke("demo_write_secret");
    updateResponse("Rust: demo_write_secret OK");
  } catch (e) {
    updateResponse(String(e));
  }
}

async function onRustRead() {
  try {
    const v = await invoke("demo_read_secret");
    updateResponse(`Rust read: ${JSON.stringify(v)}`);
  } catch (e) {
    updateResponse(String(e));
  }
}

async function onRustSession() {
  try {
    const v = await invoke("demo_session_store");
    updateResponse(`Rust session store: ${v}`);
  } catch (e) {
    updateResponse(String(e));
  }
}

async function onDemoStoreJs() {
  try {
    const session = await KeyringSession.load("demo-snapshot", "");
    const client = await session.createClient("demo");
    const enc = new TextEncoder();
    await client.getStore().insert("hello", Array.from(enc.encode("keyring")));
    const raw = await client.getStore().get("hello");
    const text = raw ? new TextDecoder().decode(raw) : "(empty)";
    await session.unload();
    updateResponse(`JS store get: ${text}`);
  } catch (e) {
    updateResponse(String(e));
  }
}
</script>

<template>
  <main class="container">
    <h1>tauri-plugin-keyring example</h1>

    <p>
      <strong>Rust</strong> buttons call <code>demo_*</code> commands that use
      <code>app.keyring().store</code> directly.
      <strong>JS store</strong> uses the guest API (requires an initialized session for IPC store commands).
    </p>

    <div class="row">
      <button type="button" @click="onPing">Ping plugin</button>
      <button type="button" @click="onRustWrite">Rust: write demo secret</button>
      <button type="button" @click="onRustRead">Rust: read demo secret</button>
      <button type="button" @click="onRustSession">Rust: session-scoped store</button>
      <button type="button" @click="onDemoStoreJs">JS: KeyringSession store</button>
    </div>

    <div class="log" v-html="response" />
  </main>
</template>

<style scoped>
.row {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin: 1rem 0;
}
.log {
  margin-top: 1rem;
  font-family: ui-monospace, monospace;
  font-size: 0.85rem;
  white-space: pre-wrap;
}
</style>
