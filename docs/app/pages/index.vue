<script setup lang="ts">
import type { ButtonProps, PageFeatureProps } from '@nuxt/ui'

const { data: page } = await useAsyncData('landing', () => queryCollection('landing').path('/').first())

useSeoMeta({
  title: 'tauri-plugin-keyring-store',
  description: page.value?.description,
  ogTitle: 'tauri-plugin-keyring-store',
  ogDescription: page.value?.description,
})

const heroLinks: ButtonProps[] = [
  { label: 'Get started', to: '/getting-started/introduction', size: 'lg', trailingIcon: 'i-lucide-arrow-right' },
  { label: 'GitHub', to: 'https://github.com/s00d/tauri-plugin-keyring-store', target: '_blank', size: 'lg', color: 'neutral', variant: 'outline', icon: 'i-simple-icons-github' },
]

const features: PageFeatureProps[] = [
  { title: 'OS credential store', description: 'macOS Keychain, Windows Credential Manager, Linux Secret Service, Android and iOS keystores through keyring-core. No snapshot file, no in-memory fallback.', icon: 'i-lucide-key-round', to: '/platforms/overview' },
  { title: 'Stronghold-shaped API', description: 'Sessions, clients, store and vault with the same calls as tauri-plugin-stronghold, so migrating is mostly an import change.', icon: 'i-lucide-arrow-left-right', to: '/guides/stronghold' },
  { title: 'Wallet procedures', description: 'SLIP10, BIP39 and Ed25519 run in Rust; private keys stay in the keyring and never reach the webview.', icon: 'i-lucide-wallet', to: '/guides/vault' },
  { title: 'Password accounts', description: 'Bulk get / set / delete of plain accounts, plus plaintext or Argon2id + ChaCha20-Poly1305 encrypted backups.', icon: 'i-lucide-list-checks', to: '/guides/passwords' },
  { title: 'Rust backend', description: 'app.keyring().store gives KeyringStore to your own commands, with iOS background-read helpers.', icon: 'i-simple-icons-rust', to: '/guides/rust' },
  { title: 'Generated reference', description: 'Every class, function, type, Tauri command and permission, built from the sources on each release.', icon: 'i-lucide-book-open', to: '/reference/javascript-api' },
]

const quickLinks: ButtonProps[] = [
  { label: 'Quick start', to: '/getting-started/quick-start', trailingIcon: 'i-lucide-arrow-right' },
  { label: 'Security notes', to: '/guides/security', color: 'neutral', variant: 'outline' },
]
</script>

<template>
  <div>
    <UPageHero
      title="Secrets in the OS keyring for Tauri 2 apps"
      description="Store passwords, records and wallet keys in the platform credential store from your Tauri frontend or backend, on desktop, Android and iOS."
      :links="heroLinks"
    >
      <template #headline>
        <UButton to="/changelog" label="0.3.1: kp: guard ignores case, backend init is retried" trailing-icon="i-lucide-arrow-right" color="neutral" variant="subtle" size="sm" />
      </template>
    </UPageHero>

    <UPageSection title="What you get" :features="features" />

    <UPageSection
      title="Session, store, vault"
      description="Open a session, write a store record, keep a wallet key in the vault. Every call is one entry in the OS keyring under your app service name."
      orientation="horizontal"
      :links="quickLinks"
    >
      <div class="min-w-0">
        <ContentRenderer v-if="page" :value="page" />
      </div>
    </UPageSection>
  </div>
</template>
