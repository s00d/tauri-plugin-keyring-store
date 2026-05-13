/**
 * JavaScript API for `tauri-plugin-keyring` — Stronghold-shaped session/store/vault/procedure calls backed by the OS keyring.
 *
 * @module tauri-plugin-keyring-api
 */

import { invoke } from '@tauri-apps/api/core'

export type ClientPath =
  | string
  | Iterable<number>
  | ArrayLike<number>
  | ArrayBuffer
export type VaultPath =
  | string
  | Iterable<number>
  | ArrayLike<number>
  | ArrayBuffer
export type RecordPath =
  | string
  | Iterable<number>
  | ArrayLike<number>
  | ArrayBuffer
export type StoreKey =
  | string
  | Iterable<number>
  | ArrayLike<number>
  | ArrayBuffer

/** Duration hint (ignored for OS keyring persistence; kept for Stronghold API compatibility). */
export interface Duration {
  secs: number
  nanos: number
}

export class Location {
  type: string
  payload: Record<string, unknown>

  constructor(type: string, payload: Record<string, unknown>) {
    this.type = type
    this.payload = payload
  }

  static generic(vault: VaultPath, record: RecordPath): Location {
    return new Location('Generic', {
      vault,
      record
    })
  }

  static counter(vault: VaultPath, counter: number): Location {
    return new Location('Counter', {
      vault,
      counter
    })
  }
}

class ProcedureExecutor {
  procedureArgs: Record<string, unknown>

  constructor(procedureArgs: Record<string, unknown>) {
    this.procedureArgs = procedureArgs
  }

  async generateSLIP10Seed(
    outputLocation: Location,
    sizeBytes?: number
  ): Promise<Uint8Array> {
    return await invoke<number[]>('plugin:keyring|execute_procedure', {
      ...this.procedureArgs,
      procedure: {
        type: 'SLIP10Generate',
        payload: {
          output: outputLocation,
          sizeBytes
        }
      }
    }).then((n) => Uint8Array.from(n))
  }

  async deriveSLIP10(
    chain: number[],
    source: 'Seed' | 'Key',
    sourceLocation: Location,
    outputLocation: Location
  ): Promise<Uint8Array> {
    return await invoke<number[]>('plugin:keyring|execute_procedure', {
      ...this.procedureArgs,
      procedure: {
        type: 'SLIP10Derive',
        payload: {
          chain,
          input: {
            type: source,
            payload: sourceLocation
          },
          output: outputLocation
        }
      }
    }).then((n) => Uint8Array.from(n))
  }

  async recoverBIP39(
    mnemonic: string,
    outputLocation: Location,
    passphrase?: string
  ): Promise<Uint8Array> {
    return await invoke<number[]>('plugin:keyring|execute_procedure', {
      ...this.procedureArgs,
      procedure: {
        type: 'BIP39Recover',
        payload: {
          mnemonic,
          passphrase,
          output: outputLocation
        }
      }
    }).then((n) => Uint8Array.from(n))
  }

  async generateBIP39(
    outputLocation: Location,
    passphrase?: string
  ): Promise<Uint8Array> {
    return await invoke<number[]>('plugin:keyring|execute_procedure', {
      ...this.procedureArgs,
      procedure: {
        type: 'BIP39Generate',
        payload: {
          output: outputLocation,
          passphrase
        }
      }
    }).then((n) => Uint8Array.from(n))
  }

  async getEd25519PublicKey(privateKeyLocation: Location): Promise<Uint8Array> {
    return await invoke<number[]>('plugin:keyring|execute_procedure', {
      ...this.procedureArgs,
      procedure: {
        type: 'PublicKey',
        payload: {
          type: 'Ed25519',
          privateKey: privateKeyLocation
        }
      }
    }).then((n) => Uint8Array.from(n))
  }

  async signEd25519(
    privateKeyLocation: Location,
    msg: string
  ): Promise<Uint8Array> {
    return await invoke<number[]>('plugin:keyring|execute_procedure', {
      ...this.procedureArgs,
      procedure: {
        type: 'Ed25519Sign',
        payload: {
          privateKey: privateKeyLocation,
          msg
        }
      }
    }).then((n) => Uint8Array.from(n))
  }
}

/** Logical client namespace (maps to hashed keyring account segments). */
export class KeyringClient {
  path: string
  name: ClientPath

  constructor(path: string, name: ClientPath) {
    this.path = path
    this.name = name
  }

  getVault(name: VaultPath): KeyringVault {
    return new KeyringVault(this.path, this.name, name)
  }

  getStore(): KeyringStoreView {
    return new KeyringStoreView(this.path, this.name)
  }
}

/** Binary store backed by keyring entries under this session/client. */
export class KeyringStoreView {
  path: string
  client: ClientPath

  constructor(path: string, client: ClientPath) {
    this.path = path
    this.client = client
  }

  async get(key: StoreKey): Promise<Uint8Array | null> {
    return await invoke<number[] | null>('plugin:keyring|get_store_record', {
      snapshotPath: this.path,
      client: this.client,
      key
    }).then((v) => v && Uint8Array.from(v))
  }

  async insert(
    key: StoreKey,
    value: number[],
    lifetime?: Duration
  ): Promise<void> {
    await invoke('plugin:keyring|save_store_record', {
      snapshotPath: this.path,
      client: this.client,
      key,
      value,
      lifetime
    })
  }

  async remove(key: StoreKey): Promise<Uint8Array | null> {
    return await invoke<number[] | null>(
      'plugin:keyring|remove_store_record',
      {
        snapshotPath: this.path,
        client: this.client,
        key
      }
    ).then((v) => v && Uint8Array.from(v))
  }
}

/** Vault record + SLIP10/BIP39 procedures for one vault name. */
export class KeyringVault extends ProcedureExecutor {
  path: string
  client: ClientPath
  name: VaultPath

  constructor(path: string, client: ClientPath, name: VaultPath) {
    super({
      snapshotPath: path,
      client,
      vault: name
    })
    this.path = path
    this.client = client
    this.name = name
  }

  async insert(recordPath: RecordPath, secret: number[]): Promise<void> {
    await invoke('plugin:keyring|save_secret', {
      snapshotPath: this.path,
      client: this.client,
      vault: this.name,
      recordPath,
      secret
    })
  }

  async remove(location: Location): Promise<void> {
    const recordPath =
      location.type === 'Generic'
        ? (location.payload as { record: RecordPath }).record
        : String((location.payload as { counter: number }).counter)

    await invoke('plugin:keyring|remove_secret', {
      snapshotPath: this.path,
      client: this.client,
      vault: this.name,
      recordPath
    })
  }
}

/**
 * Stronghold-compatible session: register a logical snapshot path (no on-disk file; secrets live in the OS keyring).
 * The password is accepted for API compatibility with Stronghold and is zeroized on the Rust side.
 */
export class KeyringSession {
  path: string

  private constructor(path: string) {
    this.path = path
  }

  static async load(path: string, password: string): Promise<KeyringSession> {
    await invoke('plugin:keyring|initialize', {
      snapshotPath: path,
      password
    })
    return new KeyringSession(path)
  }

  async unload(): Promise<void> {
    await invoke('plugin:keyring|destroy', {
      snapshotPath: this.path
    })
  }

  async loadClient(client: ClientPath): Promise<KeyringClient> {
    await invoke('plugin:keyring|load_client', {
      snapshotPath: this.path,
      client
    })
    return new KeyringClient(this.path, client)
  }

  async createClient(client: ClientPath): Promise<KeyringClient> {
    await invoke('plugin:keyring|create_client', {
      snapshotPath: this.path,
      client
    })
    return new KeyringClient(this.path, client)
  }

  /** No-op on OS keyring (included for Stronghold parity). */
  async save(): Promise<void> {
    await invoke('plugin:keyring|save', {
      snapshotPath: this.path
    })
  }
}

/** Ping helper for diagnostics. */
export async function ping(value?: string): Promise<string | null> {
  return await invoke<{ value?: string }>('plugin:keyring|ping', {
    payload: {
      value
    }
  }).then((r) => (r.value ? r.value : null))
}

/** Same separator as Rust [`PREFIX_SEPARATOR`] (`prefix.name`). */
export const KEYRING_PREFIX_SEPARATOR = '.' as const

/** Bulk / direct account IPC DTO (matches Rust [`PasswordEntryDto`]). */
export interface PasswordEntryDto {
  account: string
  secret: string
}

export interface PasswordBackupEntryDto {
  account: string
  secret?: string | null
}

export interface PasswordBackupPlainDto {
  formatVersion: number
  entries: PasswordBackupEntryDto[]
}

export interface PasswordBackupEncryptedDto {
  formatVersion: number
  salt: string
  nonce: string
  ciphertext: string
}

/** Read many UTF-8 secrets by raw account string (order preserved). */
export async function getPasswords(
  accounts: string[]
): Promise<(string | null)[]> {
  return await invoke<(string | null)[]>('plugin:keyring|get_passwords', {
    accounts
  })
}

/** Write many UTF-8 secrets. */
export async function setPasswords(entries: PasswordEntryDto[]): Promise<void> {
  await invoke('plugin:keyring|set_passwords', { entries })
}

/** Delete many keyring entries by account string. */
export async function deletePasswords(accounts: string[]): Promise<void> {
  await invoke('plugin:keyring|delete_passwords', { accounts })
}

/** True if the account exists with non-empty secret (matches Rust `exists_nonempty`). */
export async function passwordExists(account: string): Promise<boolean> {
  return await invoke<boolean>('plugin:keyring|password_exists', { account })
}

/** Plaintext backup over IPC — **security**: secrets are exposed to the webview process. */
export async function exportPasswordsPlain(
  accounts: string[]
): Promise<PasswordBackupPlainDto> {
  return await invoke<PasswordBackupPlainDto>(
    'plugin:keyring|export_passwords_plain',
    { accounts }
  )
}

export async function importPasswordsPlain(
  backup: PasswordBackupPlainDto
): Promise<void> {
  await invoke('plugin:keyring|import_passwords_plain', { backup })
}

/** Encrypted backup (Argon2id + ChaCha20-Poly1305); always available (independent of Rust `crypto` / iota-crypto). */
export async function exportPasswordsEncrypted(
  accounts: string[],
  passphrase: string
): Promise<PasswordBackupEncryptedDto> {
  return await invoke<PasswordBackupEncryptedDto>(
    'plugin:keyring|export_passwords_encrypted',
    { accounts, passphrase }
  )
}

export async function importPasswordsEncrypted(
  backup: PasswordBackupEncryptedDto,
  passphrase: string
): Promise<void> {
  await invoke('plugin:keyring|import_passwords_encrypted', {
    backup,
    passphrase
  })
}

/** Matches Rust [`join_prefix`]. */
export function joinKeyPrefix(prefix: string, name: string): string {
  const p = prefix.trim()
  const n = name.trim()
  if (!p.length || !n.length) {
    throw new Error('prefix and name must be non-empty after trim')
  }
  if (p.includes('.') || n.includes('.')) {
    throw new Error("prefix and name must not contain '.'")
  }
  return `${p}.${n}`
}

/** Matches Rust [`split_prefixed`] for exactly two segments. */
export function splitKeyPrefix(account: string): [string, string] {
  const a = account.trim()
  const i = a.indexOf('.')
  if (i <= 0 || i === a.length - 1) {
    throw new Error(
      "account must contain exactly one '.' between prefix and name"
    )
  }
  const prefix = a.slice(0, i)
  const name = a.slice(i + 1)
  if (!prefix.length || !name.length) {
    throw new Error('prefix and name segments must be non-empty')
  }
  if (name.includes('.')) {
    throw new Error(
      'only one separator allowed; use nested naming in the app layer'
    )
  }
  return [prefix, name]
}
