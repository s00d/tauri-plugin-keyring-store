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
