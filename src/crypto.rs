//! Stronghold-compatible crypto procedures using [`iota-crypto`] primitives.
//!
//! Secrets at SLIP10/BIP39 **output locations** are persisted in the OS keyring as binary blobs
//! (Base64-encoded). Private key material never leaves this module: procedures return only
//! public data (chain code, public key, signature) or the freshly generated mnemonic, exactly as
//! Stronghold does.

use std::borrow::Borrow;

use crypto::keys::bip39::{self, wordlist};
use crypto::keys::slip10::{self, Seed, Segment};
use crypto::signatures::ed25519::SecretKey;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::models::{BytesDto, KeyType, LocationDto, ProcedureDto, Slip10DeriveInputDto};
use crate::store::KeyringStore;

type Slip10 = slip10::Slip10<SecretKey>;

/// SLIP10 seed length bounds (BIP32: 128..=512 bits).
const SEED_LEN: std::ops::RangeInclusive<usize> = 16..=64;

fn account_for_location(
    store: &KeyringStore,
    snapshot_path: &str,
    client: &BytesDto,
    loc: &LocationDto,
) -> String {
    match loc {
        LocationDto::Generic { vault, record } => {
            store.account_vault_record(snapshot_path, client, vault, record)
        }
        LocationDto::Counter { vault, counter } => {
            let record = BytesDto::Text(counter.to_string());
            store.account_vault_record(snapshot_path, client, vault, &record)
        }
    }
}

struct Vault<'a> {
    store: &'a KeyringStore,
    snapshot_path: &'a str,
    client: &'a BytesDto,
}

impl Vault<'_> {
    fn read(&self, loc: &LocationDto, what: &str) -> Result<Zeroizing<Vec<u8>>> {
        let account = account_for_location(self.store, self.snapshot_path, self.client, loc);
        self.store
            .get_bytes(&account)?
            .map(Zeroizing::new)
            .ok_or_else(|| Error::Crypto(format!("{what}: location is empty")))
    }

    fn write(&self, loc: &LocationDto, bytes: &[u8]) -> Result<()> {
        let account = account_for_location(self.store, self.snapshot_path, self.client, loc);
        self.store.set_bytes(&account, bytes)
    }

    /// Reads a 65-byte extended SLIP10 key.
    fn read_extended(&self, loc: &LocationDto, what: &str) -> Result<Slip10> {
        let bytes = self.read(loc, what)?;
        let arr: Zeroizing<[u8; 65]> =
            Zeroizing::new(bytes.as_slice().try_into().map_err(|_| {
                Error::Crypto(format!(
                    "{what}: expected 65-byte extended key, got {}",
                    bytes.len()
                ))
            })?);
        Slip10::try_from_extended_bytes(&arr)
            .map_err(|_| Error::Crypto(format!("{what}: invalid extended key")))
    }

    /// Reads a signing key: 32-byte Ed25519 secret or 65-byte extended SLIP10 key.
    fn read_secret_key(&self, loc: &LocationDto, what: &str) -> Result<SecretKey> {
        let bytes = self.read(loc, what)?;
        match bytes.len() {
            65 => Ok(self.read_extended(loc, what)?.secret_key()),
            32 => {
                let arr: Zeroizing<[u8; 32]> =
                    Zeroizing::new(bytes.as_slice().try_into().expect("length checked"));
                Ok(SecretKey::from_bytes(&arr))
            }
            n => Err(Error::Crypto(format!(
                "{what}: expected 32-byte sk or 65-byte extended key, got {n}"
            ))),
        }
    }
}

fn random(buf: &mut [u8]) -> Result<()> {
    crypto::utils::rand::fill(buf).map_err(|_| Error::Crypto("random generator failed".into()))
}

/// Executes a Stronghold-shaped procedure; reads/writes key material via [`KeyringStore`] locations.
///
/// This module is crate-private; embedders call the **`execute_procedure`** IPC command (guest-js
/// `Vault.*` helpers) when the **`crypto`** feature is enabled for the Rust crate.
pub fn execute_procedure(
    store: &KeyringStore,
    snapshot_path: &str,
    client: &BytesDto,
    procedure: ProcedureDto,
) -> Result<Vec<u8>> {
    let vault = Vault {
        store,
        snapshot_path,
        client,
    };
    match procedure {
        ProcedureDto::SLIP10Generate { output, size_bytes } => {
            let size = size_bytes.unwrap_or(32);
            if !SEED_LEN.contains(&size) {
                return Err(Error::Crypto(format!(
                    "SLIP10 generate: sizeBytes must be within 16..=64, got {size}"
                )));
            }
            let mut buf = Zeroizing::new(vec![0_u8; size]);
            random(&mut buf)?;
            let master = Slip10::from(&Seed::from_bytes(&buf));
            vault.write(&output, master.extended_bytes())?;
            Ok(Vec::new())
        }
        ProcedureDto::SLIP10Derive {
            chain,
            input,
            output,
        } => {
            let parent = match input {
                Slip10DeriveInputDto::Seed(loc) => {
                    let bytes = vault.read(&loc, "SLIP10 derive seed")?;
                    Slip10::from(&Seed::from_bytes(&bytes))
                }
                Slip10DeriveInputDto::Key(loc) => vault.read_extended(&loc, "SLIP10 derive key")?,
            };
            let derived = chain
                .into_iter()
                .fold(parent, |acc, seg| acc.child_key(seg.harden()));
            vault.write(&output, derived.extended_bytes())?;
            Ok(derived.chain_code().to_vec())
        }
        ProcedureDto::BIP39Recover {
            mnemonic,
            passphrase,
            output,
        } => {
            let mnemonic = Zeroizing::new(mnemonic);
            let m = bip39::Mnemonic::from(mnemonic.as_str());
            // The wordlist error names the offending word: never echo it.
            wordlist::verify(m.borrow(), &wordlist::ENGLISH)
                .map_err(|_| Error::Crypto("BIP39 recover: invalid mnemonic".into()))?;
            let pwd = passphrase.map(bip39::Passphrase::from).unwrap_or_default();
            let seed: Seed = bip39::mnemonic_to_seed(m.borrow(), pwd.borrow()).into();
            vault.write(&output, Slip10::from(&seed).extended_bytes())?;
            Ok(Vec::new())
        }
        ProcedureDto::BIP39Generate { passphrase, output } => {
            let mut entropy = Zeroizing::new([0_u8; 32]);
            random(entropy.as_mut())?;
            let mnemonic = wordlist::encode(entropy.as_ref(), &wordlist::ENGLISH)
                .map_err(|_| Error::Crypto("BIP39 generate: encoding failed".into()))?;
            let pwd = passphrase.map(bip39::Passphrase::from).unwrap_or_default();
            let seed: Seed = bip39::mnemonic_to_seed(mnemonic.borrow(), pwd.borrow()).into();
            vault.write(&output, Slip10::from(&seed).extended_bytes())?;
            let words: &str = mnemonic.as_ref();
            Ok(words.as_bytes().to_vec())
        }
        ProcedureDto::PublicKey { ty, private_key } => match ty {
            KeyType::Ed25519 => {
                let sk = vault.read_secret_key(&private_key, "public key")?;
                Ok(sk.public_key().to_bytes().to_vec())
            }
            KeyType::X25519 => Err(Error::Crypto(
                "X25519 public key extraction is not implemented".into(),
            )),
        },
        ProcedureDto::Ed25519Sign { private_key, msg } => {
            let sk = vault.read_secret_key(&private_key, "sign")?;
            Ok(sk.sign(msg.as_bytes()).to_bytes().to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vault procedures must hand back only public data, never the stored key material.
    /// Uses the in-memory mock store from keyring-core.
    #[test]
    fn procedures_never_return_private_keys() {
        crate::backend::use_mock_store_for_tests();
        let store = KeyringStore::new("keyring-store.crypto-test");
        let client = BytesDto::Text("c".into());
        let loc = |r: &str| LocationDto::Generic {
            vault: BytesDto::Text("v".into()),
            record: BytesDto::Text(r.into()),
        };
        let run = |p| execute_procedure(&store, "/snap", &client, p).unwrap();
        let stored = |r: &str| {
            let acc = account_for_location(&store, "/snap", &client, &loc(r));
            store.get_bytes(&acc).unwrap().unwrap()
        };

        let words = run(ProcedureDto::BIP39Generate {
            passphrase: None,
            output: loc("master"),
        });
        let words = String::from_utf8(words).unwrap();
        assert_eq!(words.split(' ').count(), 24);
        let master = stored("master");
        assert_eq!(master.len(), 65);

        // Recovering the returned mnemonic reproduces the same master key.
        let out = run(ProcedureDto::BIP39Recover {
            mnemonic: words,
            passphrase: None,
            output: loc("recovered"),
        });
        assert!(out.is_empty());
        assert_eq!(stored("recovered"), master);

        let cc = run(ProcedureDto::SLIP10Derive {
            chain: vec![44, 4218],
            input: Slip10DeriveInputDto::Key(loc("master")),
            output: loc("child"),
        });
        let child = stored("child");
        assert_eq!(cc, child[33..], "derive returns the chain code only");

        let pk = run(ProcedureDto::PublicKey {
            ty: KeyType::Ed25519,
            private_key: loc("child"),
        });
        let sig = run(ProcedureDto::Ed25519Sign {
            private_key: loc("child"),
            msg: "hi".into(),
        });
        assert_eq!((pk.len(), sig.len()), (32, 64));

        assert!(
            run(ProcedureDto::SLIP10Generate {
                output: loc("gen"),
                size_bytes: None,
            })
            .is_empty()
        );
        assert!(
            execute_procedure(
                &store,
                "/snap",
                &client,
                ProcedureDto::SLIP10Generate {
                    output: loc("gen"),
                    size_bytes: Some(1 << 40),
                },
            )
            .is_err()
        );
    }

    #[test]
    fn invalid_mnemonic_error_does_not_echo_words() {
        crate::backend::use_mock_store_for_tests();
        let store = KeyringStore::new("keyring-store.crypto-test");
        let err = execute_procedure(
            &store,
            "/snap",
            &BytesDto::Text("c".into()),
            ProcedureDto::BIP39Recover {
                mnemonic: "zebra notaword".into(),
                passphrase: None,
                output: LocationDto::Generic {
                    vault: BytesDto::Text("v".into()),
                    record: BytesDto::Text("r".into()),
                },
            },
        )
        .unwrap_err()
        .to_string();
        assert!(!err.contains("notaword"), "{err}");
    }
}
