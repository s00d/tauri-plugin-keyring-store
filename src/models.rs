//! Request and response types shared between Rust, IPC, and TypeScript.

use std::{fmt, time::Duration};

use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PingRequest {
    pub value: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PingResponse {
    pub value: Option<String>,
}

/// Bytes payload compatible with Stronghold's JS API (`string | bytes`).
#[derive(Debug, Clone, Deserialize, Serialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
#[serde(untagged)]
pub enum BytesDto {
    Text(String),
    Raw(Vec<u8>),
}

impl AsRef<[u8]> for BytesDto {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Text(t) => t.as_bytes(),
            Self::Raw(b) => b.as_ref(),
        }
    }
}

impl From<BytesDto> for Vec<u8> {
    fn from(v: BytesDto) -> Self {
        match v {
            BytesDto::Text(t) => t.into_bytes(),
            BytesDto::Raw(b) => b,
        }
    }
}

/// Stronghold-compatible duration (ignored for OS keyring persistence).
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DurationDto {
    pub secs: u64,
    pub nanos: u32,
}

impl From<DurationDto> for Duration {
    fn from(d: DurationDto) -> Self {
        Duration::new(d.secs, d.nanos)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", content = "payload")]
pub enum LocationDto {
    Generic { vault: BytesDto, record: BytesDto },
    Counter { vault: BytesDto, counter: usize },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", content = "payload")]
pub enum Slip10DeriveInputDto {
    Seed(LocationDto),
    Key(LocationDto),
}

#[derive(Debug, Clone, Copy)]
pub enum KeyType {
    Ed25519,
    X25519,
}

impl<'de> Deserialize<'de> for KeyType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct KeyTypeVisitor;

        impl<'de> Visitor<'de> for KeyTypeVisitor {
            type Value = KeyType;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("ed25519 or x25519")
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value.to_lowercase().as_str() {
                    "ed25519" => Ok(KeyType::Ed25519),
                    "x25519" => Ok(KeyType::X25519),
                    _ => Err(serde::de::Error::custom("unknown key type")),
                }
            }
        }

        deserializer.deserialize_str(KeyTypeVisitor)
    }
}

impl Serialize for KeyType {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = match self {
            KeyType::Ed25519 => "ed25519",
            KeyType::X25519 => "x25519",
        };
        serializer.serialize_str(s)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", content = "payload")]
pub enum ProcedureDto {
    SLIP10Generate {
        output: LocationDto,
        #[serde(rename = "sizeBytes")]
        size_bytes: Option<usize>,
    },
    SLIP10Derive {
        chain: Vec<u32>,
        input: Slip10DeriveInputDto,
        output: LocationDto,
    },
    BIP39Recover {
        mnemonic: String,
        passphrase: Option<String>,
        output: LocationDto,
    },
    BIP39Generate {
        passphrase: Option<String>,
        output: LocationDto,
    },
    PublicKey {
        #[serde(rename = "type")]
        ty: KeyType,
        #[serde(rename = "privateKey")]
        private_key: LocationDto,
    },
    Ed25519Sign {
        #[serde(rename = "privateKey")]
        private_key: LocationDto,
        msg: String,
    },
}

/// One row for [`crate::commands::set_passwords`] (bulk set).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordEntryDto {
    pub account: String,
    pub secret: String,
}

/// Single entry in a plaintext password backup (export/import).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordBackupEntryDto {
    pub account: String,
    /// [`None`] when the credential did not exist at export time.
    pub secret: Option<String>,
}

/// Plaintext backup blob shared by export/import JSON over IPC.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordBackupPlainDto {
    /// Schema version for forward compatibility.
    pub format_version: u32,
    pub entries: Vec<PasswordBackupEntryDto>,
}

/// Argon2id + ChaCha20-Poly1305 backup envelope (always built).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordBackupEncryptedDto {
    pub format_version: u32,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}
