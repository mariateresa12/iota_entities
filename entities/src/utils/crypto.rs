/*use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::path::Path;
use tokio::fs;
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedFile {
  v: u8,
  salt_b64: String,
  nonce_b64: String,
  ct_b64: String,
}

fn derive_key_argon2id(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
  // memory: 19 MiB (19456 KiB), iterations: 3, parallelism: 1
  let params = Params::new(19_456, 3, 1, Some(32));
  let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

  let mut key = [0u8; 32];
  argon2
    .hash_password_into(password.as_bytes(), salt, &mut key);
  Ok(key)
}

pub async fn encrypt_json_to_file<T: Serialize>(path: &Path, password: &str, value: &T) -> Result<()> {
  if let Some(parent) = path.parent() {
    let _ = fs::create_dir_all(parent).await;
  }

  let plaintext = serde_json::to_vec(value).context("serialize plaintext json")?;

  // Salt aleatoria para derivación
  let mut salt = [0u8; 16];
  OsRng.fill_bytes(&mut salt);

  let mut key = derive_key_argon2id(password, &salt)?;
  let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

  // Nonce AEAD de 12 bytes
  let mut nonce = [0u8; 12];
  OsRng.fill_bytes(&mut nonce);

  let ct = cipher
    .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref());

  // Limpiar material sensible
  key.zeroize();

  let out = EncryptedFile {
    v: 1,
    salt_b64: URL_SAFE_NO_PAD.encode(salt),
    nonce_b64: URL_SAFE_NO_PAD.encode(nonce),
    ct_b64: URL_SAFE_NO_PAD.encode(ct),
  };

  let json = serde_json::to_string_pretty(&out).context("serialize encrypted file")?;
  fs::write(path, json).await.context("write encrypted file")?;
  Ok(())
}

pub async fn decrypt_json_from_file<T: DeserializeOwned>(path: &Path, password: &str) -> Result<T> {
  let content = fs::read_to_string(path).await.context("read encrypted file")?;
  let enc: EncryptedFile = serde_json::from_str(&content).context("parse encrypted file json")?;

  if enc.v != 1 {
    anyhow::bail!("unsupported encrypted format version {}", enc.v);
  }

  let salt = URL_SAFE_NO_PAD.decode(enc.salt_b64).context("b64 decode salt")?;
  let nonce = URL_SAFE_NO_PAD.decode(enc.nonce_b64).context("b64 decode nonce")?;
  let ct = URL_SAFE_NO_PAD.decode(enc.ct_b64).context("b64 decode ciphertext")?;

  if nonce.len() != 12 {
    anyhow::bail!("invalid nonce length");
  }

  let mut key = derive_key_argon2id(password, &salt)?;
  let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

  let plaintext = cipher
    .decrypt(Nonce::from_slice(&nonce), ct.as_ref());

  key.zeroize();

  let value = serde_json::from_slice::<T>(&plaintext).context("deserialize plaintext json")?;
  Ok(value)
}
*/