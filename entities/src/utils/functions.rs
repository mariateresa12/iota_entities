use std::path::{Path,PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use base64::Engine as _;

use anyhow::{Context, Ok, anyhow};
use identity_iota::iota::IotaDocument;
use identity_iota::storage::JwkDocumentExtHybrid;
use identity_iota::storage::KeyIdMemstore;
use identity_iota::storage::JwkMemStore;
use identity_iota::storage::Storage;
use identity_iota::verification::jwk::CompositeAlgId;
use identity_iota::verification::jws::JwsAlgorithm;
use identity_iota::verification::MethodScope;
use identity_iota::verification::jwk::Jwk;

use identity_iota::credential::Jwt;
use identity_iota::credential::RevocationBitmap;

use identity_iota::did::DIDUrl;
use identity_iota::did::DID;
use identity_iota::document::Service;

use identity_iota::iota::rebased::client::IdentityClient;
use identity_iota::iota::rebased::client::IdentityClientReadOnly;
use identity_iota::iota::rebased::utils::request_funds;
use identity_iota::iota_interaction::IotaKeySignature;
use identity_storage::JwkStorage;
use identity_storage::KeyIdStorage;
use identity_storage::KeyId;
use identity_storage::KeyType;
use identity_storage::StorageSigner;
use iota_sdk::types::base_types::IotaAddress;
use iota_sdk::IotaClient;
use iota_sdk::IotaClientBuilder;
use iota_sdk::IOTA_LOCAL_NETWORK_URL;
use notarization::NotarizationClient;
use notarization::NotarizationClientReadOnly;

use secret_storage::Signer;
use serde_json::{json, Value, from_slice};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncWriteExt};
use tokio::fs;

use rand::rngs::OsRng;
use rand::RngCore;

use product_common::core_client::CoreClientReadOnly as _;

pub const TEST_GAS_BUDGET: u64 = 1_000_000_000;
pub const CREDENTIAL_DIR_SEGMENTS: [&str; 2] = ["holder","credentials"];
pub const ISSUER_CREDENTIAL_DIR_SEGMENTS: [&str; 2] = ["issuer","credentials"];
pub const REVOCATION_SERVICE: &str = "#revocation-service";

pub type MemStorage = Storage<JwkMemStore, KeyIdMemstore>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerConfig {
  pub key_id: String, 
  pub public_jwk: Jwk,
}

#[derive(Debug, Serialize, Deserialize)]
struct IndexEntry {
  dir: String,
  credential_type: String,
  received_at_unix: u64,
}

pub fn decode_jwt(jwt_str: &str) -> anyhow::Result<Value> {
  let parts: Vec<&str> = jwt_str.split('.').collect();
  if parts.len() < 2 {
    anyhow::bail!("invalid JWT: expected at least 2 parts");
  }

  let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;

  let header_bytes = engine.decode(parts[0])?;
  let payload_bytes = engine.decode(parts[1])?;

  let header: Value = from_slice(&header_bytes)?;
  let payload: Value = from_slice(&payload_bytes)?;

  Ok(json!([header, payload]))
}

pub fn get_dir(segments: [&str; 2]) -> anyhow::Result<PathBuf> {
  let home = std::env::var_os("HOME")
    .or_else(|| std::env::var_os("USERPROFILE"))
    .ok_or_else(|| anyhow!("HOME/USERPROFILE could not be determined"))?;

  let mut path = PathBuf::from(home);
  for seg in segments {
    path = path.join(seg);
  }
  Ok(path)
}

pub fn index_path() -> anyhow::Result<PathBuf> {
  Ok(get_dir(CREDENTIAL_DIR_SEGMENTS)?.join("index.jsonl"))
}

pub async fn append_index_entry(dir_path: &PathBuf, credential_type: &str) -> anyhow::Result<()> {
  let base = get_dir(CREDENTIAL_DIR_SEGMENTS)?;
  let index = index_path()?;
  fs::create_dir_all(&base).await?;

  let dir_name: String = dir_path
    .file_name()
    .and_then(|x| x.to_str())
    .ok_or_else(|| anyhow!("The folder name could not be retrieved"))?
    .to_string();

  let received_at_unix: u64 = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

  let entry = IndexEntry {
    dir: dir_name,
    credential_type: credential_type.to_string(),
    received_at_unix,
  };

  let mut f = fs::OpenOptions::new()
    .create(true)
    .append(true)
    .open(&index)
    .await
    .with_context(|| format!("Could not open/create {:?}", index))?;

  let line = serde_json::to_string(&entry)?;
  f.write_all(line.as_bytes()).await?;
  f.write_all(b"\n").await?;
  f.flush().await?;
  Ok(())
}

pub async fn find_latest_dir(credential_type: &str) -> anyhow::Result<PathBuf> {
  let index = index_path()?;
  let base = get_dir(CREDENTIAL_DIR_SEGMENTS)?;

  let content = fs::read_to_string(&index)
    .await
    .with_context(|| format!("The index {:?} could not be read", index))?;

  let mut best: Option<IndexEntry> = None;

  for line in content.lines() {
    if line.trim().is_empty() {
      continue;
    }
    let entry: IndexEntry = serde_json::from_str(line)
      .with_context(|| format!("Corrupt line in index.jsonl: {}", line))?;

    if entry.credential_type == credential_type {
      let replace = match &best {
        None => true,
        Some(b) => entry.received_at_unix >= b.received_at_unix,
      };
      if replace {
        best = Some(entry);
      }
    }
  }

  let best = best.ok_or_else(|| anyhow!("There are no credentials of type '{}'", credential_type))?;
  Ok(base.join(best.dir))
}

pub async fn store_issuer_credential(credential_index: u32, jwt: &Jwt,) -> anyhow::Result<PathBuf> {
  let base: PathBuf = get_dir(ISSUER_CREDENTIAL_DIR_SEGMENTS)?;
  fs::create_dir_all(&base).await?;

  let file_path: PathBuf = base.join(format!("{}.jwt", credential_index));

  let mut f = fs::OpenOptions::new()
    .create_new(true)
    .write(true)
    .open(&file_path)
    .await
    .with_context(|| format!("Could not create {:?}", file_path))?;

  f.write_all(jwt.as_str().as_bytes()).await?;
  f.write_all(b"\n").await?;
  f.flush().await?;

  Ok(file_path)
}

pub fn issuer_credential_file_path(index: u32) -> anyhow::Result<PathBuf> {
  let base = get_dir(ISSUER_CREDENTIAL_DIR_SEGMENTS)?;
  Ok(base.join(format!("{}.jwt", index)))
}

pub fn now_unix() -> u64 {
  use std::time::{SystemTime, UNIX_EPOCH};
  SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

pub fn created_at_from_folder_name(name: &str) -> u64 {
  // Esperado: "idx1_ts1700000000_rdeadbeef"
  let ts_pos = match name.find("_ts") {
    Some(p) => p + 3, // salta "_ts"
    None => return 0,
  };

  let tail = &name[ts_pos..];
  let ts_str = match tail.split('_').next() {
    Some(v) if !v.is_empty() => v,
    _ => return 0,
  };

  ts_str.parse::<u64>().unwrap_or(0)
}

pub async fn read_credential_jwt(dir: &Path) -> anyhow::Result<String> {
  let jwt_path = dir.join("credential.jwt");
  let content = fs::read_to_string(jwt_path).await?;
  Ok(content.trim().to_string())
}

pub async fn load_credential_from_dir(dir: &PathBuf) -> anyhow::Result<Jwt> {
  let file = dir.join("credential.jwt");
  Ok(load_credential(&file).await?)
}

pub async fn load_credential(file: &PathBuf) -> anyhow::Result<Jwt> {
  let jwt_str: String = fs::read_to_string(file).await?;
  Ok(Jwt::new(jwt_str.trim().to_string()))
}

pub async fn load_latest_credential(credential_type: &str) -> anyhow::Result<(PathBuf, Jwt)> {
  let dir = find_latest_dir(credential_type).await?;
  let jwt = load_credential_from_dir(&dir).await?;
  Ok((dir, jwt))
}

// Challenge (16 bytes) en hex con guiones.
pub fn generate_challenge() -> String {
  let mut bytes: [u8; 16] = [0u8; 16];
  OsRng.fill_bytes(&mut bytes);

  format!(
    "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
    bytes[0], bytes[1], bytes[2], bytes[3],
    bytes[4], bytes[5],
    bytes[6], bytes[7],
    bytes[8], bytes[9],
    bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
  )
}

pub fn get_iota_endpoint() -> String {
  std::env::var("API_ENDPOINT").unwrap_or_else(|_| IOTA_LOCAL_NETWORK_URL.to_string())
}

pub async fn get_iota_client() -> anyhow::Result<IotaClient> {
  let api_endpoint = std::env::var("API_ENDPOINT").unwrap_or_else(|_| IOTA_LOCAL_NETWORK_URL.to_string());
  IotaClientBuilder::default()
    .build(&api_endpoint)
    .await
    .map_err(|err| anyhow::anyhow!(format!("failed to connect to network; {}", err)))
}

pub async fn get_read_only_client() -> anyhow::Result<IdentityClientReadOnly> {
  let iota_client = get_iota_client().await?;
  let package_id = std::env::var("IOTA_IDENTITY_PKG_ID")
    .map_err(|e| anyhow::anyhow!("env variable IOTA_IDENTITY_PKG_ID must be set in order to run the examples").context(e))
    .and_then(|pkg_str| pkg_str.parse().context("invalid package id"))?;

  IdentityClientReadOnly::new_with_pkg_id(iota_client, package_id)
    .await
    .context("failed to create a read-only IdentityClient")
}

pub async fn get_funded_client<K, I>(storage: &Storage<K, I>) -> Result<IdentityClient<StorageSigner<'_, K, I>>, anyhow::Error>
where
  K: JwkStorage,
  I: KeyIdStorage,
{
  // generate new key
  let generate = storage.key_storage().generate(KeyType::new("Ed25519"), JwsAlgorithm::EdDSA).await?;
  let public_key_jwk = generate.jwk.to_public().expect("public components should be derivable");
  let signer = StorageSigner::new(storage, generate.key_id, public_key_jwk);
  let sender_address = IotaAddress::from(&Signer::public_key(&signer).await?);

  request_funds(&sender_address).await?;

  let read_only_client = get_read_only_client().await?;
  let identity_client = IdentityClient::new(read_only_client, signer).await?;

  Ok(identity_client)
}

pub async fn get_notarization_client<K, I>(signer: StorageSigner<'_, K, I>) -> anyhow::Result<NotarizationClient<StorageSigner<'_, K, I>>>
where
  K: JwkStorage,
  I: KeyIdStorage,
{
  let package_id = std::env::var("IOTA_NOTARIZATION_PKG_ID")
    .map_err(|e| anyhow::anyhow!("env variable IOTA_NOTARIZATION_PKG_ID must be set in order to run this example").context(e))
    .and_then(|pkg_str| pkg_str.parse().context("invalid package id"))?;

  let read_only_client = NotarizationClientReadOnly::new_with_pkg_id(get_iota_client().await?, package_id).await?;
  let client = NotarizationClient::new(read_only_client, signer).await?;
  Ok(client)
}

pub fn get_memstorage() -> Result<MemStorage, anyhow::Error> {
  Ok(MemStorage::new(JwkMemStore::new(), KeyIdMemstore::new()))
}

pub fn pretty_print_json(label: &str, value: &str) {
  let data: Value = serde_json::from_str(value).unwrap();
  let pretty_json = serde_json::to_string_pretty(&data).unwrap();
  println!("--------------------------------------");
  println!("{label}:");
  println!("--------------------------------------");
  println!("{pretty_json} \n");
}

pub async fn create_did_document<S>(client: &IdentityClient<S>, storage: &MemStorage, alg_id: CompositeAlgId) -> anyhow::Result<(IotaDocument, String)>
where
  S: Signer<IotaKeySignature> + Sync,
{
  let mut document: IotaDocument = IotaDocument::new(client.network_name());

  let fragment: String = document.generate_method_hybrid(storage, alg_id, None, MethodScope::VerificationMethod).await?;


  
  let identity = client.create_identity(document).finish().build_and_execute(client).await?.output;

  let did_document: IotaDocument = identity.into();

  Ok((did_document, fragment))
}

/*
pub async fn create_client<K, I>(storage: &MemStorage) -> Result<(IotaDocument, String, IdentityClient<StorageSigner<'_, JwkMemStore, KeyIdMemstore>>), anyhow::Error>
where
  K: JwkStorage,
  I: KeyIdStorage,
{
  let client = get_funded_client(&storage).await?;
  let (did_document, fragment) = create_did_document(&client, &storage, CompositeAlgId::IdMldsa44Ed25519).await?;
  
  Ok((did_document, fragment, client))
}
*/

pub async fn create_client() -> anyhow::Result<(IotaDocument, String, MemStorage)> {
  let storage: MemStorage = get_memstorage()?;
  let client = get_funded_client(&storage).await?;

  let (did_document, fragment) = create_did_document(&client, &storage, CompositeAlgId::IdMldsa44Ed25519).await?;
  Ok((did_document, fragment, storage))
}

pub async fn add_revocation_service(document: &IotaDocument, storage: &MemStorage, cfg: &SignerConfig) -> anyhow::Result<IotaDocument> {
  let mut doc = document.clone();
  // Create a new empty revocation bitmap. No credential is revoked yet.
  let revocation_bitmap: RevocationBitmap = RevocationBitmap::new();

  // Add the revocation bitmap to the DID document of the issuer as a service.
  let service_id: DIDUrl = document.id().to_url().join(REVOCATION_SERVICE)?;
  let service: Service = revocation_bitmap.to_service(service_id)?;

  doc.insert_service(service).map_err(|e| anyhow::anyhow!("insert_service failed: {e}"))?;

  Ok(update_did_document(doc, storage, cfg).await?)
}

pub async fn update_did_document(document: IotaDocument, storage: &MemStorage, cfg: &SignerConfig) -> anyhow::Result<IotaDocument> {
  let client = rebuild_client(storage, cfg).await?;
  let updated = client.publish_did_document_update(document, TEST_GAS_BUDGET).await?;

  Ok(updated)
}

pub async fn get_signer_config<K, I>(storage: &Storage<K, I>, path: &Path) -> anyhow::Result<SignerConfig>
where
  K: JwkStorage,
  I: KeyIdStorage,
{
  if path.exists() {
    let txt = fs::read_to_string(path).await.context("read signer config")?;
    let cfg: SignerConfig = serde_json::from_str(&txt).context("parse signer config")?;
    return Ok(cfg);
  }

  // Crear key una sola vez
  let generate = storage
    .key_storage()
    .generate(KeyType::new("Ed25519"), JwsAlgorithm::EdDSA)
    .await?;

  let public_jwk = generate
    .jwk
    .to_public()
    .expect("public components should be derivable");

  // Construir signer y pedir fondos
  let signer = StorageSigner::new(storage, generate.key_id.clone(), public_jwk.clone());
  let sender_address = IotaAddress::from(&Signer::public_key(&signer).await?);

  request_funds(&sender_address).await?;

  // Persistir
  let cfg = SignerConfig {
    key_id: generate.key_id.to_string(),
    public_jwk,
  };

  fs::create_dir_all(path.parent().unwrap()).await.ok();
  fs::write(path, serde_json::to_string_pretty(&cfg)?).await.context("write signer config")?;

  Ok(cfg)
}

pub async fn rebuild_client<'a, K, I>(storage: &'a Storage<K, I>, cfg: &SignerConfig,) -> Result<IdentityClient<StorageSigner<'a, K, I>>, anyhow::Error>
where
  K: JwkStorage,
  I: KeyIdStorage,
{
  let key_id: KeyId = KeyId::new(cfg.key_id.clone());

  let signer = StorageSigner::new(storage, key_id, cfg.public_jwk.clone());

  let read_only_client = get_read_only_client().await?;
  let identity_client = IdentityClient::new(read_only_client, signer).await?;
  Ok(identity_client)
}

pub async fn create_client_rebuilable(path: &Path) -> anyhow::Result<(IotaDocument, String, MemStorage, SignerConfig)> {
  let storage: MemStorage = get_memstorage()?;
  let cfg = get_signer_config(&storage, path).await?;
  let client = rebuild_client(&storage, &cfg).await?;

  let (did_document, fragment) = create_did_document(&client, &storage, CompositeAlgId::IdMldsa44Ed25519).await?;
  Ok((did_document, fragment, storage, cfg))
}