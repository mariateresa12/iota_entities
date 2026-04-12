use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::env::var;
use base64::Engine as _;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{to_string_pretty, from_str};
use tokio::fs::{read_to_string, write, create_dir_all, metadata};

use fips204::ml_dsa_44;
use fips204::ml_dsa_44::{PK_LEN, SK_LEN};
use fips204::traits::{SerDes};
use ed25519_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SigningKey};
use rand::rngs::OsRng;

use identity_did::{CoreDID, DIDUrl};
use identity_iota::iota::IotaDocument;
use identity_iota::resolver::Resolver;
use identity_iota::storage::{JwkMemStore, JwkStorage, KeyIdMemstore, KeyIdStorage, Storage};
use identity_iota::verification::jwk::{CompositeAlgId, CompositeJwk, Jwk, PostQuantumJwk, TraditionalJwk};
use identity_iota::verification::jwk::{JwkParamsOkp, JwkOperation, JwkParamsAkp};
use identity_iota::verification::jws::JwsAlgorithm;
use identity_iota::verification::{MethodData, MethodScope, VerificationMethod};

use identity_storage::{KeyId, MethodDigest};

use product_common::core_client::CoreClientReadOnly;

use crate::utils::functions::{get_funded_client, get_read_only_client, MemStorage};

// -------------------------------------------------------------------------------------
// Persistencia en ~/keys/
// -------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedHybridIdentity {
  pub did: String,
  pub fragment: String,
  pub alg_id: String,

  // base64url de las claves
  pub pq_pk_b64: String,
  pub pq_sk_b64: String,
  pub t_pk_b64: String,
  pub t_sk_b64: String,
}

pub async fn keys_dir() -> Result<PathBuf> {
  let home = var("HOME").context("HOME env var not set (cannot resolve ~)")?;
  let dir = PathBuf::from(home).join("keys");
  create_dir_all(&dir).await.context("create ~/keys directory failed")?;
  Ok(dir)
}

pub async fn service_keys_dir(service: &str) -> Result<PathBuf> {
  let home = std::env::var("HOME").context("HOME env var not set (cannot resolve ~)")?;
  let dir = PathBuf::from(home).join(service).join("keys");
  create_dir_all(&dir).await.context("create service keys directory failed")?;
  Ok(dir)
}

pub async fn service_state_file(service: &str, name: &str) -> Result<PathBuf> {
  let mut p = service_keys_dir(service).await?.join(name);
  if p.extension().is_none() {
    p.set_extension("json");
  }
  Ok(p)
}

async fn write_persisted(path: &Path, data: &PersistedHybridIdentity) -> Result<()> {
  let json = to_string_pretty(data).context("serialize persisted identity")?;
  write(path, json).await.context("write persisted identity")?;
  Ok(())
}

async fn read_persisted(path: &Path) -> Result<PersistedHybridIdentity> {
  let txt = read_to_string(path).await.context("read persisted identity")?;
  let data: PersistedHybridIdentity = from_str(&txt).context("parse persisted identity")?;
  Ok(data)
}

fn b64url(bytes: &[u8]) -> String {
  base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64url_decode(s: &str) -> Result<Vec<u8>> {
  base64::engine::general_purpose::URL_SAFE_NO_PAD
    .decode(s)
    .map_err(|e| anyhow::anyhow!("base64url decode failed: {e}"))
}


pub async fn generate_hybrid_keys()-> Result<([u8; PK_LEN], [u8; SK_LEN], [u8; PUBLIC_KEY_LENGTH], [u8; SECRET_KEY_LENGTH])>{
    // Generar par de claves pos-quantum (ML-DSA-44)
    let (pq_pk, pq_sk) = ml_dsa_44::try_keygen().map_err(|e| anyhow::anyhow!("ml_dsa_44::try_keygen failed: {e}"))?;
    
    let pq_pk_bytes = pq_pk.into_bytes();
    let pq_sk_bytes = pq_sk.into_bytes();

    // Generar par de claves tradicionales (ED25519)
    let mut csprng = OsRng;
    let t_signing_key: SigningKey = SigningKey::generate(&mut csprng); 

    let t_pk_bytes: [u8; PUBLIC_KEY_LENGTH] = t_signing_key.verifying_key().to_bytes();
    let t_sk_bytes: [u8; SECRET_KEY_LENGTH] = t_signing_key.to_bytes();
    
    Ok((pq_pk_bytes,pq_sk_bytes,t_pk_bytes,t_sk_bytes))

}

fn build_ed25519_private_jwk(t_pk: &[u8], t_sk: &[u8]) -> Result<Jwk> {
  let mut params = JwkParamsOkp::new();
  params.crv = "Ed25519".to_string();
  params.x = b64url(t_pk);
  params.d = Some(b64url(t_sk));

  let mut jwk = TraditionalJwk::new(params);
  jwk.set_alg(JwsAlgorithm::EdDSA.to_string())?;
  jwk.set_key_ops([JwkOperation::Sign]);

  Ok(Jwk::from(jwk))
}

fn build_ed25519_public_jwk(t_pk: &[u8]) -> Result<Jwk> {
  let mut params = JwkParamsOkp::new();
  params.crv = "Ed25519".to_string();
  params.x = b64url(t_pk);
  params.d = None;

  let mut jwk = TraditionalJwk::new(params);
  jwk.set_alg(JwsAlgorithm::EdDSA.to_string())?;
  jwk.set_key_ops([JwkOperation::Verify]);

  Ok(Jwk::from(jwk))
}

fn build_ml_dsa_44_private_jwk(pq_pk: &[u8], pq_sk: &[u8]) -> Result<Jwk> {
  let params = JwkParamsAkp {
    public: b64url(pq_pk),
    private: Some(b64url(pq_sk)),
  };

  let mut jwk = PostQuantumJwk::new(params);
  jwk.set_alg(JwsAlgorithm::ML_DSA_44.to_string())?;
  jwk.set_key_ops([JwkOperation::Sign]);

  Ok(Jwk::from(jwk))
}

fn build_ml_dsa_44_public_jwk(pq_pk: &[u8]) -> Result<Jwk> {
  let params = JwkParamsAkp {
    public: b64url(pq_pk),
    private: None,
  };

  let mut jwk = PostQuantumJwk::new(params);
  jwk.set_alg(JwsAlgorithm::ML_DSA_44.to_string())?;
  jwk.set_key_ops([JwkOperation::Verify]);

  Ok(Jwk::from(jwk))
}

// Inserta en el storage las JWK privadas, crea el método híbrido en el documento con las públicas
// y guarda el mapping digest->composite_kid en KeyIdStorage.
pub async fn insert_hybrid_method_from_external_keys(document: &mut IotaDocument, storage: &MemStorage, alg_id: CompositeAlgId, fragment: Option<&str>, scope: MethodScope,
  pq_pk: &[u8], pq_sk: &[u8], t_pk: &[u8], t_sk: &[u8],) -> Result<String> {

  // 1) Construir JWK privadas
  let t_jwk_priv: Jwk = build_ed25519_private_jwk(t_pk, t_sk)?;
  let pq_jwk_priv: Jwk = build_ml_dsa_44_private_jwk(pq_pk, pq_sk)?;

  // 2) Insertarlas en el storage (obtiene KeyId para firmar)
  let t_key_id: KeyId = storage.key_storage().insert(t_jwk_priv).await.context("insert trad jwk failed")?;
  let pq_key_id: KeyId = storage.key_storage().insert(pq_jwk_priv).await.context("insert pq jwk failed")?;

  let composite_kid: KeyId = KeyId::new(format!("{}~{}", t_key_id.as_str(), pq_key_id.as_str()));

  // 3) Construir CompositeJwk con SOLO públicas para publicar en el DID Document
  let t_jwk_pub: Jwk = build_ed25519_public_jwk(t_pk)?;
  let pq_jwk_pub: Jwk = build_ml_dsa_44_public_jwk(pq_pk)?;

  let t_pub: TraditionalJwk = TraditionalJwk::try_from(t_jwk_pub).context("TraditionalJwk::try_from failed")?;
  let pq_pub: PostQuantumJwk = PostQuantumJwk::try_from(pq_jwk_pub).context("PostQuantumJwk::try_from failed")?;

  let composite_pk: CompositeJwk = CompositeJwk::new(alg_id, t_pub, pq_pub);

  // 4) Crear VerificationMethod y meterlo en el documento
  let method: VerificationMethod =
    VerificationMethod::new_from_compositejwk(document.id().clone(), composite_pk, fragment).context("new_from_compositejwk failed")?;

  let method_digest: MethodDigest = MethodDigest::new(&method).context("MethodDigest::new failed")?;
  let method_id: DIDUrl = method.id().clone();

  let fragment_out: String = method_id.fragment().context("missing fragment")?.to_owned();

  document.insert_method(method, scope).context("insert_method failed")?;

  // 5) Guardar mapping digest -> composite_kid
  <KeyIdMemstore as KeyIdStorage>::insert_key_id(storage.key_id_storage(), method_digest, composite_kid)
    .await
    .context("insert_key_id failed")?;

  Ok(fragment_out)
}

// -------------------------------------------------------------------------------------
// Restauración: insertar JWK privadas en MemStorage
// -------------------------------------------------------------------------------------

async fn restore_hybrid_storage(document: &IotaDocument, storage: &MemStorage, persisted: &PersistedHybridIdentity,) -> Result<String> {
  // 1) Decodificar bytes
  let pq_pk = b64url_decode(&persisted.pq_pk_b64)?;
  let pq_sk = b64url_decode(&persisted.pq_sk_b64)?;
  let t_pk = b64url_decode(&persisted.t_pk_b64)?;
  let t_sk = b64url_decode(&persisted.t_sk_b64)?;

  // 2) Construir JWK privadas e insertarlas en el storage
  let t_jwk_priv = build_ed25519_private_jwk(&t_pk, &t_sk)?;
  let pq_jwk_priv = build_ml_dsa_44_private_jwk(&pq_pk, &pq_sk)?;

  let t_key_id: KeyId = storage.key_storage().insert(t_jwk_priv).await.context("insert trad jwk failed")?;
  let pq_key_id: KeyId = storage.key_storage().insert(pq_jwk_priv).await.context("insert pq jwk failed")?;

  let composite_kid: KeyId = KeyId::new(format!("{}~{}", t_key_id.as_str(), pq_key_id.as_str()));

  // 3) Obtener el método híbrido ya existente en el documento (por fragment) y reinyectar digest->kid
  let method = document
    .resolve_method(persisted.fragment.as_str(), None)
    .with_context(|| format!("method not found for fragment {}", persisted.fragment))?;

  let MethodData::CompositeJwk(_) = method.data() else {
    anyhow::bail!("method is not CompositeJwk (not hybrid)");
  };

  let digest: MethodDigest = MethodDigest::new(method).context("MethodDigest::new failed")?;

  <KeyIdMemstore as KeyIdStorage>::insert_key_id(storage.key_id_storage(), digest, composite_kid)
    .await
    .context("insert_key_id (restore) failed")?;

  Ok(persisted.fragment.clone())
}

// -------------------------------------------------------------------------------------
// FUNCIÓN PRINCIPAL: load_or_create_hybrid_identity(state_file)
// -------------------------------------------------------------------------------------

/// Crea o carga una identidad híbrida:
/// - Persiste en JSON en `~/keys/...`.
/// - Asume un único método híbrido por DID.
/// - Mantiene claves híbridas usando MemStorage.
///
/// Devuelve: (IotaDocument, fragment, MemStorage)
pub async fn load_or_create_hybrid_identity(state_file: PathBuf) -> Result<(IotaDocument, String, MemStorage)> {
  let alg_id = CompositeAlgId::IdMldsa44Ed25519;
  let path = state_file;

  let storage: MemStorage = Storage::new(JwkMemStore::new(), KeyIdMemstore::new());

  // --------- CASO: existe estado -> resolver DID y restaurar storage ----------
  if metadata(&path).await.is_ok() {
    let persisted = read_persisted(&path).await?;

    // Resolver DID desde la red (documento actualizado)
    let read_only = get_read_only_client().await?;
    let mut resolver: Resolver<IotaDocument> = Resolver::new();
    resolver.attach_iota_handler(read_only);

    let did: CoreDID = CoreDID::from_str(&persisted.did).context("parse persisted DID")?;
    let doc: IotaDocument = resolver.resolve(&did).await.context("resolve persisted DID")?;

    let fragment = restore_hybrid_storage(&doc, &storage, &persisted).await?;
    return Ok((doc, fragment, storage));
  }

  // --------- CASO: no existe estado -> generar claves, crear DID, publicar, persistir ----------
  // Generar claves
  let (pq_pk, pq_sk, t_pk, t_sk) = generate_hybrid_keys().await?;

  // Crear client y documento
  let client = get_funded_client(&storage).await?;
  let mut document: IotaDocument = IotaDocument::new(client.network_name());

  // Insertar método híbrido usando las claves generadas
  let fragment: String = insert_hybrid_method_from_external_keys(&mut document, &storage, alg_id, None, MethodScope::VerificationMethod,
    &pq_pk, &pq_sk, &t_pk, &t_sk,).await?;

  // Publicar DID
  let identity = client
    .create_identity(document)
    .finish()
    .build_and_execute(&client)
    .await
    .context("publish identity")?
    .output;

  let did_document: IotaDocument = identity.into();

  // Persistir claves y metadata
  let persisted = PersistedHybridIdentity {
    did: did_document.id().to_string(),
    fragment: fragment.clone(),
    alg_id: format!("{alg_id:?}"),
    pq_pk_b64: b64url(&pq_pk),
    pq_sk_b64: b64url(&pq_sk),
    t_pk_b64: b64url(&t_pk),
    t_sk_b64: b64url(&t_sk),
  };

  write_persisted(&path, &persisted).await?;

  Ok((did_document, fragment, storage))
}