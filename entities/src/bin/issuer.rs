use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};

//use iota_sdk::IotaClient;
//use iota_sdk::types::storage::Storage;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::collections::HashMap;
use std::path::PathBuf;

use tokio::sync::RwLock;
use tokio::fs;

use anyhow::{anyhow, Context};

use entities::utils::{MemStorage};
use entities::utils::{generate_challenge, now_unix, decode_jwt, create_client_rebuilable, add_revocation_service, update_did_document, get_signer_config, get_dir,
                      store_issuer_credential, issuer_credential_file_path, load_credential, get_read_only_client, write_credential_idx, get_last_credential_idx};
use entities::utils::{CredentialResponse, DIDResponse, CredentialKind, IssueAuthRequest, AuthNonceResponse, StudentParams};
use entities::utils::REVOCATION_SERVICE;
use entities::database::{is_student, get_certificate};

use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::core::{FromJson, ToJson};
use identity_iota::core::Object;
use identity_iota::core::Url;
use identity_iota::credential::Credential;
use identity_iota::credential::CredentialBuilder;
use identity_iota::credential::DecodedJwtCredential;
use identity_iota::credential::FailFast;
use identity_iota::credential::Jwt;
use identity_iota::credential::JwtCredentialValidationOptions;
use identity_iota::credential::JwtCredentialValidatorHybrid;
use identity_iota::credential::Subject;
use identity_iota::credential::Status;
use identity_iota::credential::RevocationBitmapStatus;
use identity_iota::verification::jws::DecodedJws;
use identity_iota::document::verifiable::JwsVerificationOptions;

use identity_iota::iota::rebased::client::IdentityClientReadOnly;

use identity_iota::resolver::Resolver;
use identity_iota::prelude::IotaDID;
use identity_iota::did::DID;

use identity_iota::iota::IotaDocument;
use identity_iota::storage::JwkDocumentExtHybrid;
use identity_iota::storage::JwsSignatureOptions;
use identity_pqc_verifier::PQCJwsVerifier;

use serde_json::json;
use serde_json::Value;

const ISSUER_CFG_DIR_SEGMENTS: [&str; 2] = ["issuer", "cfg"];
const NONCE_TTL_SECS: u64 = 300; // 5 minutos
const PORT: u16 = 9001;

struct IssuerState {
  pub issuer_document: RwLock<IotaDocument>,
  issuer_fragment: Arc<String>,
  issuer_storage: Arc<MemStorage>,
  next_id: AtomicU32,
  nonces: RwLock<HashMap<String, u64>>,
}

pub async fn validate_proof_auth(proof_jws: &str, challenge: &str, holder_doc: &IotaDocument) -> anyhow::Result<()>{
  let verify_opts: JwsVerificationOptions = JwsVerificationOptions::default().nonce(challenge.to_owned());

  let decoded: DecodedJws<'_> = holder_doc
    .as_ref()
    .verify_jws_hybrid(proof_jws,None, &EdDSAJwsVerifier::default(), &PQCJwsVerifier::default(), &verify_opts,)
    .map_err(|e| anyhow::anyhow!("hybrid verify_jws_hybrid failed: {e}"))?;
  
  if decoded.claims.as_ref() != challenge.as_bytes() {
    anyhow::bail!("did-auth claims mismatch");
  }

  Ok(())
}

async fn create_credential(credential_index: u32, num_id: &str, titulacion: &str, holder_document: IotaDocument,
      issuer_document: &IotaDocument, issuer_fragment: &str, issuer_storage: &MemStorage,) -> anyhow::Result<Jwt> {
  
  let cert = get_certificate(num_id, titulacion)?;

  let subject: Subject = Subject::from_json_value(json!({
      "id": holder_document.id().as_str(),
      "certificate": cert
  }))?;

  let service_url = issuer_document.id().to_url().join(REVOCATION_SERVICE)?;
  let status: Status = RevocationBitmapStatus::new(service_url, credential_index).into();

  // Build credential using subject above and issuer.
  let credential: Credential = CredentialBuilder::default()
    .id(Url::parse("https://example.edu/credentials/3732")?)
    .issuer(Url::parse(issuer_document.id().as_str())?)
    .type_("UniversityDegreeCredential")
    .status(status)
    .subject(subject)
    .build()?;

  let credential_jwt: Jwt = issuer_document
    .create_credential_jwt_hybrid(
      &credential,
      issuer_storage,
      issuer_fragment,
      &JwsSignatureOptions::default(),
      None,
    )
    .await?;

  // Validate the credential's signature using the issuer's DID Document, the credential's semantic structure,
  // that the issuance date is not in the future and that the expiration date is not in the past:
  let _decoded: DecodedJwtCredential<Object> = JwtCredentialValidatorHybrid::with_signature_verifiers(
    EdDSAJwsVerifier::default(),
    PQCJwsVerifier::default(),
  )
  .validate::<_, Object>(
    &credential_jwt,
    issuer_document,
    &JwtCredentialValidationOptions::default(),
    FailFast::FirstError,
  ).map_err(|e| anyhow::anyhow!("Credential validation failed: {e}"))?;

  Ok(credential_jwt)
}

async fn get_holder_from_jwt(issuer_document: &IotaDocument, path: &PathBuf,) -> anyhow::Result<IotaDocument> {
  let jwt: Jwt = load_credential(path).await?;

  let decoded: DecodedJwtCredential<Object> =
    JwtCredentialValidatorHybrid::with_signature_verifiers(
      EdDSAJwsVerifier::default(),
      PQCJwsVerifier::default(),
    )
    .validate::<_, Object>(
      &jwt,
      issuer_document,
      &JwtCredentialValidationOptions::default(),
      FailFast::FirstError,
    )
    .map_err(|e| anyhow!("Credential validation failed: {e}"))?;

  let first = decoded
    .credential
    .credential_subject
    .iter()
    .next()
    .ok_or_else(|| anyhow!("credentialSubject is empty"))?;

  let id: &Url = first
    .id
    .as_ref()
    .ok_or_else(|| anyhow!("credentialSubject.id not found"))?;
  
  let holder_did_str = id.as_str().to_string();
  let holder_did = IotaDID::parse(holder_did_str).map_err(|e| anyhow!("invalid holder DID: {e}"))?;

  let read_only: IdentityClientReadOnly = get_read_only_client().await?; // o tu función equivalente
  let mut resolver: Resolver<IotaDocument> = Resolver::new();
  resolver.attach_iota_handler(read_only);

  let holder_doc = resolver.resolve(&holder_did).await
    .context("failed to resolve holder DID document")?;

  Ok(holder_doc)
}

/***************** Servicio API ******************/
#[utoipa::path(
  get,
  path="/did",
  tag="Issuer",
  responses(
    (status=200, description="Found", body=DIDResponse),
    (status=404, description="Not found")
  )
)]
#[get("/did")]
async fn get_did_document(state: web::Data<IssuerState>) -> impl Responder {
  let did_document_json: String = {
    let doc = state.issuer_document.read().await;
    match doc.to_json() {
      Ok(s) => s,
      Err(e) => {return HttpResponse::InternalServerError().body(format!("issuer did_document serialization failed: {e}"));}
    }
  };

  let did_value: serde_json::Value = match serde_json::from_str(&did_document_json) {
    Ok(v) => v,
    Err(e) => return HttpResponse::InternalServerError().body(format!("did_document JSON parse failed: {e}")),
  };

  let pretty: String = match serde_json::to_string_pretty(&did_value) {
    Ok(s) => s,
    Err(e) => return HttpResponse::InternalServerError().body(format!("did_document pretty serialization failed: {e}")),
  };

  HttpResponse::Ok().content_type("application/json; charset=utf-8").body(pretty)
}

#[utoipa::path(
  get,
  path="/auth/nonce",
  tag="Issuer",
  responses((status=200, description="Nonce generated", body=AuthNonceResponse))
)]
#[get("/auth/nonce")]
async fn get_auth_nonce(state: web::Data<IssuerState>) -> impl Responder {
  let challenge: String = generate_challenge();
  let expires: u64 = now_unix() + NONCE_TTL_SECS;

  {
    let mut map = state.nonces.write().await;
    map.insert(challenge.clone(), expires);
  }

  HttpResponse::Ok().json(AuthNonceResponse { challenge, expires })
}

// Petición POST para solicitar una nueva credencial
#[utoipa::path(
  post,
  path="/new_credential/{request}",
  tag="Issuer",
  params(
    ("request" = CredentialKind, Path, description="Tipo de credencial a emitir."),
    ("student_id" = String, Query, description="Identificador del estudiante en la BD (ej: \"100001\").", example="100001"),
    ("degree_requested" = String, Query, description="Titulación solicitada (ej: \"Grado en Ingeniería Informática\").", example="Grado en Ingeniería Informática")
  ),
  request_body=IssueAuthRequest,
  responses(
    (status=201, description="Credential issued", body=CredentialResponse),
    (status=400, description="Invalid request / auth failed"),
    (status=404, description="Unknown student_id")
  )
)]
#[post("/new_credential/{request}")]
async fn post_new_credential(state: web::Data<IssuerState>, request: web::Path<CredentialKind>, params: web::Query<StudentParams>, body: web::Json<IssueAuthRequest>) -> impl Responder {
  let _request: CredentialKind = request.into_inner();

  let holder_doc: IotaDocument = match IotaDocument::from_json(&body.did_document) {
    Ok(d) => d,
    Err(e) => return HttpResponse::BadRequest().body(format!("invalid did_document JSON: {e}")),
  };

  // Comprobar challenge emitido y expiración
  let expires: u64 = {
    let mut map = state.nonces.write().await;
    match map.remove(&body.challenge) {
      Some(exp) => exp,
      None => return HttpResponse::BadRequest().body("invalid or unknown challenge"),
    }
  };

  if now_unix() > expires {
    return HttpResponse::BadRequest().body("challenge expired");
  }

  // Validar DID-auth
  if let Err(e) = validate_proof_auth(&body.proof_jws, body.challenge.as_str(), &holder_doc).await {
    return HttpResponse::BadRequest().body(format!("did-auth failed: {e}"));
  } else {
      println!("Holder's DID document successfully validated: {}", holder_doc.id());
  }

  // Índice único de la credencial creada
  let credential_idx= state.next_id.fetch_add(1, Ordering::Relaxed);
  let id = credential_idx.to_string();
  let ts: u64 = now_unix();

  let student_id: &str = params.student_id.as_str();
  let degree_requested: &str = params.degree_requested.as_str();

  // Comprueba que existe el estudiante
  let exists: bool = match is_student(student_id) {
    Ok(v) => v,
    Err(e) => return HttpResponse::InternalServerError().body(format!("db error checking student_id: {e}")),
  };

  if !exists {
    return HttpResponse::NotFound().body("unknown student_id");
  }

  // Crea la credencial
  let jwt: Jwt = {
    let doc = state.issuer_document.read().await;
    match create_credential(credential_idx, student_id, degree_requested, holder_doc,
            &doc, state.issuer_fragment.as_str(), state.issuer_storage.as_ref()).await {
      Ok(jwt) => jwt,
      Err(e) => {return HttpResponse::InternalServerError().body(format!("credential creation failed: {e}"));}
    }
  };
  
  match store_issuer_credential(credential_idx, &jwt).await {
    Ok(_p) => {
      // Si se almacena correctamente la credencial, actualizamos el índice
      if let Err(e) = write_credential_idx(credential_idx+1).await {
        return HttpResponse::InternalServerError().body(format!("credential stored but failed to update idx: {e}"));
      }
    }
    Err(e) => {
      if let Some(ioe) = e.downcast_ref::<std::io::Error>() {
        if ioe.kind() == std::io::ErrorKind::AlreadyExists {
          return HttpResponse::Conflict().body("credential file already exists");
        }
      }
      return HttpResponse::InternalServerError().body(format!("store failed: {e}"));
    }
  }

  let credential_decoded: Option<Value> = decode_jwt(jwt.as_str()).ok();

  HttpResponse::Created().json(CredentialResponse { id, credential_jwt: jwt.as_str().to_string(), credential_decoded, created_at: ts })
}

// Petición para revocar una nueva credencial
#[utoipa::path(
  post,
  path="/revoke_credential/{index}",
  tag="Issuer",
  params(("index" = u32, Path, description="Índice de la credencial")),
  request_body = IssueAuthRequest,
  responses(
    (status=200, description="Credential revoked"),
    (status=400, description="Revocation failed")
  )
)]
#[post("/revoke_credential/{index}")]
async fn post_revoke_credential(state: web::Data<IssuerState>, index: web::Path<u32>, body: web::Json<IssueAuthRequest>) -> impl Responder {
  let index: u32 = index.into_inner();

  // Comprobar que existe el fichero de credencial
  let cred_path = match issuer_credential_file_path(index) {
    Ok(p) => p,
    Err(e) => return HttpResponse::InternalServerError().body(format!("path error: {e}")),
  };

  if fs::metadata(&cred_path).await.is_err() {
    return HttpResponse::NotFound().body("credential not found");
  }

  // Extraer holder del jwt almacenado
  let issuer_doc = {
    let doc = state.issuer_document.read().await;
    doc.clone()
  };
  
  let holder_doc = match get_holder_from_jwt(&issuer_doc, &cred_path).await {
    Ok(d) => d,
    Err(e) => {return HttpResponse::InternalServerError().body(format!("get_holder_from_jwt failed: {e}"));}
  };

  // Comprobar challenge emitido y expiración
  let expires: u64 = {
    let mut map = state.nonces.write().await;
    match map.remove(&body.challenge) {
      Some(exp) => exp,
      None => return HttpResponse::BadRequest().body("invalid or unknown challenge"),
    }
  };

  if now_unix() > expires {
    return HttpResponse::BadRequest().body("challenge expired");
  }

  // Validar DID-auth
  if let Err(e) = validate_proof_auth(&body.proof_jws, body.challenge.as_str(), &holder_doc).await {
    return HttpResponse::BadRequest().body(format!("did-auth failed: {e}"));
  } else {
      println!("Holder's DID document successfully validated: {}", holder_doc.id());
  }

  // Revocar 
  let mut doc = state.issuer_document.write().await;

  if let Err(e) = doc.revoke_credentials(REVOCATION_SERVICE, &[index]) {
    return HttpResponse::BadRequest().body(format!("revocation failed: {e}"));
  }

  // Actualizar DID
  let path = match get_dir(ISSUER_CFG_DIR_SEGMENTS) {
    Ok(p) => p,
    Err(e) => {return HttpResponse::InternalServerError().body(format!("get_dir failed: {e}"));}
  };

  let cfg = match get_signer_config(state.issuer_storage.as_ref(), &path).await {
    Ok(c) => c,
    Err(e) => {return HttpResponse::InternalServerError().body(format!("get_signer_config failed: {e}"));}
  };

  let updated = match update_did_document(doc.clone(), state.issuer_storage.as_ref(), &cfg).await {
    Ok(d) => d,
    Err(e) => return HttpResponse::InternalServerError().body(format!("publish update failed: {e}")),
  };

  // Persistir en state
  *doc = updated;

  if let Err(e) = fs::remove_file(&cred_path).await {
    eprintln!("revoked but could not delete file {:?}: {}", cred_path, e);
  }
  
  HttpResponse::Ok().finish()
}

#[derive(OpenApi)]
#[openapi(
  paths(get_did_document, get_auth_nonce, post_new_credential, post_revoke_credential),
  components(schemas(DIDResponse, AuthNonceResponse, CredentialResponse)),
  tags((name="Issuer", description="Issuer service (9001)"))
)]
struct IssuerApiDoc;

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
  let path = get_dir(ISSUER_CFG_DIR_SEGMENTS)?;
  let (issuer_document, issuer_fragment, issuer_storage, issuer_cfg) = create_client_rebuilable(&path).await?;
  let issuer_document = add_revocation_service(&issuer_document, &issuer_storage, &issuer_cfg).await?;

  let state = web::Data::new(IssuerState {
    issuer_document: RwLock::new(issuer_document),
    issuer_fragment: Arc::new(issuer_fragment),
    issuer_storage: Arc::new(issuer_storage),
    next_id: AtomicU32::new(get_last_credential_idx().await?),
    nonces: RwLock::new(HashMap::new()),
  });

  HttpServer::new(move || {
    App::new()
      .app_data(state.clone())
      .service(
        SwaggerUi::new("/issuer/{_:.*}")
          .url("/api-docs/openapi.json", IssuerApiDoc::openapi()),
      )
      .service(get_did_document)
      .service(get_auth_nonce)
      .service(post_new_credential)
      .service(post_revoke_credential)
  })
  .bind(("127.0.0.1", PORT))?
  .run()
  .await?;

  Ok(())
}
