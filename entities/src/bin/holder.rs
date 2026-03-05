use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use reqwest::Client;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use serde_json::Value;

use std::sync::Arc;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, anyhow};
use rand::rngs::OsRng;
use rand::RngCore;

use tokio::io::{AsyncWriteExt};
use tokio::fs;

use entities::utils::{append_index_entry, get_dir, created_at_from_folder_name, decode_jwt, now_unix, create_client, read_credential_jwt,
                      load_latest_credential};
use entities::utils::MemStorage;
use entities::utils::{CredentialResponse, PresentationRequest, PresentationResponse, DIDResponse, CredentialKind, IssueAuthRequest, 
                      AuthNonceResponse, StudentParams, RevocationResponse};
use entities::utils::CREDENTIAL_DIR_SEGMENTS;
use entities::pdf::generate_pdf;

use identity_iota::core::{ToJson};
use identity_iota::core::{Duration,Timestamp};
use identity_iota::credential::Jwt;
use identity_iota::credential::JwtPresentationOptions;
use identity_iota::credential::Presentation;
use identity_iota::credential::PresentationBuilder;
use identity_iota::credential::Jws;
use identity_iota::did::DID;
use identity_iota::iota::IotaDocument;
use identity_iota::storage::JwkDocumentExtHybrid;
use identity_iota::storage::JwsSignatureOptions;

const PORT: u16 = 9002;
const ISSUER_BASE_URL: &str = "http://127.0.0.1:9001";

struct HolderState {
  holder_document: Arc<IotaDocument>,
  holder_fragment: Arc<String>,
  holder_storage: Arc<MemStorage>,
  http: Client,

  next_pres_id: AtomicU64,
}

async fn list_credentials_from_fs(base_dir: &Path) -> anyhow::Result<Vec<CredentialResponse>> {
  let mut out: Vec<CredentialResponse> = Vec::new();

  let mut rd = match fs::read_dir(base_dir).await {
    Ok(r) => r,
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out), // si no existe la carpeta, lista vacía
    Err(e) => return Err(e.into()),
  };

  while let Some(entry) = rd.next_entry().await? {
    let file_type = entry.file_type().await?;
    if !file_type.is_dir() {
      continue;
    }

    let folder_name = entry.file_name().to_string_lossy().to_string();
    let dir_path = entry.path();

    // Lee el JWT almacenado
    let jwt = match read_credential_jwt(&dir_path).await {
      Ok(s) => s,
      Err(_) => continue, // si la carpeta no contiene credential.jwt, la ignoramos
    };

    let credential_decoded: Option<Value> = decode_jwt(jwt.as_str()).ok();
    let created_at: u64 = created_at_from_folder_name(&folder_name);

    out.push(CredentialResponse {
      id: folder_name.clone(),
      credential_jwt: jwt,
      credential_decoded,
      created_at,
    });
  }

  out.sort_by_key(|x| x.created_at);
  Ok(out)
}

async fn store_credential(id: &str, credential_jwt: &Jwt, ts:u64) -> anyhow::Result<PathBuf> {
  let base_dir: PathBuf = get_dir(CREDENTIAL_DIR_SEGMENTS)?;
  fs::create_dir_all(&base_dir).await?;

  let dir_path: PathBuf = loop {
    let rand_u32: u32 = OsRng.next_u32();
    let folder_name: String = format!("idx{}_ts{}_r{:08x}", id, ts, rand_u32);
    let candidate: PathBuf = base_dir.join(folder_name);

    match fs::create_dir(&candidate).await {
      Ok(_) => break candidate,
      Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
      Err(e) => return Err(e).with_context(|| format!("The folder {:?} could not be created", candidate)),
    }
  };

  let jwt_path: PathBuf = dir_path.join("credential.jwt");
  let mut jwt_file = fs::OpenOptions::new()
    .write(true)
    .create_new(true)
    .open(&jwt_path)
    .await?;

  jwt_file.write_all(credential_jwt.as_str().as_bytes()).await?;
  jwt_file.write_all(b"\n").await?;
  jwt_file.flush().await?;

  Ok(dir_path)
}

async fn create_proof_auth(did_document: &IotaDocument, fragment: &str, storage: &MemStorage, challenge: &str) -> anyhow::Result<Jws> {
  let opts: JwsSignatureOptions = JwsSignatureOptions::default().nonce(challenge.to_owned());

  // Firma el payload (expiración)
  let jws: Jws = did_document
    .create_jws(storage, fragment, challenge.as_bytes(), &opts)
    .await
    .map_err(|e| anyhow::anyhow!("hybrid create_jws failed: {e}"))?;

  Ok(jws)
}

async fn create_presentation(did_document: &IotaDocument, fragment: &str, storage: &MemStorage, credential_type: &str, challenge: &str, expires: Timestamp,) -> anyhow::Result<Jwt> {
  let (_dir, credential_jwt) = load_latest_credential(credential_type).await?;

  let presentation: Presentation<Jwt> =
    PresentationBuilder::new(did_document.id().to_url().into(), Default::default())
      .credential(credential_jwt)
      .build()?;

  let presentation_jwt: Jwt = did_document
    .create_presentation_jwt_hybrid(
      &presentation,
      storage,
      fragment,
      &JwsSignatureOptions::default().nonce(challenge.to_owned()),
      &JwtPresentationOptions::default().expiration_date(expires),
    )
    .await?;

  Ok(presentation_jwt)
}

pub async fn store_pdf(dir: &Path, jwt: &str, pdf_id: String, ts: u64) -> anyhow::Result<PathBuf> {
  // Decodificar header + payload del JWT
  let decoded: serde_json::Value = decode_jwt(jwt).context("decode_jwt failed")?;

  let header = decoded
    .get(0)
    .ok_or_else(|| anyhow!("decode_jwt returned invalid format (missing header)"))?;
  
  let payload = decoded
    .get(1)
    .ok_or_else(|| anyhow!("decode_jwt returned invalid format (missing payload)"))?;

  // Extraer alg / kid / issuer DID
  let alg: String = header
    .get("alg")
    .and_then(|v| v.as_str())
    .unwrap_or("EdDSA")
    .to_string();

  let kid: String = header
    .get("kid")
    .and_then(|v| v.as_str())
    .unwrap_or("")
    .to_string();

  let issuer_did: String = payload
    .get("iss")
    .and_then(|v| v.as_str())
    .unwrap_or("")
    .to_string();

  if issuer_did.is_empty() {
    return Err(anyhow!("JWT payload does not contain 'iss' (issuer DID)"));
  }

  // JSON para el PDF
  let cert = payload
    .get("vc")
    .and_then(|vc| vc.get("credentialSubject"))
    .and_then(|cs| cs.get("certificate"))
    .cloned()
    .ok_or_else(|| anyhow!("certificate not found in JWT payload"))?;

  let json_str: String = serde_json::to_string(&cert).context("serialize certificate failed")?;

  // Path del PDF
  let out_pdf: PathBuf = dir.join(format!("set_{}.pdf", pdf_id));

  // Generación en thread blocking
  let dir_cl = dir.to_path_buf();
  let out_pdf_cl = out_pdf.clone();

  let jwt_cl = jwt.to_string();
  let issuer_did_cl = issuer_did.clone();
  let kid_cl = kid.clone();
  let alg_cl = alg.clone();
  let pdf_id_cl = pdf_id.clone();
  let json_str_cl = json_str.clone();

  web::block(move || {
    std::fs::create_dir_all(&dir_cl).ok();

    generate_pdf(&json_str_cl, out_pdf_cl.to_str().context("invalid out_pdf path")?, &jwt_cl,
      &issuer_did_cl, &kid_cl, &alg_cl, &pdf_id_cl, ts)}).await.map_err(|e| anyhow!("blocking task failed: {e}"))??;

  Ok(out_pdf)
}

/***************** Servicio API ******************/
#[utoipa::path(
  get,
  path="/did",
  tag="Holder",
  responses(
    (status=200, description="Found", body=DIDResponse),
    (status=404, description="Not found")
  )
)]
#[get("/did")]
async fn get_did_document(state: web::Data<HolderState>) -> impl Responder {
  let did_document_json: String = match state.holder_document.to_json() {
    Ok(s) => s,
    Err(e) => return HttpResponse::InternalServerError().body(format!("holder did_document serialization failed: {e}")),
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
  post,
  path="/new_credential/{request}",
  tag="Holder",
  params(
    ("request" = CredentialKind, Path, description="Tipo de credencial a emitir."),
    ("student_id" = String, Query, description="Identificador del estudiante en la BD (ej: \"100001\").", example="100001"),
    ("degree_requested" = String, Query, description="Titulación solicitada (ej: \"Grado en Ingeniería Informática\").", example="Grado en Ingeniería Informática")
  ),
  responses(
    (status=201, description="Credential requested from issuer and stored", body=CredentialResponse),
    (status=502, description="Issuer not available / error"),
    (status=400, description="Invalid request")
  )
)]
#[post("/new_credential/{request}")]
async fn post_new_credential(state: web::Data<HolderState>, request: web::Path<CredentialKind>, params: web::Query<StudentParams>) -> impl Responder {
  let request: CredentialKind = request.into_inner();

  // Pedir nonce al issuer
  let nonce_url = format!("{}/auth/nonce", ISSUER_BASE_URL);
  let nonce_resp = match state.http.get(nonce_url).send().await {
    Ok(r) => r,
    Err(e) => return HttpResponse::BadGateway().body(format!("issuer nonce request failed: {e}")),
  };

  if !nonce_resp.status().is_success() {
    let status = nonce_resp.status();
    let txt = nonce_resp.text().await.unwrap_or_default();
    return HttpResponse::BadGateway().body(format!("issuer nonce error {}: {}", status, txt));
  }

  let nonce: AuthNonceResponse = match nonce_resp.json().await {
    Ok(v) => v,
    Err(e) => return HttpResponse::BadGateway().body(format!("issuer nonce parse failed: {e}")),
  };

  // Crear VP DID-auth con nonce
  let _expires: Timestamp = match Timestamp::now_utc().checked_add(Duration::minutes(5)) {
    Some(t) => t,
    None => return HttpResponse::InternalServerError().body("Could not compute auth expires"),
  };

  let did_document_json: String = match state.holder_document.to_json() {
    Ok(s) => s,
    Err(e) => return HttpResponse::InternalServerError().body(format!("holder did_document serialization failed: {e}")),
  };

  let proof_auth: Jws = match create_proof_auth(state.holder_document.as_ref(), state.holder_fragment.as_str(), state.holder_storage.as_ref(), nonce.challenge.as_str()).await {
    Ok(vp) => vp,
    Err(e) => return HttpResponse::InternalServerError().body(format!("did-auth creation failed: {e}")),
  };

  // Enviar solicitud autenticada al issuer
  let issue = IssueAuthRequest { did_document: did_document_json, challenge: nonce.challenge.clone(), proof_jws: proof_auth.as_str().to_string()};

  let url = format!(
    "{}/new_credential/{}?student_id={}&degree_requested={}",
    ISSUER_BASE_URL,
    request.as_str(),
    urlencoding::encode(params.student_id.as_str()),
    urlencoding::encode(params.degree_requested.as_str())
  );
  
  let resp = match state.http.post(url).json(&issue).send().await {
    Ok(r) => r,
    Err(e) => return HttpResponse::BadGateway().body(format!("issuer request failed: {e}")),
  };

  if !resp.status().is_success() {
    let status = resp.status();
    let txt = resp.text().await.unwrap_or_default();
    return HttpResponse::BadGateway().body(format!("issuer error {}: {}", status, txt));
  }

  let cred: CredentialResponse = match resp.json().await {
    Ok(c) => c,
    Err(e) => return HttpResponse::BadGateway().body(format!("issuer response parse failed: {e}")),
  };

  // Guardar JWT en disco
  let jwt = Jwt::new(cred.credential_jwt.clone());
  let ts = cred.created_at;
  let dir = match store_credential(cred.id.as_str(), &jwt, ts.clone()).await {
    Ok(p) => p,
    Err(e) => return HttpResponse::InternalServerError().body(format!("store_credential failed: {e}")),
  };

  if let Err(e) = append_index_entry(&dir, request.as_str()).await {
    return HttpResponse::InternalServerError().body(format!("append_index_entry failed: {e}"));
  }

  // Generar y almacenar pdf
let pdf_id: String = Path::new(&dir).file_name().and_then(|s| s.to_str()).unwrap_or("set_pdf").to_string();

let _pdf_path = match store_pdf(dir.as_path(),cred.credential_jwt.as_str(),pdf_id, ts).await {
  Ok(p) => p,
  Err(e) => return HttpResponse::InternalServerError().body(format!("store_pdf failed: {e}")),
};

  HttpResponse::Created().json(cred)
}

#[utoipa::path(
  post,
  path="/revoke_credential/{index}",
  tag="Holder",
  params(("index" = u32, Path, description="Índice de la credencial")),
  responses(
    (status=200, description="Credential revoked", body=RevocationResponse),
    (status=400, description="Revocation failed"),
    (status=404, description="Not found"),
    (status=502, description="Issuer not available / error")
  )
)]
#[post("/revoke_credential/{index}")]
async fn post_revoke_credential(state: web::Data<HolderState>, index: web::Path<u32>) -> impl Responder {
  // Pedir nonce al issuer
  let nonce_url = format!("{}/auth/nonce", ISSUER_BASE_URL);
  let nonce_resp = match state.http.get(nonce_url).send().await {
    Ok(r) => r,
    Err(e) => return HttpResponse::BadGateway().body(format!("issuer nonce request failed: {e}")),
  };

  if !nonce_resp.status().is_success() {
    let status = nonce_resp.status();
    let txt = nonce_resp.text().await.unwrap_or_default();
    return HttpResponse::BadGateway().body(format!("issuer nonce error {}: {}", status, txt));
  }

  let nonce: AuthNonceResponse = match nonce_resp.json().await {
    Ok(v) => v,
    Err(e) => return HttpResponse::BadGateway().body(format!("issuer nonce parse failed: {e}")),
  };

  // Crear VP DID-auth con nonce
  let _expires: Timestamp = match Timestamp::now_utc().checked_add(Duration::minutes(5)) {
    Some(t) => t,
    None => return HttpResponse::InternalServerError().body("Could not compute auth expires"),
  };

  let did_document_json: String = match state.holder_document.to_json() {
    Ok(s) => s,
    Err(e) => return HttpResponse::InternalServerError().body(format!("holder did_document serialization failed: {e}")),
  };

  let proof_auth: Jws = match create_proof_auth(state.holder_document.as_ref(), state.holder_fragment.as_str(), state.holder_storage.as_ref(), nonce.challenge.as_str()).await {
    Ok(vp) => vp,
    Err(e) => return HttpResponse::InternalServerError().body(format!("did-auth creation failed: {e}")),
  };

  // Enviar solicitud autenticada al issuer
  let issue = IssueAuthRequest { did_document: did_document_json, challenge: nonce.challenge.clone(), proof_jws: proof_auth.as_str().to_string()};
  
  let index: u32 = index.into_inner();

  // Enviar solicitud al issuer
  let revocation_url = format!("{}/revoke_credential/{}", ISSUER_BASE_URL, index);
  let resp = match state.http.post(revocation_url).json(&issue).send().await {
    Ok(r) => r,
    Err(e) => return HttpResponse::BadGateway().body(format!("issuer revocation request failed: {e}")),
  };

  if !resp.status().is_success() {
    let status = resp.status();
    let txt = resp.text().await.unwrap_or_default();

    if status == reqwest::StatusCode::NOT_FOUND {
      return HttpResponse::NotFound().body(txt);
    }
    if status == reqwest::StatusCode::BAD_REQUEST {
      return HttpResponse::BadRequest().body(txt);
    }
    return HttpResponse::BadGateway().body(format!("issuer revocation error {}: {}", status, txt));
  }

  HttpResponse::Ok().json(RevocationResponse { revoked: true, index })
}

#[utoipa::path(
  get,
  path="/credentials",
  tag="Holder",
  responses((status=200, description="Listed", body=[CredentialResponse]))
)]
#[get("/credentials")]
async fn get_credentials(_state: web::Data<HolderState>) -> impl Responder {
  let base_dir: PathBuf = match get_dir(CREDENTIAL_DIR_SEGMENTS) {
    Ok(p) => p,
    Err(e) => return HttpResponse::InternalServerError().body(format!("get_base_dir failed: {e}")),
  };

  let items = match list_credentials_from_fs(&base_dir).await {
    Ok(v) => v,
    Err(e) => return HttpResponse::InternalServerError().body(format!("list_credentials_from_fs failed: {e}")),
  };

  HttpResponse::Ok().json(items)
}

#[utoipa::path(
  get,
  path="/credential/{id}",
  tag="Holder",
  responses(
    (status=200, description="Found", body=CredentialResponse),
    (status=404, description="Not found")
  )
)]
#[get("/credential/{id}")]
async fn get_credential_by_id(_state: web::Data<HolderState>, id: web::Path<String>) -> impl Responder {
  let id: String = id.into_inner();

  // Evitar path traversal (no permitir subpaths)
  if id.contains("..") || id.contains('/') || id.contains('\\') {
    return HttpResponse::BadRequest().body("invalid id");
  }

  let base_dir: PathBuf = match get_dir(CREDENTIAL_DIR_SEGMENTS) {
    Ok(p) => p,
    Err(e) => return HttpResponse::InternalServerError().body(format!("get_base_dir failed: {e}")),
  };

  let dir_path: PathBuf = base_dir.join(&id);

  // Lee el JWT almacenado
  let jwt = match read_credential_jwt(&dir_path).await {
    Ok(s) => s,
    Err(e) if e.downcast_ref::<std::io::Error>().map(|ioe| ioe.kind()) == Some(std::io::ErrorKind::NotFound) => {
      return HttpResponse::NotFound().finish();
    }
    Err(_) => return HttpResponse::NotFound().finish(),
  };

  let credential_decoded: Option<Value> = decode_jwt(jwt.as_str()).ok();
  let created_at = created_at_from_folder_name(&id);

  HttpResponse::Ok().json(CredentialResponse {id: id.clone(), credential_jwt: jwt, credential_decoded, created_at,})
}

#[utoipa::path(
  post,
  path="/presentations/{request}",
  tag="Holder",
  params(("request" = CredentialKind, Path, description="Credential type")),
  request_body=PresentationRequest,
  responses(
    (status=201, description="Presentation eissued", body=PresentationResponse),
    (status=400, description="Invalid request")
  )
)]
#[post("/presentations/{request}")]
async fn post_presentations(state: web::Data<HolderState>, request: web::Path<CredentialKind>, body: web::Json<PresentationRequest>) -> impl Responder {
  let request : CredentialKind = request.into_inner();
  if request.as_str() != "Certificate" {
    return HttpResponse::BadRequest().body("request must be 'Certificate'");
  }

  let pres_id: String = state.next_pres_id.fetch_add(1, Ordering::Relaxed).to_string();
  let ts: u64 = now_unix();

  // Crea la presentación
  let jwt: Jwt = match create_presentation(
    state.holder_document.as_ref(),
    state.holder_fragment.as_str(),
    state.holder_storage.as_ref(),
    request.clone().as_str(),
    body.challenge.as_str(),
    body.expires,
  )
  .await
  {
    Ok(jwt) => jwt,
    Err(e) => return HttpResponse::BadRequest().body(format!("create_presentation failed: {e}")),
  };

  HttpResponse::Created().json(PresentationResponse {
    id: pres_id,
    presentation_jwt: jwt.as_str().to_string(),
    created_at: ts,
  })
}

#[derive(OpenApi)]
#[openapi(
  paths(get_did_document, post_new_credential, post_revoke_credential, get_credentials, get_credential_by_id, post_presentations),
  components(schemas(DIDResponse, CredentialKind, CredentialResponse, RevocationResponse, PresentationResponse)),
  tags((name="Holder", description="Holder service (9002)"))
)]
struct HolderApiDoc;

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
  let (holder_document, holder_fragment, holder_storage) = create_client().await?;

  let state = web::Data::new(HolderState {
    holder_document: Arc::new(holder_document),
    holder_fragment: Arc::new(holder_fragment),
    holder_storage: Arc::new(holder_storage),
    http: Client::new(),
    next_pres_id: AtomicU64::new(1),
  });

  HttpServer::new(move || {
    App::new()
      .app_data(state.clone())
      .service(
        SwaggerUi::new("/holder/{_:.*}")
          .url("/api-docs/openapi.json", HolderApiDoc::openapi()),
      )
      .service(get_did_document)
      .service(post_new_credential)
      .service(post_revoke_credential)
      .service(get_credentials)
      .service(get_credential_by_id)
      .service(post_presentations)
  })
  .bind(("127.0.0.1", PORT))?
  .run()
  .await?;

  Ok(())
}