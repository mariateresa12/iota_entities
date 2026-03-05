use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa::IntoParams;
use serde_json::Value;
use identity_iota::core::Timestamp;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DIDResponse {
  // DID Document serializado como JSON (string)
  pub did_document: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuthNonceResponse {
  pub challenge: String,
  pub expires: u64,
}

#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct StudentParams {
  // Identificador del estudiante (ej: "100001")
  pub student_id: String,

  // Titulación solicitada (ej: "Grado en Ingeniería Informática")
  pub degree_requested: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IssueAuthRequest {
  // DID Document del holder (JSON string)
  pub did_document: String,

  // Nonce/challenge recibido del issuer
  pub challenge: String,

  // JWS de DID-Auth (VP)
  pub proof_jws: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CredentialResponse {
  pub id: String,
  pub credential_jwt: String,
  #[schema(value_type = Object)]
  pub credential_decoded: Option<Value>, 
  pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CredentialUpdateRequest {
  pub request: Option<String>,
  pub did_document: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RevocationResponse {
  pub revoked: bool,
  pub index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PresentationRequest {
  // "Certificate"
  pub request: String,

  // Timestamp IOTA (se documenta como string para OpenAPI)
  #[schema(value_type = String)]
  pub expires: Timestamp,

  pub challenge: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PresentationResponse {
  pub id: String,
  pub presentation_jwt: String,
  pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct VerifyRequest {
  // "Certificate"
  pub request: String,

  // por defecto 10
  #[serde(default = "default_expires_minutes")]
  pub expires_minutes: i64,
}

fn default_expires_minutes() -> i64 {
  10
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct VerifyResponse {
  pub verified: bool,
  pub challenge: String,
  pub presentation_jwt: Option<String>,
  #[schema(value_type = Object)]
  pub presentation_decoded: Option<Value>,
  pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub enum CredentialKind {
  Certificate,
}

impl CredentialKind {
  pub fn as_str(&self) -> &'static str {
    match self {
      CredentialKind::Certificate => "Certificate",
    }
  }
}