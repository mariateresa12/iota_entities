use actix_web::{post, web, App, HttpResponse, HttpServer, Responder};
use reqwest::Client;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use entities::utils::{generate_challenge, get_read_only_client};
use entities::utils::{PresentationRequest, PresentationResponse, VerifyRequest, VerifyResponse, CredentialKind};

use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::core::{Duration, Object, Timestamp, ToJson};
use identity_iota::credential::DecodedJwtCredential;
use identity_iota::credential::DecodedJwtPresentation;
use identity_iota::credential::FailFast;
use identity_iota::credential::Jwt;
use identity_iota::credential::JwtCredentialValidationOptions;
use identity_iota::credential::JwtCredentialValidatorHybrid;
use identity_iota::credential::JwtCredentialValidatorUtils;
use identity_iota::credential::JwtPresentationValidationOptions;
use identity_iota::credential::JwtPresentationValidatorHybrid;
use identity_iota::credential::JwtPresentationValidatorUtils;
use identity_iota::credential::SubjectHolderRelationship;
use identity_iota::credential::Presentation;
use identity_iota::did::CoreDID;
use identity_iota::did::DID;
use identity_iota::document::verifiable::JwsVerificationOptions;
use identity_iota::iota::rebased::client::{IdentityClientReadOnly};
use identity_iota::iota::IotaDocument;
use identity_iota::resolver::Resolver;
use identity_pqc_verifier::PQCJwsVerifier;

use serde::Deserialize;
use std::collections::HashMap;


const PORT: u16 = 9003;
const HOLDER_BASE_URL: &str = "http://127.0.0.1:9002";

struct VerifierState {
  http: Client,
  verifier_client: IdentityClientReadOnly,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
struct ExpirationQuery {
  #[serde(default = "default_expiration_minutes")]
  expiration_minutes: u32,
}

// Tiempo por defecto de expiración de la solicitud
fn default_expiration_minutes() -> u32 { 10 }

async fn verify_presentation(presentation_jwt: Jwt, challenge: &str, verifier_client: &IdentityClientReadOnly) -> anyhow::Result<Presentation<Jwt>> {
  // The verifier wants the following requirements to be satisfied:
  // - JWT verification of the presentation (including checking the requested challenge to mitigate replay attacks)
  // - JWT verification of the credentials.
  // - The presentation holder must always be the subject, regardless of the presence of the nonTransferable property
  // - The issuance date must not be in the future.
  
  let presentation_verifier_options: JwsVerificationOptions = JwsVerificationOptions::default().nonce(challenge.to_owned());

  let mut resolver: Resolver<IotaDocument> = Resolver::new();
  resolver.attach_iota_handler(verifier_client.clone());

  // Resolve the holder's document.
  let holder_did: CoreDID = JwtPresentationValidatorUtils::extract_holder(&presentation_jwt)?;
  let holder: IotaDocument = resolver.resolve(&holder_did).await?;

  // Validate presentation. Note that this doesn't validate the included credentials.
  let presentation_validation_options: JwtPresentationValidationOptions =
    JwtPresentationValidationOptions::default().presentation_verifier_options(presentation_verifier_options);

  let presentation: DecodedJwtPresentation<Jwt> =
    JwtPresentationValidatorHybrid::with_signature_verifiers(EdDSAJwsVerifier::default(), PQCJwsVerifier::default())
      .validate(&presentation_jwt, &holder, &presentation_validation_options)?;

  // Concurrently resolve the issuers' documents.
  let jwt_credentials: &Vec<Jwt> = &presentation.presentation.verifiable_credential;
  let issuers: Vec<CoreDID> = jwt_credentials
    .iter()
    .map(JwtCredentialValidatorUtils::extract_issuer_from_jwt)
    .collect::<Result<Vec<CoreDID>, _>>()?;

  let issuers_documents: HashMap<CoreDID, IotaDocument> = resolver.resolve_multiple(&issuers).await?;

  // Validate the credentials in the presentation.
  let credential_validator =
    JwtCredentialValidatorHybrid::with_signature_verifiers(EdDSAJwsVerifier::default(), PQCJwsVerifier::default());

  let validation_options: JwtCredentialValidationOptions = JwtCredentialValidationOptions::default()
    .subject_holder_relationship(holder_did.to_url().into(), SubjectHolderRelationship::AlwaysSubject);

  for (index, jwt_vc) in jwt_credentials.iter().enumerate() {
    let issuer_document: &IotaDocument = &issuers_documents[&issuers[index]];
    let _decoded_credential: DecodedJwtCredential<Object> =
      credential_validator.validate::<_, Object>(jwt_vc, issuer_document, &validation_options, FailFast::FirstError)?;
  }

  Ok(presentation.presentation)
}

/***************** Servicio API ******************/

#[utoipa::path(
  post,
  path="/request_presentation/{request}",
  tag="Verifier",
  params(("request" = CredentialKind, Path, description="Credential type"), ExpirationQuery),
  responses((status=200, description="Verification result", body=VerifyResponse))
)]
#[post("/request_presentation/{request}")]
async fn post_request_presentation(state: web::Data<VerifierState>, request: web::Path<CredentialKind>, query: web::Query<ExpirationQuery>) -> impl Responder {
  let request: CredentialKind = request.into_inner();
  let expiration_minutes: u32 = query.expiration_minutes;

  let challenge: String = generate_challenge();

  let expires: Timestamp = match Timestamp::now_utc().checked_add(Duration::minutes(expiration_minutes)) {
    Some(t) => t,
    None => {
      return HttpResponse::Ok().json(VerifyResponse {
        verified: false,
        challenge,
        presentation_jwt: None,
        presentation_decoded: None,
        error: Some("Could not compute expires".to_string()),
      })
    }
  };

  let pres_req = PresentationRequest { request: request.as_str().to_string(), expires, challenge: challenge.clone() };
  let url = format!("{}/presentations/{}", HOLDER_BASE_URL, request.as_str());

  let resp = match state.http.post(url).json(&pres_req).send().await {
    Ok(r) => r,
    Err(e) => {
      return HttpResponse::Ok().json(VerifyResponse {
        verified: false,
        challenge,
        presentation_jwt: None,
        presentation_decoded: None,
        error: Some(format!("holder request failed: {e}")),
      })
    }
  };

  if !resp.status().is_success() {
    let status = resp.status();
    let txt = resp.text().await.unwrap_or_default();
    return HttpResponse::Ok().json(VerifyResponse {
      verified: false,
      challenge,
      presentation_jwt: None,
      presentation_decoded: None,
      error: Some(format!("holder error {}: {}", status, txt)),
    });
  }

  let pres: PresentationResponse = match resp.json().await {
    Ok(p) => p,
    Err(e) => {
      return HttpResponse::Ok().json(VerifyResponse {
        verified: false,
        challenge,
        presentation_jwt: None,
        presentation_decoded: None,
        error: Some(format!("holder response parse failed: {e}")),
      })
    }
  };

  let jwt = Jwt::new(pres.presentation_jwt.clone());

  let decoded = match verify_presentation(jwt, challenge.as_str(), &state.verifier_client).await {
  Ok(presentation) => presentation,
  Err(e) => {
    return HttpResponse::Ok().json(VerifyResponse {
      verified: false,
      challenge,
      presentation_jwt: Some(pres.presentation_jwt),
      presentation_decoded: None,
      error: Some(format!("verification failed: {e}")),
    })
  }
};

let decoded_json: String = match decoded.to_json() {
  Ok(s) => s,
  Err(e) => {
    return HttpResponse::Ok().json(VerifyResponse {
      verified: false,
      challenge,
      presentation_jwt: Some(pres.presentation_jwt),
      presentation_decoded: None,
      error: Some(format!("presentation to_json failed: {e}")),
    })
  }
};

let decoded_value: serde_json::Value = match serde_json::from_str(&decoded_json) {
  Ok(v) => v,
  Err(e) => {
    return HttpResponse::Ok().json(VerifyResponse {
      verified: false,
      challenge,
      presentation_jwt: Some(pres.presentation_jwt),
      presentation_decoded: None,
      error: Some(format!("presentation JSON parse failed: {e}")),
    })
  }
};

  HttpResponse::Ok().json(VerifyResponse { verified: true, challenge, presentation_jwt: Some(pres.presentation_jwt), presentation_decoded: Some(decoded_value), error: None })
}

#[derive(OpenApi)]
#[openapi(
  paths(post_request_presentation),
  components(schemas(CredentialKind, VerifyRequest, VerifyResponse)),
  tags((name="Verifier", description="Verifier service (9003)"))
)]
struct VerifierApiDoc;

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
  let verifier_client = get_read_only_client().await?;

  let state = web::Data::new(VerifierState { http: Client::new(), verifier_client });

  HttpServer::new(move || {
    App::new()
      .app_data(state.clone())
      .service(SwaggerUi::new("/verifier/{_:.*}").url("/api-docs/openapi.json", VerifierApiDoc::openapi()))
      .service(post_request_presentation)
  })
  .bind(("127.0.0.1", PORT))?
  .run()
  .await?;

  Ok(())
}
