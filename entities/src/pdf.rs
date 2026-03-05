use serde::{Deserialize, Serialize};
use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use image::Luma;
use qrcode::QrCode;
use std::{fs, process::Command};
use std::path::{Path, PathBuf};
use chrono::prelude::DateTime;

const LOGO_BYTES: &[u8] = include_bytes!("images/logoUMU.jpg"); 

#[derive(Debug, Deserialize)]
pub struct InputJson {
  pub one: DatosTitulado,
  pub two: InfoTitulacion,
  pub three: NivelTitulacion,
  pub four: ContenidoResultados,
}

// Para mapear tus claves exactas, usa serde(rename)
#[derive(Debug, Deserialize, Serialize)]
pub struct DatosTitulado {
  #[serde(rename = "datos_identificativos_del_titulado")]
  pub d: DatosTituladoInner,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DatosTituladoInner {
  pub apellidos: String,
  pub nombre: String,
  pub fecha_nacimiento: String,
  pub numero_identificacion: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct InfoTitulacion {
  #[serde(rename = "informacion_de_la_titulacion")]
  pub d: InfoTitulacionInner,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct InfoTitulacionInner {
  pub nombre_titulacion: String,
  pub nombre_institucion: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NivelTitulacion {
  #[serde(rename = "informacion_sobre_el_nivel_de_la_titulacion")]
  pub d: NivelTitulacionInner,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NivelTitulacionInner {
  pub nivel_titulacion: i32,
  pub duracion_oficial: i32,
  pub ects_global: i32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ContenidoResultados {
  #[serde(rename = "informacion_sobre_el_contenido_y_los_resultados_obtenidos")]
  pub d: ContenidoResultadosInner,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ContenidoResultadosInner {
  pub modalidad: String,
  pub descripcion_programa: DescripcionPrograma,
  pub calificacion_global: f64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DescripcionPrograma {
  pub fecha_fin: String,
  pub asignaturas: Vec<Asignatura>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Asignatura {
  pub nombre: String,
  pub tipo: String,
  pub ects: i32,
  pub calificacion: f64,
  pub anyo_academico: String,
  pub observaciones: Option<String>,
}

// ------------ Extraer y generar firma ------------
fn jwt_signature_b64url(jwt: &str) -> Result<&str> {
  let mut it = jwt.split('.');
  let _h = it.next().ok_or_else(|| anyhow!("invalid jwt"))?;
  let _p = it.next().ok_or_else(|| anyhow!("invalid jwt"))?;
  let s = it.next().ok_or_else(|| anyhow!("invalid jwt"))?;
  if it.next().is_some() {
    return Err(anyhow!("invalid jwt (too many parts)"));
  }
  Ok(s)
}

// ------------ Generar QR ------------
fn qr_data_uri(qr_content: &str) -> Result<String> {
    let code = QrCode::new(qr_content.as_bytes())?;

  let img = code.render::<Luma<u8>>().min_dimensions(260, 260).build();

  let mut buf: Vec<u8> = Vec::new();
  {
    let dyn_img = image::DynamicImage::ImageLuma8(img);
    dyn_img.write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Png)?;
  }

  let b64 = base64::engine::general_purpose::STANDARD.encode(buf);
  Ok(format!("data:image/png;base64,{}", b64))
}

fn logo_data_uri() -> String {
  let b64 = base64::engine::general_purpose::STANDARD.encode(LOGO_BYTES);
  format!("data:image/jpeg;base64,{}", b64)
}

// ------------ Funciones auxiliares para generar pdf ------------
// --- PDF base ---
fn run_wkhtmltopdf(input_html: &Path, out_pdf: &Path, base_margins: bool) -> Result<()> {
  let mut cmd = Command::new("wkhtmltopdf");

  if base_margins {
    cmd.args([
      "--page-size", "A4",
      "--zoom", "1",
      "--margin-top", "12mm",
      "--margin-bottom", "28mm",  // reserva para footer overlay
      "--margin-left", "12mm",
      "--margin-right", "12mm",
    ]);
  } else {
    // ✅ Overlay: fuerza tamaño exacto en mm (evita que "bottom" suba)
    cmd.args([
      "--page-width", "210mm",
      "--page-height", "297mm",
      "--zoom", "1",
      "--margin-top", "0",
      "--margin-bottom", "0",
      "--margin-left", "0",
      "--margin-right", "0",
      "--no-background",
    ]);
  }

  let status = cmd.arg(input_html).arg(out_pdf).status().context("failed to run wkhtmltopdf")?;

  anyhow::ensure!(status.success(), "wkhtmltopdf failed");
  Ok(())
}

// --- Overlay (firmas, QR, etc.) ---
fn apply_overlay_qpdf(base_pdf: &Path, overlay_pdf: &Path, out_pdf: &Path) -> Result<()> {
  let status = Command::new("qpdf")
    .args([
      base_pdf.to_str().context("invalid base_pdf path")?,
      "--underlay",
      overlay_pdf.to_str().context("invalid overlay_pdf path")?,
      "--repeat=1",
      "--",
      out_pdf.to_str().context("invalid out_pdf path")?,
    ])
    .status()
    .context("failed to run qpdf")?;

  anyhow::ensure!(status.success(), "qpdf overlay failed");
  Ok(())
}

// ------------ Generar pdf a partir del modelo ------------
pub fn generate_pdf(json_str: &str, out_pdf: &str, jwt: &str, issuer_did: &str, kid: &str, alg: &str, pdf_id: &str, ts:u64) -> Result<()> {
  let v: serde_json::Value = serde_json::from_str(json_str).context("invalid certificate JSON")?;
  
  // Bloques del documento
  let one = serde_json::from_value::<DatosTituladoInner>(
    v.get("datos_identificativos_del_titulado")
      .cloned()
      .context("missing datos_identificativos_del_titulado")?,
  )?;
  let two = serde_json::from_value::<InfoTitulacionInner>(
    v.get("informacion_de_la_titulacion")
      .cloned()
      .context("missing informacion_de_la_titulacion")?,
  )?;
  let three = serde_json::from_value::<NivelTitulacionInner>(
    v.get("informacion_sobre_el_nivel_de_la_titulacion")
      .cloned()
      .context("missing informacion_sobre_el_nivel_de_la_titulacion")?,
  )?;
  let four = serde_json::from_value::<ContenidoResultadosInner>(
    v.get("informacion_sobre_el_contenido_y_los_resultados_obtenidos")
      .cloned()
      .context("missing informacion_sobre_el_contenido_y_los_resultados_obtenidos")?,
  )?;

  // Datos VC/JWS 
  let jws_sig_b64url = jwt_signature_b64url(jwt)?.to_string();
  
  let qr_content = format!("pdf_id: {}", pdf_id);
  let qr_data = qr_data_uri(&qr_content)?;

  let mut tera = tera::Tera::default();
  tera.add_raw_template("set.html", include_str!("templates/set.html"))?;
  tera.add_raw_template("overlay.html", include_str!("templates/overlay.html"))?;

  // Logo
  let logo_uri = logo_data_uri();

  // Fecha de creación
  let datetime = DateTime::from_timestamp(ts.try_into().unwrap(), 0).unwrap();
  let date = datetime.format("%d-%m-%Y %H:%M:%S").to_string();

  // Parámetros del HTML
  let mut ctx = tera::Context::new();

  ctx.insert("logo_uri", &logo_uri);

  ctx.insert("pdf_id", pdf_id);

  ctx.insert("one", &one);
  ctx.insert("two", &two);
  ctx.insert("three", &three);
  ctx.insert("four", &four);

  ctx.insert("issuer_did", issuer_did);
  ctx.insert("kid", kid);
  ctx.insert("alg", alg);
  ctx.insert("date", &date);

  ctx.insert("jws_sig_b64url", &jws_sig_b64url);
  ctx.insert("jwt_full", jwt);

  ctx.insert("qr_data_uri", &qr_data);
  ctx.insert("qr_content", &qr_content);


  let set_html = tera.render("set.html", &ctx).map_err(|e| anyhow::anyhow!("render set.html failed:\n{:#?}", e))?;
  let overlay_html = tera.render("overlay.html", &ctx).map_err(|e| anyhow::anyhow!("render overlay.html failed:\n{:#?}", e))?;

  // Escribe archivos temporales en la misma carpeta del PDF final
  let out_pdf_path = PathBuf::from(out_pdf);
  let out_dir = out_pdf_path.parent().context("out_pdf has no parent dir")?.to_path_buf();

  fs::create_dir_all(&out_dir).ok();

  let set_path = out_dir.join("set_base.html");
  let overlay_path = out_dir.join("set_overlay.html");
  let base_pdf = out_dir.join("base.pdf");
  let overlay_pdf = out_dir.join("overlay.pdf");

  fs::write(&set_path, set_html).context("write set_base.html failed")?;
  fs::write(&overlay_path, overlay_html).context("write set_overlay.html failed")?;
  
  // Generar PDFs temporales (base y overlay)
  run_wkhtmltopdf(&set_path, &base_pdf, true)?;
  run_wkhtmltopdf(&overlay_path, &overlay_pdf, false)?;

  // PDF final
  apply_overlay_qpdf(&base_pdf, &overlay_pdf, &out_pdf_path)?;
  
  // Borrar PDFs temporales
 // for p in [&set_path, &overlay_path, &base_pdf, &overlay_pdf] {
 //   let _ = fs::remove_file(p);
 // }

  Ok(())
}