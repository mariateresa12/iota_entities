use serde::{Deserialize, Serialize};
use anyhow::{anyhow, Context, Result};
use image::Luma;
use printpdf::{
  BuiltinFont, Line, LinePoint, Mm, Op, ParsedFont, PdfDocument, PdfFontHandle, PdfPage,
  PdfSaveOptions, PdfWarnMsg, Point, Pt, RawImage, TextItem, TextMatrix, XObjectId,
  XObjectTransform,
};
use qrcode::QrCode;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use chrono::{DateTime, Utc};
use unicode_normalization::UnicodeNormalization;

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

const PAGE_W: f32 = 210.0;
const PAGE_H: f32 = 297.0;
const CONTENT_LEFT: f32 = 24.0;
const CONTENT_TOP: f32 = 282.0;
const CONTENT_BOTTOM: f32 = 34.0;

fn draw_line(ops: &mut Vec<Op>, x1: f32, y1: f32, x2: f32, y2: f32) {
  let line = Line {
    points: vec![
      LinePoint {
        p: Point::new(Mm(x1), Mm(y1)),
        bezier: false,
      },
      LinePoint {
        p: Point::new(Mm(x2), Mm(y2)),
        bezier: false,
      },
    ],
    is_closed: false,
  };
  ops.push(Op::DrawLine { line });
}

fn try_load_unicode_font(doc: &mut PdfDocument) -> Option<PdfFontHandle> {
  let candidates = [
    "data/fonts/NotoSans-Regular.ttf",
    "data/fonts/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
    "C:/Windows/Fonts/arial.ttf",
  ];

  for path in candidates {
    if let Ok(bytes) = fs::read(path) {
      let mut warnings = Vec::new();
      if let Some(parsed) = ParsedFont::from_bytes(&bytes, 0, &mut warnings) {
        let font_id = doc.add_font(&parsed);
        return Some(PdfFontHandle::External(font_id));
      }
    }
  }

  None
}

fn write_text_with_font(
  ops: &mut Vec<Op>,
  text: &str,
  size: f32,
  x: f32,
  y: f32,
  font: &PdfFontHandle,
) {
  // Normalize to NFC so decomposed accents render correctly.
  let normalized: String = text.nfc().collect();
  ops.push(Op::StartTextSection);
  ops.push(Op::SetFont {
    font: font.clone(),
    size: Pt(size),
  });
  ops.push(Op::SetTextCursor {
    pos: Point::new(Mm(x), Mm(y)),
  });
  ops.push(Op::ShowText {
    items: vec![TextItem::Text(normalized)],
  });
  ops.push(Op::EndTextSection);
}

fn wrap_text(text: &str, max_chars: usize) -> Vec<String> {
  let mut out = Vec::new();
  let mut line = String::new();

  for word in text.split_whitespace() {
    let candidate_len = if line.is_empty() {
      word.len()
    } else {
      line.len() + 1 + word.len()
    };

    if candidate_len > max_chars && !line.is_empty() {
      out.push(line);
      line = word.to_string();
    } else {
      if !line.is_empty() {
        line.push(' ');
      }
      line.push_str(word);
    }
  }

  if !line.is_empty() {
    out.push(line);
  }

  if out.is_empty() {
    out.push(String::new());
  }

  out
}

fn fit_text(text: &str, max_chars: usize) -> String {
  let trimmed = text.trim();
  if trimmed.chars().count() <= max_chars {
    return trimmed.to_string();
  }

  let mut out = String::new();
  for (i, ch) in trimmed.chars().enumerate() {
    if i + 1 >= max_chars.saturating_sub(1) {
      out.push('…');
      break;
    }
    out.push(ch);
  }
  out
}

fn draw_footer(
  ops: &mut Vec<Op>,
  font_regular: &PdfFontHandle,
  font_bold: &PdfFontHandle,
  font_mono: &PdfFontHandle,
  qr_image_id: Option<&XObjectId>,
  qr_label: &str,
  pdf_id: &str,
  codificacion: &str,
) {
  draw_line(ops, 12.0, 24.0, PAGE_W - 12.0, 24.0);

  if let Some(id) = qr_image_id {
    ops.push(Op::UseXobject {
      id: id.clone(),
      transform: XObjectTransform {
        translate_x: Some(Mm(14.0).into()),
        translate_y: Some(Mm(5.0).into()),
        rotate: None,
        scale_x: None,
        scale_y: None,
        dpi: Some(254.0),
      },
    });
  }

  write_text_with_font(ops, qr_label, 8.0, 12.5, 2.6, font_regular);

  write_text_with_font(ops, "identificador:", 7.0, 70.0, 16.0, font_bold);
  write_text_with_font(ops, pdf_id, 6.0, 102.0, 16.0, font_mono);

  write_text_with_font(ops, "codificación:", 7.0, 70.0, 9.5, font_bold);
  let cod_lines = wrap_text(codificacion, 72);
  let mut y = 9.5_f32;
  for line in cod_lines {
    write_text_with_font(ops, &line, 6.0, 102.0, y, font_mono);
    y -= 3.2;
    if y < 2.5 {
      break;
    }
  }
}

fn draw_left_sidebar(
  ops: &mut Vec<Op>,
  font_mono: &PdfFontHandle,
  issuer_did: &str,
  kid: &str,
  alg: &str,
  date: &str,
) {
  let lines = [
    format!("Emisor: {}", issuer_did),
    format!("Método: {}", kid),
    format!("Alg: {}", alg),
    format!("Fecha de creación: {}", date),
  ];

  let mut x = 7.0_f32;
  for text in lines {
    ops.push(Op::StartTextSection);
    ops.push(Op::SetFont {
      font: font_mono.clone(),
      size: Pt(6.2),
    });
    ops.push(Op::SetTextMatrix {
      matrix: TextMatrix::TranslateRotate(Mm(x).into(), Mm(30.0).into(), 90.0),
    });
    ops.push(Op::ShowText {
      items: vec![TextItem::Text(fit_text(&text, 250).nfc().collect())],
    });
    ops.push(Op::EndTextSection);

    x += 2.8;
  }
}

fn draw_logo(ops: &mut Vec<Op>, logo_image_id: Option<&XObjectId>) {
  if let Some(id) = logo_image_id {
    ops.push(Op::UseXobject {
      id: id.clone(),
      transform: XObjectTransform {
        translate_x: Some(Mm(174.0).into()),
        translate_y: Some(Mm(266.0).into()),
        rotate: None,
        scale_x: Some(0.20),
        scale_y: Some(0.20),
        dpi: Some(320.0),
      },
    });
  }
}

fn draw_table_header(ops: &mut Vec<Op>, font_bold: &PdfFontHandle, y: &mut f32) {
  let x = [CONTENT_LEFT, 86.0, 108.0, 122.0, 140.0, 160.0, PAGE_W - 12.0];
  let y_top = *y;
  let y_bot = *y - 6.0;

  for yy in [y_top, y_bot] {
    draw_line(ops, x[0], yy, x[6], yy);
  }

  for xpos in x {
    draw_line(ops, xpos, y_top, xpos, y_bot);
  }

  write_text_with_font(ops, "Asignatura", 8.0, 25.0, y_top - 4.2, font_bold);
  write_text_with_font(ops, "Tipo", 8.0, 88.0, y_top - 4.2, font_bold);
  write_text_with_font(ops, "ECTS", 8.0, 109.0, y_top - 4.2, font_bold);
  write_text_with_font(ops, "Calif.", 8.0, 123.0, y_top - 4.2, font_bold);
  write_text_with_font(ops, "Año", 8.0, 141.0, y_top - 4.2, font_bold);
  write_text_with_font(ops, "Obs.", 8.0, 161.0, y_top - 4.2, font_bold);

  *y = y_bot;
}

fn draw_table_row(
  ops: &mut Vec<Op>,
  font_regular: &PdfFontHandle,
  y: &mut f32,
  a: &Asignatura,
) {
  let x = [CONTENT_LEFT, 86.0, 108.0, 122.0, 140.0, 160.0, PAGE_W - 12.0];
  let y_top = *y;
  let y_bot = *y - 6.0;

  draw_line(ops, x[0], y_bot, x[6], y_bot);

  for xpos in x {
    draw_line(ops, xpos, y_top, xpos, y_bot);
  }

  write_text_with_font(ops, &fit_text(&a.nombre, 24), 7.6, 25.0, y_top - 4.1, font_regular);
  write_text_with_font(ops, &fit_text(&a.tipo, 10), 7.6, 88.0, y_top - 4.1, font_regular);
  write_text_with_font(ops, &a.ects.to_string(), 7.6, 110.0, y_top - 4.1, font_regular);
  write_text_with_font(
    ops,
    &format!("{:.2}", a.calificacion),
    7.6,
    123.0,
    y_top - 4.1,
    font_regular,
  );
  write_text_with_font(
    ops,
    &fit_text(&a.anyo_academico, 8),
    7.6,
    141.0,
    y_top - 4.1,
    font_regular,
  );
  write_text_with_font(
    ops,
    &fit_text(a.observaciones.as_deref().unwrap_or(""), 18),
    7.6,
    161.0,
    y_top - 4.1,
    font_regular,
  );

  *y = y_bot;
}

fn draw_section_title(
  ops: &mut Vec<Op>,
  font_bold: &PdfFontHandle,
  y: &mut f32,
  text: &str,
) {
  write_text_with_font(ops, text, 11.0, CONTENT_LEFT, *y, font_bold);
  *y -= 6.5;
}

fn draw_subtitle(
  ops: &mut Vec<Op>,
  font_bold: &PdfFontHandle,
  y: &mut f32,
  text: &str,
) {
  // Mismo tamaño que las etiquetas de campo (ej. "4.2 - Fecha de finalización").
  write_text_with_font(ops, text, 9.2, CONTENT_LEFT, *y, font_bold);
  *y -= 4.8;
}

fn draw_label_value(
  ops: &mut Vec<Op>,
  font_bold: &PdfFontHandle,
  font_regular: &PdfFontHandle,
  y: &mut f32,
  label: &str,
  value: &str,
) {
  write_text_with_font(ops, label, 9.2, CONTENT_LEFT, *y, font_bold);
  *y -= 4.0;
  for line in wrap_text(value, 95) {
    write_text_with_font(ops, &line, 9.2, CONTENT_LEFT + 2.0, *y, font_regular);
    *y -= 4.1;
  }
  *y -= 1.0;
}

fn ensure_space(
  pages: &mut Vec<PdfPage>,
  ops: &mut Vec<Op>,
  y: &mut f32,
  needed: f32,
  font_regular: &PdfFontHandle,
  font_bold: &PdfFontHandle,
  font_mono: &PdfFontHandle,
  qr_image_id: Option<&XObjectId>,
  qr_label: &str,
  pdf_id: &str,
  codificacion: &str,
  issuer_did: &str,
  kid: &str,
  alg: &str,
  date: &str,
) {
  if *y - needed >= CONTENT_BOTTOM {
    return;
  }

  pages.push(PdfPage::new(Mm(PAGE_W), Mm(PAGE_H), std::mem::take(ops)));
  draw_footer(
    ops,
    font_regular,
    font_bold,
    font_mono,
    qr_image_id,
    qr_label,
    pdf_id,
    codificacion,
  );
  draw_left_sidebar(ops, font_mono, issuer_did, kid, alg, date);
  *y = CONTENT_TOP;
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

  let codificacion = format!("{:x}", Sha256::digest(jwt.as_bytes()));
  let qr_content = "http://localhost:3000";
  let qr_label = "http:localhost:3000";

  // Fecha de creación
  let datetime = DateTime::<Utc>::from_timestamp(ts.try_into().unwrap(), 0)
    .ok_or_else(|| anyhow!("invalid timestamp"))?;
  let date = datetime.format("%d-%m-%Y %H:%M:%S").to_string();

  let qr_code = QrCode::new(qr_content.as_bytes()).context("cannot build QR")?;
  let qr_img = qr_code.render::<Luma<u8>>().min_dimensions(180, 180).build();
  let mut qr_png: Vec<u8> = Vec::new();
  {
    let dyn_img = image::DynamicImage::ImageLuma8(qr_img);
    dyn_img
      .write_to(&mut std::io::Cursor::new(&mut qr_png), image::ImageFormat::Png)
      .context("cannot encode QR PNG")?;
  }
  let mut doc = PdfDocument::new("Certificado de Titulación");
  let mut image_warnings = Vec::<PdfWarnMsg>::new();
  let qr_image = RawImage::decode_from_bytes(&qr_png, &mut image_warnings)
    .map_err(|e| anyhow!("cannot decode QR image: {}", e))?;
  let qr_image_id = Some(doc.add_image(&qr_image));
  let logo_image_id = RawImage::decode_from_bytes(LOGO_BYTES, &mut image_warnings)
    .ok()
    .map(|img| doc.add_image(&img));

  let unicode_font = try_load_unicode_font(&mut doc);
  let font_regular = unicode_font
    .clone()
    .unwrap_or(PdfFontHandle::Builtin(BuiltinFont::Helvetica));
  let font_bold = unicode_font
    .clone()
    .unwrap_or(PdfFontHandle::Builtin(BuiltinFont::HelveticaBold));
  let font_mono = unicode_font
    .clone()
    .unwrap_or(PdfFontHandle::Builtin(BuiltinFont::Courier));

  let mut pages: Vec<PdfPage> = Vec::new();
  let mut ops: Vec<Op> = Vec::new();
  draw_footer(
    &mut ops,
    &font_regular,
    &font_bold,
    &font_mono,
    qr_image_id.as_ref(),
    qr_label,
    pdf_id,
    &codificacion,
  );
  draw_left_sidebar(&mut ops, &font_mono, issuer_did, kid, alg, &date);
  draw_logo(&mut ops, logo_image_id.as_ref());

  let mut y = CONTENT_TOP;

  write_text_with_font(&mut ops, "Suplemento Europeo al Título", 16.0, 55.0, y, &font_bold);
  y -= 7.0;
  write_text_with_font(&mut ops, "Diploma Supplement", 12.0, 75.0, y, &font_bold);
  y -= 10.0;

  ensure_space(
    &mut pages,
    &mut ops,
    &mut y,
    40.0,
    &font_regular,
    &font_bold,
    &font_mono,
    qr_image_id.as_ref(),
    qr_label,
    pdf_id,
    &codificacion,
    issuer_did,
    kid,
    alg,
    &date,
  );
  draw_section_title(&mut ops, &font_bold, &mut y, "1 - Datos identificativos del titulado");
  draw_label_value(&mut ops, &font_bold, &font_regular, &mut y, "1.1 - Apellidos", &one.apellidos);
  draw_label_value(&mut ops, &font_bold, &font_regular, &mut y, "1.2 - Nombre(s)", &one.nombre);
  draw_label_value(
    &mut ops,
    &font_bold,
    &font_regular,
    &mut y,
    "1.3 - Fecha de nacimiento",
    &one.fecha_nacimiento,
  );
  draw_label_value(
    &mut ops,
    &font_bold,
    &font_regular,
    &mut y,
    "1.4 - Número de identificación",
    &one.numero_identificacion,
  );

  ensure_space(
    &mut pages,
    &mut ops,
    &mut y,
    28.0,
    &font_regular,
    &font_bold,
    &font_mono,
    qr_image_id.as_ref(),
    qr_label,
    pdf_id,
    &codificacion,
    issuer_did,
    kid,
    alg,
    &date,
  );
  draw_section_title(&mut ops, &font_bold, &mut y, "2 - Información sobre la titulación");
  draw_label_value(
    &mut ops,
    &font_bold,
    &font_regular,
    &mut y,
    "2.1 - Nombre de la titulación",
    &two.nombre_titulacion,
  );
  draw_label_value(
    &mut ops,
    &font_bold,
    &font_regular,
    &mut y,
    "2.2 - Nombre de la institución",
    &two.nombre_institucion,
  );

  ensure_space(
    &mut pages,
    &mut ops,
    &mut y,
    24.0,
    &font_regular,
    &font_bold,
    &font_mono,
    qr_image_id.as_ref(),
    qr_label,
    pdf_id,
    &codificacion,
    issuer_did,
    kid,
    alg,
    &date,
  );
  draw_section_title(
    &mut ops,
    &font_bold,
    &mut y,
    "3 - Información sobre el nivel de la titulación",
  );
  draw_label_value(
    &mut ops,
    &font_bold,
    &font_regular,
    &mut y,
    "3.1 - Nivel de la titulación",
    &format!("Nivel {} del MECES.", three.nivel_titulacion),
  );
  draw_label_value(
    &mut ops,
    &font_bold,
    &font_regular,
    &mut y,
    "3.2 - Duración oficial del programa",
    &format!("{} ECTS. {} años.", three.ects_global, three.duracion_oficial),
  );

  ensure_space(
    &mut pages,
    &mut ops,
    &mut y,
    44.0,
    &font_regular,
    &font_bold,
    &font_mono,
    qr_image_id.as_ref(),
    qr_label,
    pdf_id,
    &codificacion,
    issuer_did,
    kid,
    alg,
    &date,
  );
  draw_section_title(
    &mut ops,
    &font_bold,
    &mut y,
    "4 - Información sobre el contenido y los resultados obtenidos",
  );
  draw_label_value(
    &mut ops,
    &font_bold,
    &font_regular,
    &mut y,
    "4.1 - Modalidad de estudio",
    &four.modalidad,
  );
  draw_label_value(
    &mut ops,
    &font_bold,
    &font_regular,
    &mut y,
    "4.2 - Fecha de finalización",
    &four.descripcion_programa.fecha_fin,
  );

  draw_subtitle(&mut ops, &font_bold, &mut y, "Asignaturas");
  ensure_space(
    &mut pages,
    &mut ops,
    &mut y,
    12.0,
    &font_regular,
    &font_bold,
    &font_mono,
    qr_image_id.as_ref(),
    qr_label,
    pdf_id,
    &codificacion,
    issuer_did,
    kid,
    alg,
    &date,
  );
  draw_table_header(&mut ops, &font_bold, &mut y);

  for a in &four.descripcion_programa.asignaturas {
    ensure_space(
      &mut pages,
      &mut ops,
      &mut y,
      8.0,
      &font_regular,
      &font_bold,
      &font_mono,
      qr_image_id.as_ref(),
      qr_label,
      pdf_id,
      &codificacion,
      issuer_did,
      kid,
      alg,
      &date,
    );

    if y > CONTENT_TOP - 0.1_f32 {
      draw_table_header(&mut ops, &font_bold, &mut y);
    }
    draw_table_row(&mut ops, &font_regular, &mut y, a);
  }

  // Separación extra entre la tabla y el bloque 4.3.
  y -= 6.0;

  ensure_space(
    &mut pages,
    &mut ops,
    &mut y,
    16.0,
    &font_regular,
    &font_bold,
    &font_mono,
    qr_image_id.as_ref(),
    qr_label,
    pdf_id,
    &codificacion,
    issuer_did,
    kid,
    alg,
    &date,
  );
  draw_label_value(
    &mut ops,
    &font_bold,
    &font_regular,
    &mut y,
    "4.3 - Calificación global del titulado",
    &format!("{}", four.calificacion_global),
  );

  pages.push(PdfPage::new(Mm(PAGE_W), Mm(PAGE_H), ops));
  doc.with_pages(pages);

  let out_pdf_path = PathBuf::from(out_pdf);
  let out_dir = out_pdf_path.parent().context("out_pdf has no parent dir")?;
  fs::create_dir_all(out_dir)?;

  let file = File::create(&out_pdf_path).context("cannot create output pdf")?;
  let mut writer = BufWriter::new(file);
  let mut warnings = Vec::<PdfWarnMsg>::new();
  let pdf_bytes = doc.save(&PdfSaveOptions::default(), &mut warnings);
  writer
    .write_all(&pdf_bytes)
    .context("cannot save output pdf")?;

  Ok(())
}