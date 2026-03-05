use sqlite::{Connection, State};
use anyhow::{Result, anyhow};

const DATABASE: &str = "data/universidad.db";

pub fn is_student(id: &str) -> sqlite::Result<bool> {
  let connection = Connection::open(DATABASE)?;

  let query = r#"
      SELECT EXISTS(
        SELECT 1 FROM estudiantes WHERE num_identificacion = ?
      ) AS exist;
  "#;

  let mut st = connection.prepare(query)?;
  st.bind((1, id))?;

  match st.next()? {
      State::Row => {
          let exist: i64  = st.read("exist")?;
          Ok(exist == 1)
      }
      State::Done => Ok(false),
  }
}

pub fn get_certificate(student_id: &str, degree: &str) -> Result<serde_json::Value> {
  let connection = Connection::open(DATABASE)?;

  let query = r#"
  SELECT json_object(
    'datos_identificativos_del_titulado', json_object(
      'apellidos', e.apellidos,
      'nombre', e.nombre,
      'fecha_nacimiento', e.nacimiento,
      'numero_identificacion', e.num_identificacion
    ),
    'informacion_de_la_titulacion', json_object(
      'nombre_titulacion', t.nombre,
      'nombre_institucion', t.institucion
    ),
    'informacion_sobre_el_nivel_de_la_titulacion', json_object(
      'nivel_titulacion', t.nivel,
      'duracion_oficial', t.duracion_anyos,
      'ects_global', (
        SELECT CAST(SUM(a.ects) AS INTEGER)
        FROM asignaturas a
        WHERE a.titulacion = t.titulacion_id
      )
    ),
    'informacion_sobre_el_contenido_y_los_resultados_obtenidos', json_object(
      'modalidad', t.modalidad,
      'descripcion_programa', json_object(
        'fecha_fin', ex.fecha_fin,
        'asignaturas', (
          SELECT json_group_array(
            json_object(
              'nombre', a.nombre,
              'tipo', a.tipo,
              'ects', a.ects,
              'calificacion', c.calificacion,
              'anyo_academico', c.anyo_academico,
              'observaciones', c.observaciones
            )
          )
          FROM calificaciones c
          JOIN asignaturas a ON a.asignatura_id = c.asignatura_id
          WHERE c.expediente_id = ex.expediente_id
          ORDER BY c.anyo_academico, a.nombre
        )
      ),
      'calificacion_global', (
        SELECT ROUND(SUM(c.calificacion * a.ects) * 1.0 / SUM(a.ects), 2)
        FROM calificaciones c
        JOIN asignaturas a ON a.asignatura_id = c.asignatura_id
        WHERE c.expediente_id = ex.expediente_id
      )
    )
  ) AS titulo_universitario_json
  FROM estudiantes e
  JOIN expedientes ex ON ex.estudiante_id = e.estudiante_id
  JOIN titulaciones t ON t.titulacion_id = ex.titulacion_id
  WHERE e.num_identificacion = ?
    AND t.nombre = ?
  LIMIT 1;
  "#;

  let mut statement = connection.prepare(query)?;

  statement.bind((1, student_id))?;
  statement.bind((2, degree))?;

  match statement.next()? {
      State::Row => {
          let json: String = statement.read::<String, _>("titulo_universitario_json")?;

          let cert: serde_json::Value = serde_json::from_str(&json)?;
          // println!("{}", serde_json::to_string_pretty(&cert)?);

          Ok(cert)
      }
      State::Done => Err(anyhow!("Student or titulation not found.")),
  }
}