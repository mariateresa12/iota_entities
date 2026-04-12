const express = require("express");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");

const app = express();
const port = process.env.PORT || 3000;

function resolveCredentialsDir(rawDir) {
  if (!rawDir) {
    return path.join(os.homedir(), "issuer", "credentials");
  }

  if (rawDir === "~") {
    return os.homedir();
  }

  if (rawDir.startsWith("~/") || rawDir.startsWith("~\\")) {
    return path.join(os.homedir(), rawDir.slice(2));
  }

  return rawDir;
}

const credentialsDir = resolveCredentialsDir(process.env.CREDENTIALS_DIR || "~/issuer/credentials");

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

function computeFileHash(content) {
  return crypto.createHash("sha256").update(content).digest("hex");
}

function loadCredentialHashByIdentifier(identificadorBuscado) {
  if (!fs.existsSync(credentialsDir)) {
    return null;
  }

  const directPath = path.join(credentialsDir, `${identificadorBuscado}.jwt`);
  if (fs.existsSync(directPath)) {
    try {
      const raw = fs.readFileSync(directPath, "utf8").trim();
      return computeFileHash(raw);
    } catch {
      return null;
    }
  }

  return null;
}

app.post("/api/validar", (req, res) => {
  const identificador = (req.body.identificador || "").toString().trim();
  const codificacion = (req.body.codificacion || "").toString().trim().toLowerCase();

  if (!identificador || !codificacion) {
    return res.status(400).json({
      ok: false,
      message: "Debe completar identificador y codificacion.",
      code: "EMPTY_FIELDS",
    });
  }

  const credentialHash = loadCredentialHashByIdentifier(identificador);

  if (!credentialHash) {
    return res.status(404).json({
      ok: false,
      message: "No existe la credencial o ha sido revocada",
      code: "NOT_FOUND_OR_REVOKED",
    });
  }

  if (credentialHash === codificacion) {
    return res.status(200).json({
      ok: true,
      message: "Credencial válida",
      code: "VALID",
    });
  }

  return res.status(401).json({
    ok: false,
    message: "Credencial inválida",
    code: "INVALID_CODE",
  });
});

app.get("/:identificador", (req, res) => {
  const identificador = (req.params.identificador || "").toString().trim();

  if (!identificador) {
    return res.status(400).json({
      ok: false,
      message: "Identificador requerido",
      code: "MISSING_IDENTIFIER",
    });
  }

  if (!fs.existsSync(credentialsDir)) {
    return res.status(500).json({
      ok: false,
      message: "Directorio de credenciales no disponible",
      code: "CREDENTIALS_DIR_NOT_FOUND",
    });
  }

  const jwtPath = path.join(credentialsDir, `${identificador}.jwt`);

  if (!fs.existsSync(jwtPath)) {
    return res.status(404).json({
      ok: false,
      message: "No existe la credencial",
      code: "CREDENTIAL_NOT_FOUND",
    });
  }

  try {
    const jwtContent = fs.readFileSync(jwtPath, "utf8").trim();
    const codificacion = computeFileHash(jwtContent);
    return res.status(200).json({
      ok: true,
      identificador: identificador,
      jwt: jwtContent,
      codificacion: codificacion,
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      message: "Error al leer la credencial",
      code: "READ_ERROR",
    });
  }
});

app.listen(port, () => {
  console.log(`Portal de verificacion disponible en http://localhost:${port}`);
  console.log(`Leyendo credenciales desde: ${credentialsDir}`);
});
