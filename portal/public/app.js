const form = document.getElementById("validation-form");
const message = document.getElementById("result-message");

function showMessage(text, isOk) {
  message.textContent = text;
  message.classList.remove("ok", "error");
  message.classList.add(isOk ? "ok" : "error");
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const identificador = form.identificador.value.trim();
  const codificacion = form.codificacion.value.trim();

  if (!identificador || !codificacion) {
    showMessage("Debe completar identificador y codificacion.", false);
    return;
  }

  try {
    const response = await fetch("/api/validar", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ identificador, codificacion }),
    });

    const result = await response.json();

    if (result.code === "VALID") {
      showMessage("Credencial válida", true);
      return;
    }

    if (result.code === "INVALID_CODE") {
      showMessage("Credencial inválida", false);
      return;
    }

    if (result.code === "NOT_FOUND_OR_REVOKED") {
      showMessage("No existe la credencial o ha sido revocada", false);
      return;
    }

    showMessage(result.message || "No se pudo validar la credencial.", false);
  } catch {
    showMessage("Error de conexion con el servidor de validacion.", false);
  }
});
