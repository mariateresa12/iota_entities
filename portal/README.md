# Portal de verificación de credenciales

Portal web para validar credenciales por identificador y codificación.

## Requisitos

- Node.js 18+

## Ejecución

1. Instalar dependencias:
   npm install

2. Iniciar servidor:
   npm start

3. Abrir en navegador:
   <http://localhost:3000>

## Ubicación de credenciales

Por defecto, el servidor busca credenciales en:

~/issuer/credentials

Se puede cambiar con variable de entorno:

CREDENTIALS_DIR="ruta/deseada" npm start

## Formato de credenciales

Cada credencial debe ser un fichero JWT con nombre [id].jwt dentro de la carpeta indicada.

Ejemplo de archivo: ~/issuer/credentials/ABC123.jwt

El identificador es el propio nombre del fichero (sin extension).
La codificacion no se guarda como campo: se calcula como hash SHA-256 del contenido exacto del fichero.

Ejemplo para obtener la codificacion en PowerShell:

Get-FileHash "$HOME/issuer/credentials/ABC123.jwt" -Algorithm SHA256 | Select-Object -ExpandProperty Hash

Reglas:

- Si el archivo no existe: "No existe la credencial o ha sido revocada"
- Si codificacion coincide: "Credencial válida"
- Si codificacion no coincide: "Credencial inválida"
