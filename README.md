# IOTA entities

## Instrucciones de ejecución

### Iniciar local network

- **Sin persistencia** 
```bash
RUST_LOG="off,iota_node=info" iota start --force-regenesis --with-faucet
```
- **Con persistencia**
```bash
iota start --network.config persisted-localnet --with-faucet --committee-size 2 --epoch-duration-ms 60000
```

### Antes de ejecutar
1. **Conseguir tokens/coins** 
```bash
iota client faucet
```
2. **Subir paquete IOTA Identity a la blockchain**
```bash
./identity_iota_core/scripts/publish_identity_package.sh
```
3. **Exportar ID de paquete (en todas las terminales)** 
```bash
export IOTA_IDENTITY_PKG_ID=<id_packet>
```
El `<id_packet>` se corresponde con el devuelto en el comando anterior.

### Ejecutar entidades
**ADVERTENCIA:** En la primera ejecución tardará unos minutos en compilar y se generarán archivos con un tamaño total de aprox. **30GB**.

**Nota:** Eliminar archivo `~/issuer/cfg` entre ejecuciones.

Dentro de `entities/`, ejecutar:
- `cargo run --bin issuer`
- `cargo run --bin holder`
- `cargo run --bin verifier`

## Base de datos
El código hace uso de una base de datos **SQLite**. En `entities/data` se incluye un fichero `.db` con datos de ejemplo.

## Dependencias
Para la ejecución correcta, se necesita tener instalados los siguientes paquetes:
- `wkhtmltopdf` 
- `qpdf`
