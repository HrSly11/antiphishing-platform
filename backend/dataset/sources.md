# Fuentes de Datos Públicas y Trazabilidad del Dataset

## 1. Fuentes Seleccionadas

### A. PhishTank Community Verified Feed
- **Proveedor**: Cisco Talos / OpenDNS / PhishTank.
- **Licencia**: PhishTank Developer License (Uso no comercial y de seguridad defensiva, requiere atribución).
- **Formato**: CSV / JSON diario.
- **Campos del Esquema**:
  - `phish_id` (Integer): Identificador único de PhishTank.
  - `url` (String): URL sospechosa/confirmada.
  - `phish_detail_url` (String): Enlace al análisis forense en PhishTank.
  - `submission_time` (Timestamp ISO 8601): Fecha de reporte.
  - `verified` (Boolean): Si la comunidad validó que es phishing activo.
  - `verification_time` (Timestamp): Fecha de confirmación.
  - `online` (Boolean): Si el sitio atacante continúa activo al momento del feed.
  - `target` (String): Marca o institución bancaria suplantada.

### B. OpenPhish Community Feed
- **Proveedor**: OpenPhish Threat Intelligence.
- **Licencia**: OpenPhish Terms of Service (Libre para operaciones de seguridad interna e investigación académica).
- **Formato**: TXT plano (una URL por línea), actualizado cada 6 horas.
- **Tamaño Promedio**: ~2,000 a 8,000 URLs activas concurrentes.

---

## 2. Pipeline de Ingesta y Versionado ETL

```mermaid
flowchart LR
    A["Download Feed (HTTPS)"] --> B["URL Parsing & Normalization"]
    B --> C["SHA-256 Hash Computation"]
    C --> D["Deduplication against Redis"]
    D --> E["Batch Insert into PostgreSQL"]
    E --> F["Register in dataset_versions"]
```

1. **Extracción**: Descarga periódica mediante worker asíncrono o webhook n8n con verificación de integridad de canal TLS.
2. **Transformación**:
   - Normalización de esquema (`http://` vs `https://`).
   - Remoción de fragmentos `#` y parámetros de tracking (e.g. `utm_*`).
   - Cálculo del `url_hash = SHA256(normalized_url)`.
3. **Carga**:
   - Inserción en tabla `phishing_samples` con cláusula `ON CONFLICT (url_hash) DO NOTHING`.
   - Actualización de conjunto Set en Redis para consulta O(1) en el pipeline en tiempo real.
4. **Versionado Inmutable**:
   - Cada ejecución genera un registro en `dataset_versions` con el hash SHA-256 del archivo de origen crudo, número de registros procesados, número de duplicados descartados y usuario/proceso ejecutor.
