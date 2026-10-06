# Challenge Técnico MELI — Seguridad Cloud

## Ejecutar localmente

Requisitos: **Node.js 24.21.0** y npm. La versión de Node está fijada en `.nvmrc`.

```bash
nvm install
nvm use
```

Instalar y ejecutar en desarrollo:

```bash
npm ci --ignore-scripts
cp .env.example .env
npm run dev
```

`npm run dev` reinicia el servidor cuando cambia el código. `.env` es opcional: si no existe, se utilizan los valores predeterminados. Las variables del entorno tienen prioridad sobre el archivo.

Para ejecutar la versión compilada:

```bash
npm run build
npm start
```

El servidor escucha por defecto en `http://127.0.0.1:3000`. Para detenerlo, usar `Ctrl+C`.

## Probar los health checks

Con el servidor en ejecución:

```bash
curl -i http://127.0.0.1:3000/health/live
curl -i http://127.0.0.1:3000/health/ready
```

`live` devuelve HTTP `200` con `{"status":"ok"}`. `ready` devuelve `503` con `{"status":"not_ready"}` durante la carga o si falla, y `200` cuando se completa.

| Ruta                | Significado en esta entrega          |
| ------------------- | ------------------------------------ |
| `GET /health/live`  | El proceso responde solicitudes HTTP |
| `GET /health/ready` | El catálogo NVD terminó de cargarse  |

La carga NVD comienza en segundo plano al escuchar HTTP. Los health checks consultan el estado local y no hacen solicitudes a NVD. Al cerrar, se cancela la carga y se esperan las solicitudes HTTP en curso.

## Configuración

| Variable      | Valor predeterminado | Validación                                                                                     |
| ------------- | -------------------- | ---------------------------------------------------------------------------------------------- |
| `NODE_ENV`    | `development`        | `development`, `test` o `production`                                                           |
| `HOST`        | `127.0.0.1`          | Dirección IPv4 o IPv6 literal                                                                  |
| `PORT`        | `3000`               | Entero decimal entre 1 y 65535                                                                 |
| `LOG_LEVEL`   | `info`               | `fatal`, `error`, `warn`, `info`, `debug`, `trace` o `silent`                                  |
| `NVD_API_KEY` | Sin key              | Opcional; si está definida, debe contener entre 1 y 256 caracteres ASCII visibles sin espacios |

En una etapa posterior de la implementación, la key NVD se almacenará en AWS Secrets Manager cifrada en reposo con KMS y se recuperará al iniciar el proceso mediante el SDK y el task role de ECS. La variable `NVD_API_KEY` no se escribirá en `.env`, en la imagen Docker ni en logs.

Una configuración inválida impide iniciar el servidor y termina con código `1`. El error identifica la variable sin registrar su valor. Los valores vacíos se consideran inválidos.

`.env.example` contiene únicamente valores de ejemplo. `HOST=0.0.0.0` permite escuchar en todas las interfaces cuando se incorpore Docker; para desarrollo local se utiliza loopback.

## Cliente NVD

El cliente en [src/nvd/client.ts](src/nvd/client.ts) consulta la API CVE 2.0 mediante `fetch` de Node, sin dependencias adicionales, y se utiliza en la carga inicial del servidor. Las consultas aceptan un `AbortSignal` opcional para cancelar solicitudes y esperas.

| Método                                    | Resultado                                                                                          |
| ----------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `getCve(id)`                              | Registro con el ID solicitado o `null` si una respuesta válida no contiene resultados              |
| `getPage({ startIndex, resultsPerPage })` | Una página validada; valores predeterminados: índice `0` y tamaño `2000`                           |
| `pages({ startIndex, resultsPerPage })`   | Iterador asíncrono que obtiene una página por vez y permite detenerse sin descargar las siguientes |

Cada página devuelve `startIndex`, `resultsPerPage`, `totalResults`, `timestamp` y `cves`. Cada CVE conserva `id`, fechas, estado y el objeto `metrics`; los restantes campos del proveedor no se incorporan al modelo local. El cliente conserva las métricas sin interpretarlas; su selección y la clasificación se realizan por separado. Los registros `Rejected` también se conservan y se identifican como excluidos de los futuros resúmenes.

## Clasificación CVSS

La [selección de métricas](src/cvss/selection.ts) prioriza versiones `4.0 → 3.1 → 3.0 → 2.0`, luego NVD y `Primary`; desempata por mayor score, fuente y vector.

[classifyCve](src/cvss/classification.ts) devuelve la severidad y su evaluación (`scored`), `unknown` sin métricas válidas (`unscored`) o `rejected` para excluirlo de los futuros resúmenes. Conserva la escala de cada versión: cero es `none` en v3/v4 y `low` en v2; 9.8 es `critical` en v3/v4 y `high` en v2.

### Probar una consulta

Con Node configurado y dependencias instaladas:

```bash
npm run build
node --env-file-if-exists=.env --input-type=module <<'JS'
import { loadConfig } from './dist/config.js';
import { NvdClient } from './dist/nvd/client.js';
import { classifyCve } from './dist/cvss/classification.js';

const client = new NvdClient({ apiKey: loadConfig().nvdApiKey });
const cve = await client.getCve('CVE-2021-44228');
console.log(cve ? { id: cve.id, status: cve.vulnStatus, classification: classifyCve(cve) } : null);

const page = await client.getPage({ resultsPerPage: 2 });
console.log({ startIndex: page.startIndex, received: page.cves.length, totalResults: page.totalResults });
JS
```

El comando hace dos consultas pequeñas, respetando la pausa, y no descarga el catálogo completo. Para probar sin key, dejar `NVD_API_KEY` sin definir.

## Catálogo en memoria

[CveCatalog](src/sync/catalog.ts) guarda un registro por ID con sus fechas, estado y clasificación. Cada carga reemplaza el registro anterior y recalcula su severidad; conserva también CVEs sin score y rechazados. Las consultas devuelven copias. El catálogo inicia vacío y se pierde al reiniciar.

[RemediationStore](src/remediations/store.ts) guarda en memoria un registro por CVE y su fecha de registro en UTC, generada por el servidor. Repetirlo devuelve el registro original sin cambiar la fecha; las consultas devuelven copias. Los registros se pierden al reiniciar.

[RemediationService](src/remediations/service.ts) valida el ID y consulta NVD antes de cada alta nueva; permite CVEs sin score y rechaza inexistentes o `Rejected` ([criterio CVE](https://www.cve.org/ResourcesSupport/Glossary?activeTerm=glossaryRecord)). Los duplicados devuelven el registro original sin otra consulta. Un fallo del proveedor o cancelación no guarda datos; no se confunde con un CVE inexistente. Comparte los límites y reintentos del cliente NVD y no modifica el catálogo de la sincronización.

`catalog.summary()` calcula los conteos sobre los registros actuales, incluyendo categorías en cero. `total` suma `none`, `low`, `medium`, `high`, `critical` y `unknown`; `excludedRejected` informa los rechazados aparte. El cálculo es local, recorre el catálogo sin copiarlo completo y devuelve un resultado independiente.

`catalog.pendingSummary(id => remediations.has(id))` excluye las remediaciones del catálogo vigente y devuelve `excludedRemediated`; los `Rejected` siguen separados. Remediaciones fuera del catálogo no restan. Se cumple `total = pendientes + remediadas elegibles`, también por severidad, usando la clasificación actual. Recorre los datos una vez sin copiarlos completos.

[InitialSync](src/sync/initial-sync.ts) carga páginas con `run()`, pausa con `stop()` cancelando la consulta o espera y expone el progreso. Guarda checkpoints en memoria; llamadas simultáneas comparten la carga. Si los IDs únicos no coinciden con el total final, falla y el próximo intento recorre desde cero. La carga no representa una instantánea atómica de NVD.

Al iniciar HTTP, [runtime](src/sync/runtime.ts) ejecuta la carga y registra inicio, progreso cada 5 segundos y resultado, sin keys ni detalles crudos del proveedor. Un fallo mantiene `ready` en `503` después de los reintentos del cliente. `SIGINT`/`SIGTERM` cancelan la carga; reiniciar vuelve a cargar desde cero. La descarga completa puede tardar varios minutos por los límites de NVD.

## Resumen total

`GET /api/v1/vulnerabilities/summary` devuelve `200` con `total`, `excludedRejected`, `bySeverity` y `meta` (`syncStatus`, `lastPageTimestamp`) cuando finaliza la carga. La fecha corresponde a la última respuesta NVD, no a una instantánea de todo el catálogo. Antes de completarse devuelve `503` con `error: catalog_not_ready` y `syncStatus` (`idle`, `running`, `paused` o `failed`), sin conteos parciales ni detalles del proveedor. Consulta solo datos locales y utiliza `Cache-Control: no-store`.

```bash
curl -i http://127.0.0.1:3000/api/v1/vulnerabilities/summary
```

`GET /api/v1/vulnerabilities/pending/summary` devuelve el mismo formato, más `excludedRemediated`, con conteos que excluyen las remediaciones elegibles. Se recalcula sobre datos locales en cada consulta; comparte el `503` durante la carga, los metadatos y `Cache-Control: no-store` del resumen total.

```bash
curl -i http://127.0.0.1:3000/api/v1/vulnerabilities/pending/summary
```

## Registrar una remediación

`PUT /api/v1/remediations/:cveId`, sin cuerpo, devuelve `201` con `Location` al crear y `200` al repetir; ambos devuelven `cveId` y `registeredAt` ([semántica PUT](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.4)). Funciona durante la carga inicial. El router limita el ID a 100 caracteres (`414` si se supera); cuerpos se rechazan (límite de lectura: 1 KiB). Devuelve `400` para entradas inválidas, `404` para CVEs inexistentes, `409` para rechazados y `502`/`503`/`504` ante fallos del proveedor; nunca expone errores crudos y utiliza `Cache-Control: no-store`. El plazo total es de 30 segundos, incluyendo cola y reintentos; desconexión o cierre del servidor cancelan la validación. Cada creación emite un log `remediation_registered` con CVE, fecha y `requestId`; los duplicados no repiten ese evento. El registro y la auditoría persistentes siguen pendientes.

```bash
curl -i -X PUT http://127.0.0.1:3000/api/v1/remediations/CVE-2021-44228
```

## Verificación

```bash
npm run typecheck
npm test
npm run build
npm audit --audit-level=high
```

## CI y seguridad

El workflow [CI](.github/workflows/ci.yml) se ejecuta en PRs hacia `main`, pushes a `main`, o manualmente desde Actions.

Los tres jobs se ejecutan en paralelo:

| Check                    | Cobertura                                                                                 | Cuándo falla                                                                 |
| ------------------------ | ----------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `Calidad y dependencias` | Instalación desde el lockfile, tipos, tests, compilación y `npm audit`                    | Error en cualquiera de esas operaciones o vulnerabilidades `high`/`critical` |
| `Secretos`               | Gitleaks sobre todos los commits alcanzables por las referencias obtenidas en el checkout | Se detecta un secreto o falla la herramienta                                 |
| `SAST`                   | Semgrep sobre `src`, `test` y `.github/workflows`                                         | Se detecta un hallazgo o falla el análisis/configuración                     |

## Alcance pendiente

El próximo paso es persistencia. Autenticación/autorización, Docker, despliegue e infraestructura cloud continúan pendientes.
