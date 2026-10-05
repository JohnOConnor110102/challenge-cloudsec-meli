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

Ambos devuelven HTTP `200` con `{"status":"ok"}`.

| Ruta                | Significado en esta entrega                             |
| ------------------- | ------------------------------------------------------- |
| `GET /health/live`  | El proceso responde solicitudes HTTP                    |
| `GET /health/ready` | Fastify completó su inicialización y acepta solicitudes |

Todavía no hay DB ni sincronización: el cliente NVD está disponible, pero los health checks no consultan al proveedor. Los endpoints no devuelven configuración ni credenciales. Durante el cierre, Fastify deja de aceptar nuevas solicitudes y espera las que están en curso.

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

El cliente en [src/nvd/client.ts](src/nvd/client.ts) consulta la API CVE 2.0 mediante `fetch` de Node, sin dependencias adicionales. En esta entrega se puede usar desde código; todavía no se incorpora a las rutas HTTP ni inicia una sincronización al arrancar el servidor.

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

[CveCatalog](src/sync/catalog.ts) guarda un registro por ID con sus fechas, estado y clasificación. Cada carga reemplaza el registro anterior y recalcula su severidad; conserva también CVEs sin score y rechazados. Las consultas devuelven copias. El catálogo inicia vacío y se pierde al reiniciar; la carga desde NVD y los checkpoints se incorporarán en el siguiente incremento.

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

El próximo incremento es la carga paginada de NVD con progreso y reanudación en memoria, seguido de la integración al inicio del servidor. Después se incorporarán los endpoints y luego persistencia. Autenticación/autorización, Docker, despliegue e infraestructura cloud continúan pendientes.
