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

Todavía no hay DB ni conexión al NVD: readiness no verifica dependencias externas en esta etapa. Los endpoints no devuelven configuración ni credenciales. Durante el cierre, Fastify deja de aceptar nuevas solicitudes y espera las que están en curso.

## Configuración

| Variable    | Valor predeterminado | Validación                                                    |
| ----------- | -------------------- | ------------------------------------------------------------- |
| `NODE_ENV`  | `development`        | `development`, `test` o `production`                          |
| `HOST`      | `127.0.0.1`          | Dirección IPv4 o IPv6 literal                                 |
| `PORT`      | `3000`               | Entero decimal entre 1 y 65535                                |
| `LOG_LEVEL` | `info`               | `fatal`, `error`, `warn`, `info`, `debug`, `trace` o `silent` |

Una configuración inválida impide iniciar el servidor y termina con código `1`. El error identifica la variable sin registrar su valor. Los valores vacíos se consideran inválidos.

`.env.example` contiene únicamente valores de ejemplo. `HOST=0.0.0.0` permite escuchar en todas las interfaces cuando se incorpore Docker; para desarrollo local se utiliza loopback.

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

Los endpoints del challenge, persistencia, autenticación/autorización, Docker, despliegue e infraestructura cloud se incorporarán en las próximas entregas. Esta entrega agrega CI y seguridad a la base del servidor.
