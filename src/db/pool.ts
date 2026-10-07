import { open, readFile } from 'node:fs/promises';
import pg from 'pg';
import type { DatabaseConfig } from './config.js';

export async function readDatabasePassword(file: string): Promise<string> {
  try {
    const handle = await open(file, 'r');
    try {
      const info = await handle.stat();
      if (!info.isFile() || info.size < 1 || info.size > 4096
        || (process.platform !== 'win32' && (info.mode & 0o077) !== 0)) {
        throw new Error('Archivo de secreto inválido');
      }
      const password = (await handle.readFile('utf8')).replace(/\r?\n$/, '');
      if (!/^[\x21-\x7e]{16,256}$/.test(password)) throw new Error('Contenido de secreto inválido');
      return password;
    } finally {
      await handle.close();
    }
  } catch {
    throw new Error('DB_PASSWORD_FILE debe contener una contraseña válida en un archivo privado y legible');
  }
}

export async function openDatabase(config: DatabaseConfig, onIdleError: () => void): Promise<pg.Pool> {
  const password = await readDatabasePassword(config.passwordFile);
  let ca: string | undefined;
  if (config.caFile !== undefined) {
    try {
      ca = await readFile(config.caFile, 'utf8');
      if (ca.trim() === '') throw new Error('CA vacía');
    } catch {
      throw new Error('DB_CA_FILE debe contener un certificado legible');
    }
  }
  const pool = new pg.Pool({
    host: config.host, port: config.port, database: config.name, user: 'cve_app', password,
    ssl: config.tls === 'verify-full' ? { rejectUnauthorized: true, ...(ca === undefined ? {} : { ca }) } : false,
    application_name: 'meli-cloudsec',
    sslnegotiation: 'postgres',
    max: 5,
    connectionTimeoutMillis: 5_000,
    idleTimeoutMillis: 30_000,
    statement_timeout: 10_000,
    query_timeout: 12_000,
    options: '-c search_path=pg_catalog,app -c lock_timeout=5000 -c idle_in_transaction_session_timeout=10000',
  });
  // pg retira el cliente fallido; informar el evento sin pasar errores ni credenciales.
  pool.on('error', () => onIdleError());
  try {
    const result = await pool.query<{ role: string; schema_ready: boolean }>(`
      SELECT current_user AS role,
        to_regclass('app.cves') IS NOT NULL AND to_regclass('app.sync_state') IS NOT NULL
        AND to_regclass('app.remediations') IS NOT NULL AND to_regclass('app.audit_events') IS NOT NULL
        AS schema_ready
    `);
    if (result.rows[0]?.role !== 'cve_app' || result.rows[0]?.schema_ready !== true) {
      throw new Error('Esquema de aplicación no disponible');
    }
    return pool;
  } catch {
    await pool.end().catch(() => {});
    throw new Error('No se pudo conectar PostgreSQL con el usuario y esquema de aplicación');
  }
}
