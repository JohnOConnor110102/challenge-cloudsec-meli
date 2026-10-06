import { loadConfig } from '../config.js';
import { openDatabase } from './pool.js';

async function main(): Promise<void> {
  const pool = await openDatabase(loadConfig().database, () => {
    console.error('Se perdió una conexión PostgreSQL inactiva');
  });
  try {
    console.log('Conexión PostgreSQL de Node verificada con cve_app y esquema disponible.');
  } finally {
    await pool.end();
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : 'Falló la verificación PostgreSQL');
  process.exitCode = 1;
});
