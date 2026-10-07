import { buildPersistentApp } from './app.js';
import { loadConfig } from './config.js';

async function main() {
  const config = loadConfig();
  const app = await buildPersistentApp(config);

  let closing = false;
  async function shutdown(signal: string) {
    if (closing) return;
    closing = true;
    app.log.info({ signal }, 'Cerrando servidor');
    const deadline = setTimeout(() => {
      app.log.error('Se agotó el tiempo para cerrar el servidor');
      process.exit(1);
    }, 10_000);
    deadline.unref();

    try {
      await app.close();
    } catch {
      app.log.error('No se pudo cerrar el servidor');
      process.exitCode = 1;
    } finally {
      clearTimeout(deadline);
    }
  }

  process.on('SIGINT', () => { void shutdown('SIGINT'); });
  process.on('SIGTERM', () => { void shutdown('SIGTERM'); });

  try {
    await app.listen({ host: config.host, port: config.port });
  } catch (error) {
    await app.close();
    throw error;
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : 'No se pudo iniciar el servidor');
  process.exitCode = 1;
});
