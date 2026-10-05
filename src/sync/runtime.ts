import type { FastifyInstance } from 'fastify';
import { NvdError } from '../nvd/client.js';
import { InitialSync } from './initial-sync.js';

export function registerSyncRuntime(app: FastifyInstance, sync: InitialSync): void {
  let task: Promise<void> | undefined;
  let timer: ReturnType<typeof setInterval> | undefined;
  let closing = false;

  app.addHook('onListen', async () => {
    if (closing) return;
    task = sync.run();
    app.log.info({ event: 'nvd_sync_started', sync: sync.progress }, 'Iniciando carga NVD');
    timer = setInterval(() => {
      app.log.info({ event: 'nvd_sync_progress', sync: sync.progress }, 'Progreso de carga NVD');
    }, 5_000);
    timer.unref();
    task = task.then(() => {
      app.log.info({ event: 'nvd_sync_finished', sync: sync.progress }, 'Carga NVD finalizada');
    }, (error: unknown) => {
      app.log.error({
        event: 'nvd_sync_failed', sync: sync.progress,
        ...(error instanceof NvdError ? { providerCode: error.code, providerStatus: error.status } : {}),
      }, 'Falló la carga NVD');
    }).finally(() => { clearInterval(timer); });
  });

  app.addHook('preClose', async () => {
    closing = true;
    sync.stop();
    clearInterval(timer);
  });
  app.addHook('onClose', async () => {
    closing = true;
    sync.stop();
    clearInterval(timer);
    await task;
  });
}
