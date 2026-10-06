import { NvdError } from '../nvd/client.js';
import type { NvdClient } from '../nvd/client.js';
import { isCveId } from '../nvd/validation.js';
import type { RemediationRegistration, RemediationStore } from './store.js';

type ErrorCode = 'INVALID_CVE_ID' | 'CVE_NOT_FOUND' | 'CVE_REJECTED';
const messages: Record<ErrorCode, string> = {
  INVALID_CVE_ID: 'El ID debe tener formato CVE-AAAA-NNNN',
  CVE_NOT_FOUND: 'El CVE no existe en NVD',
  CVE_REJECTED: 'No se puede registrar una remediación para un CVE rechazado',
};

export class RemediationError extends Error {
  constructor(readonly code: ErrorCode) {
    super(messages[code]);
    this.name = 'RemediationError';
  }
}

export class RemediationService {
  readonly #store: RemediationStore;
  readonly #client: Pick<NvdClient, 'getCve'>;

  constructor(store: RemediationStore, client: Pick<NvdClient, 'getCve'>) {
    this.#store = store;
    this.#client = client;
  }

  async register(cveId: string, options: { signal?: AbortSignal } = {}): Promise<RemediationRegistration> {
    if (!isCveId(cveId)) throw new RemediationError('INVALID_CVE_ID');
    if (options.signal?.aborted) throw new NvdError('CANCELLED');

    const existing = this.#store.get(cveId);
    if (existing !== undefined) return { created: false, remediation: existing };

    // getCve valida la respuesta y devuelve null solo cuando NVD no tiene resultados.
    const cve = await this.#client.getCve(cveId, options);
    if (options.signal?.aborted) throw new NvdError('CANCELLED');
    if (cve === null) throw new RemediationError('CVE_NOT_FOUND');
    if (cve.vulnStatus === 'Rejected') throw new RemediationError('CVE_REJECTED');

    // La comprobación final del store evita duplicados tras consultas concurrentes.
    return this.#store.register(cveId);
  }
}
