import { isCveId } from '../nvd/validation.js';

export interface Remediation {
  cveId: string;
  registeredAt: string;
}

export interface RemediationRegistration {
  created: boolean;
  remediation: Remediation;
}

export class RemediationStore {
  readonly #records = new Map<string, Remediation>();
  readonly #now: () => Date;

  constructor(now: () => Date = () => new Date()) {
    this.#now = now;
  }

  get size(): number {
    return this.#records.size;
  }

  get(cveId: string): Remediation | undefined {
    const record = this.#records.get(cveId);
    return record === undefined ? undefined : { ...record };
  }

  // El llamador debe comprobar la existencia del CVE antes de registrar.
  register(cveId: string): RemediationRegistration {
    if (!isCveId(cveId)) throw new Error('El ID debe tener formato CVE-AAAA-NNNN');

    const existing = this.#records.get(cveId);
    if (existing !== undefined) return { created: false, remediation: { ...existing } };

    const record: Remediation = { cveId, registeredAt: this.#now().toISOString() };
    // Sin esperas entre comprobar y guardar: un único registro por ID en este proceso.
    this.#records.set(cveId, record);
    return { created: true, remediation: { ...record } };
  }
}
