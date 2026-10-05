import { isIP } from 'node:net';
import { isNvdApiKey } from './nvd/validation.js';

const nodeEnvironments = ['development', 'test', 'production'] as const;
const logLevels = ['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'] as const;

export interface Config {
  nodeEnv: (typeof nodeEnvironments)[number];
  host: string;
  port: number;
  logLevel: (typeof logLevels)[number];
  nvdApiKey: string | undefined;
}

function enumValue<T extends string>(
  name: string,
  value: string,
  allowed: readonly T[],
): T {
  const found = allowed.find((candidate) => candidate === value);
  if (found === undefined) {
    throw new Error(`${name} tiene un valor inválido`);
  }
  return found;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const host = env.HOST ?? '127.0.0.1';
  if (isIP(host) === 0) {
    throw new Error('HOST debe ser una dirección IPv4 o IPv6');
  }

  const rawPort = env.PORT ?? '3000';
  const port = Number(rawPort);
  if (!/^\d+$/.test(rawPort) || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('PORT debe ser un entero entre 1 y 65535');
  }

  const nvdApiKey = env.NVD_API_KEY;
  if (nvdApiKey !== undefined && !isNvdApiKey(nvdApiKey)) {
    throw new Error('NVD_API_KEY tiene un valor inválido');
  }

  return {
    nodeEnv: enumValue('NODE_ENV', env.NODE_ENV ?? 'development', nodeEnvironments),
    host,
    port,
    logLevel: enumValue('LOG_LEVEL', env.LOG_LEVEL ?? 'info', logLevels),
    nvdApiKey,
  };
}
