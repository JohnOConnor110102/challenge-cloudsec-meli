import { isIP } from 'node:net';

export interface DatabaseConfig {
  host: string;
  port: number;
  name: string;
  passwordFile: string;
  tls: 'disable' | 'verify-full';
  caFile: string | undefined;
}

export function loadDatabaseConfig(
  env: NodeJS.ProcessEnv,
  nodeEnv: 'development' | 'test' | 'production',
): DatabaseConfig {
  const host = env.DB_HOST ?? '127.0.0.1';
  const dnsName = host.length <= 253 && host.split('.').every((label) =>
    label.length <= 63 && /^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(label));
  if (isIP(host) === 0 && !dnsName) {
    throw new Error('DB_HOST tiene un valor inválido');
  }
  const rawPort = env.DB_PORT ?? '5432';
  const port = Number(rawPort);
  if (!/^\d+$/.test(rawPort) || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('DB_PORT debe ser un entero entre 1 y 65535');
  }
  const name = env.DB_NAME ?? 'cves';
  if (!/^[a-z][a-z0-9_]{0,62}$/.test(name)) throw new Error('DB_NAME tiene un valor inválido');

  const passwordFile = env.DB_PASSWORD_FILE ?? '.secrets/db_app_password';
  const caFile = env.DB_CA_FILE;
  for (const [variable, value] of [['DB_PASSWORD_FILE', passwordFile], ['DB_CA_FILE', caFile]] as const) {
    if (value !== undefined && (value.trim() === '' || /[\x00-\x1f\x7f]/.test(value))) {
      throw new Error(`${variable} tiene un valor inválido`);
    }
  }
  const local = nodeEnv !== 'production' && (host === '127.0.0.1' || host === '::1');
  const tls = env.DB_TLS ?? (local ? 'disable' : 'verify-full');
  if (tls !== 'disable' && tls !== 'verify-full') throw new Error('DB_TLS tiene un valor inválido');
  if (tls === 'disable' && !local) throw new Error('DB_TLS solo permite disable en loopback de desarrollo o test');
  if (tls === 'disable' && caFile !== undefined) throw new Error('DB_CA_FILE requiere DB_TLS=verify-full');

  return { host, port, name, passwordFile, tls, caFile };
}
