import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmod, lstat, mkdir, readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../', import.meta.url));
const secretDirectory = new URL('../../.secrets/', import.meta.url);

async function secret(name: string): Promise<string> {
  const file = new URL(name, secretDirectory);
  try {
    await writeFile(file, `${randomBytes(32).toString('hex')}\n`, { flag: 'wx', mode: 0o600 });
  } catch (error) {
    if (!(error instanceof Error) || !('code' in error) || error.code !== 'EEXIST') throw error;
  }
  const info = await lstat(file);
  if (!info.isFile() || info.isSymbolicLink()) throw new Error('Archivo de secreto inválido');
  await chmod(file, 0o600);
  const value = (await readFile(file, 'utf8')).trim();
  if (!/^[a-f0-9]{64}$/.test(value)) throw new Error('Contenido del secreto inválido');
  return value;
}

async function main(): Promise<void> {
  const command = process.argv[2] ?? 'up';
  if (command === 'migrate' || command === 'test') {
    // Los secretos montados conservan permisos 600 y el propietario del host.
    const user = `${process.getuid?.() ?? 1000}:${process.getgid?.() ?? 1000}`;
    execFileSync('docker', ['compose', 'run', '--rm', '--user', user,
      command === 'migrate' ? 'migrate' : 'db-check'], {
      cwd: root, stdio: 'inherit', timeout: 120_000,
    });
    return;
  }
  if (command === 'stop') {
    execFileSync('docker', ['compose', 'stop', 'db'], { cwd: root, stdio: 'inherit', timeout: 60_000 });
    return;
  }
  if (command !== 'up') throw new Error('Comando PostgreSQL inválido');

  await mkdir(secretDirectory, { recursive: true, mode: 0o700 });
  const directory = await lstat(secretDirectory);
  if (!directory.isDirectory() || directory.isSymbolicLink()) throw new Error('Directorio de secretos inválido');
  await chmod(secretDirectory, 0o700);
  const admin = await secret('db_admin_password');
  const migrator = await secret('db_migrator_password');
  const app = await secret('db_app_password');

  execFileSync('docker', ['compose', 'up', '--detach', '--wait', '--wait-timeout', '60', 'db'], {
    cwd: root, stdio: 'inherit', timeout: 90_000,
  });
  // Solo bootstrap local: enviar las claves por stdin, sin argumentos ni logs.
  // Los valores son hexadecimales generados y validados arriba.
  execFileSync('docker', ['compose', 'exec', '-T', '--user', '0', 'db', 'psql', '-X', '--username', 'postgres',
    '--dbname', 'cves', '--set', 'ON_ERROR_STOP=1'], {
    cwd: root, timeout: 10_000,
    input: `BEGIN;
SET LOCAL log_statement = 'none';
SET LOCAL log_min_error_statement = 'panic';
ALTER ROLE postgres PASSWORD '${admin}';
ALTER ROLE cve_migrator LOGIN PASSWORD '${migrator}';
ALTER ROLE cve_app LOGIN PASSWORD '${app}';
COMMIT;`,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  console.log('PostgreSQL local listo; credenciales en .secrets con permisos 600.');
}

main().catch(() => {
  console.error('Falló el comando PostgreSQL local. Revisá Docker, los secretos locales, el puerto y las migraciones.');
  process.exitCode = 1;
});
