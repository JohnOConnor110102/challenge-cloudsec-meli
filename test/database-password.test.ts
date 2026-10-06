import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { readDatabasePassword } from '../src/db/pool.js';

test('lee la contraseña de un archivo privado sin conservar el salto de línea', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'meli-db-password-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const file = join(directory, 'password');
  const password = randomBytes(32).toString('hex');
  await writeFile(file, `${password}\n`, { mode: 0o600 });
  assert.equal(await readDatabasePassword(file), password);
  await chmod(file, 0o400);
  assert.equal(await readDatabasePassword(file), password);
});

test('rechaza archivos inexistentes, compartidos o inválidos sin exponer su ruta ni contenido', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'meli-db-password-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const file = join(directory, 'private-path');
  const message = 'DB_PASSWORD_FILE debe contener una contraseña válida en un archivo privado y legible';
  await assert.rejects(readDatabasePassword(file), { message });
  await assert.rejects(readDatabasePassword(directory), { message });
  for (const value of ['', 'short', 'x'.repeat(4097), 'x'.repeat(257), 'x'.repeat(32) + '\n\n', 'x'.repeat(32) + '\0']) {
    await writeFile(file, value, { mode: 0o600 });
    await assert.rejects(readDatabasePassword(file), { message });
  }
  if (process.platform !== 'win32') {
    await writeFile(file, randomBytes(32).toString('hex'));
    await chmod(file, 0o640);
    await assert.rejects(readDatabasePassword(file), { message });
    await chmod(file, 0o644);
    await assert.rejects(readDatabasePassword(file), { message });
  }
});
