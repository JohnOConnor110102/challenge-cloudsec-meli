\getenv migration_name MIGRATION_NAME
\getenv migration_path MIGRATION_PATH
\getenv migration_checksum MIGRATION_CHECKSUM
BEGIN;
-- Serializar ejecuciones concurrentes de migraciones en esta base.
SELECT pg_advisory_xact_lock(1749202401);
CREATE TABLE IF NOT EXISTS app.schema_migrations (
  name text PRIMARY KEY,
  checksum text NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT now()
);
SELECT EXISTS (SELECT 1 FROM app.schema_migrations WHERE name = :'migration_name') AS applied \gset
\if :applied
  SELECT checksum = :'migration_checksum' AS unchanged FROM app.schema_migrations WHERE name = :'migration_name' \gset
  \if :unchanged
    \echo Ya aplicada: :migration_name
  \else
    DO $$ BEGIN RAISE EXCEPTION 'Se modificó una migración ya aplicada'; END $$;
  \endif
\else
  SELECT NOT EXISTS (SELECT 1 FROM app.schema_migrations WHERE name > :'migration_name') AS ordered \gset
  \if :ordered
    \i :migration_path
    INSERT INTO app.schema_migrations (name, checksum) VALUES (:'migration_name', :'migration_checksum');
    \echo Aplicada: :migration_name
  \else
    DO $$ BEGIN RAISE EXCEPTION 'Las nuevas migraciones deben agregarse al final'; END $$;
  \endif
\endif
COMMIT;
