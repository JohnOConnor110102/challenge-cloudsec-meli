-- Estas pruebas usan la credencial real de aplicación y revierten sus datos.
BEGIN;
DO $$
BEGIN
  IF current_user <> 'cve_app' THEN RAISE EXCEPTION 'La prueba requiere cve_app'; END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user
    AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))
    OR pg_has_role(current_user, 'cve_migrator', 'MEMBER')
    OR has_schema_privilege('app', 'CREATE')
    OR has_schema_privilege('public', 'CREATE')
    OR has_database_privilege(current_database(), 'CREATE')
    OR has_database_privilege(current_database(), 'TEMP')
    OR has_table_privilege('app.schema_migrations', 'SELECT')
    OR has_table_privilege('app.remediations', 'UPDATE')
    OR has_table_privilege('app.remediations', 'DELETE')
    OR has_table_privilege('app.audit_events', 'SELECT')
    OR has_table_privilege('app.audit_events', 'UPDATE')
    OR has_table_privilege('app.audit_events', 'DELETE')
  THEN RAISE EXCEPTION 'La aplicación tiene permisos excesivos'; END IF;

  BEGIN
    CREATE TABLE app.forbidden (id integer);
    RAISE EXCEPTION 'La aplicación pudo crear tablas';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END $$;

INSERT INTO app.cves (id, published, last_modified, vuln_status, classification_status, severity)
VALUES ('CVE-2024-99990001', now(), now(), 'Awaiting Analysis', 'unscored', 'unknown');
UPDATE app.cves SET vuln_status = 'Modified' WHERE id = 'CVE-2024-99990001';
INSERT INTO app.sync_state (id, status, next_start_index, total_results)
VALUES (1, 'paused', 1, 2)
ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status;
INSERT INTO app.remediations (cve_id) VALUES ('CVE-2024-99990002');
INSERT INTO app.audit_events (event, cve_id, request_id)
VALUES ('remediation_registered', 'CVE-2024-99990002', 'c804d24a-98b7-4ab1-a128-f96b5b493b70');

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM app.cves WHERE id = 'CVE-2024-99990001' AND severity = 'unknown')
    OR NOT EXISTS (SELECT 1 FROM app.remediations WHERE cve_id = 'CVE-2024-99990002')
  THEN RAISE EXCEPTION 'No se guardaron los datos'; END IF;

  BEGIN
    INSERT INTO app.remediations (cve_id) VALUES ('CVE-2024-99990002');
    RAISE EXCEPTION 'Se admitió una remediación duplicada';
  EXCEPTION WHEN unique_violation THEN NULL;
  END;
  BEGIN
    INSERT INTO app.cves (id, published, last_modified, vuln_status, classification_status)
    VALUES ('CVE-2024-99990003', now(), now(), 'Analyzed', 'scored');
    RAISE EXCEPTION 'Se admitió clasificación incompleta';
  EXCEPTION WHEN check_violation THEN NULL;
  END;
  BEGIN
    DELETE FROM app.audit_events;
    RAISE EXCEPTION 'Se pudo borrar auditoría';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END $$;
ROLLBACK;
\echo Permisos, restricciones y escrituras PostgreSQL verificados; datos de prueba revertidos.
