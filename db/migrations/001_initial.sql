CREATE TABLE app.cves (
  id text PRIMARY KEY CHECK (id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
  published timestamptz NOT NULL,
  last_modified timestamptz NOT NULL,
  vuln_status text NOT NULL CHECK (length(vuln_status) > 0),
  classification_status text NOT NULL,
  severity text,
  metric jsonb,
  CHECK ((vuln_status = 'Rejected') = (classification_status = 'rejected')),
  CHECK (
    (classification_status = 'scored' AND severity IS NOT NULL
      AND severity IN ('none', 'low', 'medium', 'high', 'critical')
      AND metric IS NOT NULL AND jsonb_typeof(metric) = 'object')
    OR (classification_status = 'unscored' AND severity IS NOT NULL AND severity = 'unknown' AND metric IS NULL)
    OR (classification_status = 'rejected' AND severity IS NULL AND metric IS NULL)
  )
);

CREATE TABLE app.sync_state (
  id integer PRIMARY KEY CHECK (id = 1),
  status text NOT NULL CHECK (status IN ('idle', 'running', 'paused', 'failed', 'completed')),
  next_start_index bigint NOT NULL CHECK (next_start_index >= 0),
  total_results bigint CHECK (total_results >= 0),
  last_page_timestamp timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Puede registrarse antes de que la carga local reciba el CVE: sin FK a cves.
CREATE TABLE app.remediations (
  cve_id text PRIMARY KEY CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
  registered_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE app.audit_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event text NOT NULL CHECK (event = 'remediation_registered'),
  cve_id text NOT NULL CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
  request_id uuid NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE ON app.cves, app.sync_state TO cve_app;
GRANT SELECT, INSERT ON app.remediations TO cve_app;
GRANT INSERT ON app.audit_events TO cve_app;
