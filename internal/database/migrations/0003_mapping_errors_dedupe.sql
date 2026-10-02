-- Identity mapping errors are retried on every request, so collapse repeats
-- into one row per Keycloak subject with an occurrence counter.
DELETE FROM identity_mapping_errors a
  USING identity_mapping_errors b
 WHERE a.keycloak_sub = b.keycloak_sub AND a.id < b.id;

ALTER TABLE identity_mapping_errors
    ADD COLUMN IF NOT EXISTS occurrences INT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE UNIQUE INDEX IF NOT EXISTS identity_mapping_errors_sub_idx
    ON identity_mapping_errors(keycloak_sub);
