-- The ACME account for each directory. EAB keys are single use, so the
-- account key must outlive restarts. This is the CA account key, never a
-- certificate key.
CREATE TABLE acme_accounts (
    directory_url TEXT PRIMARY KEY,
    credentials TEXT NOT NULL
);
