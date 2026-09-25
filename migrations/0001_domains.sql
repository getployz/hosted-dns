-- One row per Cluster Domain ever granted. Released names keep their row
-- (retired_at set) so the primary key stops them being reissued.
CREATE TABLE domains (
    name TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL,
    reserved_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_expires_at TIMESTAMPTZ NOT NULL,
    -- Set once records were published or a certificate was requested. Unused
    -- reservations are freed after 24 hours; used names only ever retire.
    used BOOLEAN NOT NULL DEFAULT false,
    retired_at TIMESTAMPTZ
);
