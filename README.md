# hosted-dns — Ployz Hosted DNS service: generated Cluster Domains on Route 53.

Rust axum service backed by Route 53 and Postgres. Configuration comes from the
environment; see `.env.example`. Migrations run at startup.

Tests need Docker: `cargo test` starts a throwaway Postgres per test
(testcontainers) and runs the HTTP API against an in-memory fake Route 53 and
a fake ACME CA that validates DNS-01 through it.

## API

```
GET    /healthz                     anon      200 "ok"
POST   /domains                     anon*     {preferred?} → 201 {name, token}
POST   /domains/{name}/rotate       bearer    → 200 {token}
PUT    /domains/{name}/records      bearer    {a?, aaaa?} → 204
POST   /domains/{name}/lease        bearer    → 200 {name, lease_expires_at}
POST   /domains/{name}/certificate  bearer    {csr} → 200 {certificate_chain_pem}
DELETE /domains/{name}              bearer    → 204, name retired forever
```

- Anonymous mints are limited per source IP. A `MINT_KEYS` key sent as the bearer skips the limit, and a wrong key gets 401.
- Every authorized call renews a 7-day lease.
- `PUT /records` replaces the whole apex set. It returns 422 `invalid_records` for an empty set, a non-public address, or more than 32 addresses per family.
- A name that has published no records and asked for no certificate after 24 hours is freed. Any other name is retired forever, either on `DELETE` or when its lease expires.
- Errors are `{"error": code, "message": text}`.
