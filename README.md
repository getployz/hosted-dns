# hosted-dns — Ployz Hosted DNS service: generated Cluster Domains on Route 53.

Rust axum service backed by Route 53 and Postgres. Configuration comes from the
environment; see `.env.example`. Migrations run at startup.

Tests need Docker: `cargo test` starts a throwaway Postgres per test
(testcontainers) and runs the HTTP API against an in-memory fake Route 53.
