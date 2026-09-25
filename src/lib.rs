//! Hosted DNS: mints generated Cluster Domains under one Route 53 zone and
//! publishes their apex addresses for Ployz Cloud. Signs one wildcard
//! certificate per name from a CSR; it never holds certificate keys.

mod acme;
mod api;
mod cert;
mod domain;
mod route53;
mod zone;

pub use acme::{Acme, AcmeConfig};
pub use api::{ApiError, AppState, Config, reap, router};
pub use cert::{Ca, CaError, CertError};
pub use domain::TOKEN_LEN;
pub use route53::Route53;
pub use zone::{Change, ChangeId, RecordSet, RecordType, Zone, ZoneError};

/// Schema migrations, run at startup.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();
