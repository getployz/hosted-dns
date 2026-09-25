//! Hosted DNS: mints generated Cluster Domains under one Route 53 zone and
//! publishes their apex addresses for Ployz Cloud.

mod api;
mod label;
mod route53;
mod zone;

pub use api::{ApiError, AppState, Config, reap, router};
pub use route53::Route53;
pub use zone::{Change, RecordSet, RecordType, Zone, ZoneError};

/// Schema migrations, run at startup.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();
