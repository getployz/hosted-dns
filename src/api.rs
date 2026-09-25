//! HTTP API: mint, rotate, records, lease, release, certificate, and the reaper.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, PgPool};

use crate::cert::{self, Ca, CaError};
use crate::label;
use crate::zone::{Change, RecordSet, RecordType, Zone, ZoneError};

const LEASE: TimeDelta = TimeDelta::days(7);
const UNUSED_RESERVATION: TimeDelta = TimeDelta::hours(24);
const TOKEN_LEN: usize = 40;
// Tokens are 200+ random bits, so bcrypt's work factor guards nothing brute force could reach.
const BCRYPT_COST: u32 = 10;
const MINT_ATTEMPTS: usize = 8;
const RECORD_TTL: i64 = 60;
const MAX_ADDRESSES: usize = 32;
const MINT_WINDOW: Duration = Duration::from_secs(3600);

/// Service settings read from the environment at startup.
pub struct Config {
    /// Zone apex every Cluster Domain sits under, e.g. `ployz.app`.
    pub apex: String,
    /// Mints allowed per source IP (IPv6: per /64) per hour.
    pub mints_per_hour: u32,
    /// Header holding the client IP when behind a proxy; the peer address otherwise.
    pub client_ip_header: Option<HeaderName>,
}

/// Shared state for every request.
pub struct AppState<Z, C> {
    db: PgPool,
    zone: Z,
    ca: C,
    config: Config,
    mints: MintLimiter,
    /// The CA's quota is per account, so one 429 pauses every caller.
    ca_blocked_until: Mutex<Option<SystemTime>>,
}

impl<Z: Zone, C: Ca> AppState<Z, C> {
    pub fn new(db: PgPool, zone: Z, ca: C, config: Config) -> Self {
        let mints = MintLimiter {
            per_hour: config.mints_per_hour,
            windows: Mutex::default(),
        };
        Self {
            db,
            zone,
            ca,
            config,
            mints,
            ca_blocked_until: Mutex::default(),
        }
    }
}

/// The service's routes.
pub fn router<Z: Zone, C: Ca>(state: Arc<AppState<Z, C>>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/domains", post(mint::<Z, C>))
        .route("/domains/{name}", delete(release::<Z, C>))
        .route("/domains/{name}/rotate", post(rotate::<Z, C>))
        .route("/domains/{name}/lease", post(renew::<Z, C>))
        .route("/domains/{name}/records", put(put_records::<Z, C>))
        .route("/domains/{name}/certificate", post(certificate::<Z, C>))
        .with_state(state)
}

#[derive(Deserialize)]
struct MintRequest {
    preferred: Option<String>,
}

#[derive(Serialize)]
struct MintResponse {
    name: String,
    token: String,
}

async fn mint<Z: Zone, C: Ca>(
    State(state): State<Arc<AppState<Z, C>>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Option<Json<MintRequest>>, JsonRejection>,
) -> Result<(StatusCode, Json<MintResponse>), ApiError> {
    let body = body.map_err(|rejection| ApiError::BadRequest(rejection.body_text()))?;
    let client = client_ip(&headers, state.config.client_ip_header.as_ref(), peer.ip());
    state.mints.check(client)?;
    let preferred = body.and_then(|Json(body)| body.preferred);
    let token = label::random_string(TOKEN_LEN);
    let token_hash = hash(&token).await?;
    for label in label::candidates(preferred.as_deref()).take(MINT_ATTEMPTS) {
        let name = format!("{label}.{}", state.config.apex);
        // Retired names keep their row, so the conflict also refuses them.
        let inserted = sqlx::query(
            "INSERT INTO domains (name, token_hash, lease_expires_at) VALUES ($1, $2, now() + $3)
             ON CONFLICT (name) DO NOTHING",
        )
        .bind(&name)
        .bind(&token_hash)
        .bind(LEASE)
        .execute(&state.db)
        .await?
        .rows_affected()
            == 1;
        if inserted {
            return Ok((StatusCode::CREATED, Json(MintResponse { name, token })));
        }
    }
    Err(ApiError::NamespaceExhausted)
}

#[derive(Serialize)]
struct RotateResponse {
    token: String,
}

async fn rotate<Z: Zone, C: Ca>(
    State(state): State<Arc<AppState<Z, C>>>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Json<RotateResponse>, ApiError> {
    let mut tx = state.db.begin().await?;
    authenticate(&mut tx, &name, &headers).await?;
    let token = label::random_string(TOKEN_LEN);
    sqlx::query("UPDATE domains SET token_hash = $2 WHERE name = $1")
        .bind(&name)
        .bind(hash(&token).await?)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(RotateResponse { token }))
}

#[derive(Serialize)]
struct LeaseResponse {
    name: String,
    lease_expires_at: DateTime<Utc>,
}

async fn renew<Z: Zone, C: Ca>(
    State(state): State<Arc<AppState<Z, C>>>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Json<LeaseResponse>, ApiError> {
    let mut tx = state.db.begin().await?;
    let lease_expires_at = authenticate(&mut tx, &name, &headers).await?;
    tx.commit().await?;
    Ok(Json(LeaseResponse {
        name,
        lease_expires_at,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Records {
    #[serde(default)]
    a: Vec<Ipv4Addr>,
    #[serde(default)]
    aaaa: Vec<Ipv6Addr>,
}

async fn put_records<Z: Zone, C: Ca>(
    State(state): State<Arc<AppState<Z, C>>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Result<Json<Records>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let Json(records) = body.map_err(|rejection| ApiError::BadRequest(rejection.body_text()))?;
    let mut tx = state.db.begin().await?;
    authenticate(&mut tx, &name, &headers).await?;
    let wanted = [
        (RecordType::A, addresses(records.a, |ip| is_public_v4(*ip))?),
        (RecordType::Aaaa, addresses(records.aaaa, is_public_v6)?),
    ];
    if wanted.iter().all(|(_, values)| values.is_empty()) {
        return Err(ApiError::InvalidRecords(
            "at least one address is required".into(),
        ));
    }

    let current = state.zone.record_sets(&name).await?;
    let mut changes = Vec::new();
    for (kind, values) in wanted {
        if !values.is_empty() {
            changes.push(Change::Upsert(RecordSet {
                name: name.clone(),
                kind,
                ttl: RECORD_TTL,
                values,
            }));
        } else if let Some(stale) = current.iter().find(|set| set.kind == kind) {
            changes.push(Change::Delete(stale.clone()));
        }
    }
    let wildcard = format!("*.{name}");
    let has_wildcard = state
        .zone
        .record_sets(&wildcard)
        .await?
        .iter()
        .any(|set| set.kind == RecordType::Cname);
    if !has_wildcard {
        changes.push(Change::Upsert(RecordSet {
            values: vec![name.clone()],
            name: wildcard,
            kind: RecordType::Cname,
            ttl: RECORD_TTL,
        }));
    }
    state.zone.apply(changes).await?;

    sqlx::query("UPDATE domains SET has_records = true WHERE name = $1")
        .bind(&name)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn release<Z: Zone, C: Ca>(
    State(state): State<Arc<AppState<Z, C>>>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let mut tx = state.db.begin().await?;
    authenticate(&mut tx, &name, &headers).await?;
    retire(&state.zone, &mut tx, &name).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct CertificateRequest {
    csr: String,
}

#[derive(Serialize)]
struct CertificateResponse {
    certificate_chain_pem: String,
}

// ponytail: no per-name lock; overlapping calls for one name clobber each other's
// challenge and one fails. Cloud runs one sync per Organization at a time.
async fn certificate<Z: Zone, C: Ca>(
    State(state): State<Arc<AppState<Z, C>>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Result<Json<CertificateRequest>, JsonRejection>,
) -> Result<Json<CertificateResponse>, ApiError> {
    let Json(request) = body.map_err(|rejection| ApiError::BadRequest(rejection.body_text()))?;
    let mut tx = state.db.begin().await?;
    authenticate(&mut tx, &name, &headers).await?;
    // Issuance takes minutes; do not hold the row lock through it.
    tx.commit().await?;
    let csr_der = cert::csr_der(&request.csr, &name)?;

    let blocked_until = *state
        .ca_blocked_until
        .lock()
        .expect("ca backoff lock is never poisoned");
    if let Some(until) = blocked_until
        && until > SystemTime::now()
    {
        return Err(CaError::RateLimited { until }.into());
    }
    let issued = cert::issue(&state.zone, &state.ca, &name, &csr_der).await;
    if let Err(ApiError::Ca(CaError::RateLimited { until })) = &issued {
        *state
            .ca_blocked_until
            .lock()
            .expect("ca backoff lock is never poisoned") = Some(*until);
    }
    Ok(Json(CertificateResponse {
        certificate_chain_pem: issued?,
    }))
}

/// Frees reservations that published no records within 24 hours, and retires
/// names whose lease expired (removing their records).
///
/// # Errors
///
/// Returns [`ApiError`] on the first database or Route 53 failure; the next run retries.
pub async fn reap<Z: Zone, C: Ca>(state: &AppState<Z, C>) -> Result<(), ApiError> {
    sqlx::query(
        "DELETE FROM domains
         WHERE retired_at IS NULL AND NOT has_records AND reserved_at < now() - $1",
    )
    .bind(UNUSED_RESERVATION)
    .execute(&state.db)
    .await?;
    // ponytail: one name per transaction; a name Route 53 keeps refusing stalls the rest until fixed.
    loop {
        let mut tx = state.db.begin().await?;
        let Some(name) = sqlx::query_scalar::<_, String>(
            "SELECT name FROM domains WHERE retired_at IS NULL AND lease_expires_at < now()
             LIMIT 1 FOR UPDATE SKIP LOCKED",
        )
        .fetch_optional(&mut *tx)
        .await?
        else {
            return Ok(());
        };
        retire(&state.zone, &mut tx, &name).await?;
        tx.commit().await?;
        tracing::info!(%name, "retired expired lease");
    }
}

/// Removes the apex and wildcard records and marks the name retired forever.
async fn retire<Z: Zone>(zone: &Z, tx: &mut PgConnection, name: &str) -> Result<(), ApiError> {
    let mut changes = Vec::new();
    for set_name in [name.to_owned(), format!("*.{name}")] {
        changes.extend(
            zone.record_sets(&set_name)
                .await?
                .into_iter()
                .map(Change::Delete),
        );
    }
    if !changes.is_empty() {
        zone.apply(changes).await?;
    }
    sqlx::query("UPDATE domains SET retired_at = now() WHERE name = $1")
        .bind(name)
        .execute(tx)
        .await?;
    Ok(())
}

/// Locks the name's row for the transaction, checks the bearer token and renews
/// the lease. Returns the new lease expiry.
async fn authenticate(
    tx: &mut PgConnection,
    name: &str,
    headers: &HeaderMap,
) -> Result<DateTime<Utc>, ApiError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?
        .to_owned();
    let row: Option<(String, Option<DateTime<Utc>>)> =
        sqlx::query_as("SELECT token_hash, retired_at FROM domains WHERE name = $1 FOR UPDATE")
            .bind(name)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((token_hash, retired_at)) = row else {
        return Err(ApiError::NotFound);
    };
    if retired_at.is_some() {
        return Err(ApiError::Retired);
    }
    let valid = tokio::task::spawn_blocking(move || bcrypt::verify(token, &token_hash))
        .await
        .expect("bcrypt verify does not panic")?;
    if !valid {
        return Err(ApiError::Unauthorized);
    }
    let lease_expires_at = sqlx::query_scalar(
        "UPDATE domains SET lease_expires_at = now() + $2 WHERE name = $1
         RETURNING lease_expires_at",
    )
    .bind(name)
    .bind(LEASE)
    .fetch_one(&mut *tx)
    .await?;
    Ok(lease_expires_at)
}

async fn hash(token: &str) -> Result<String, ApiError> {
    let token = token.to_owned();
    Ok(
        tokio::task::spawn_blocking(move || bcrypt::hash(token, BCRYPT_COST))
            .await
            .expect("bcrypt hash does not panic")?,
    )
}

/// Sorts and dedups `addresses`, refusing non-public ones and oversized sets.
fn addresses<T: Ord + ToString>(
    mut addresses: Vec<T>,
    is_public: impl Fn(&T) -> bool,
) -> Result<Vec<String>, ApiError> {
    addresses.sort();
    addresses.dedup();
    if addresses.len() > MAX_ADDRESSES {
        return Err(ApiError::InvalidRecords(format!(
            "at most {MAX_ADDRESSES} addresses per family"
        )));
    }
    if let Some(bad) = addresses.iter().find(|ip| !is_public(ip)) {
        return Err(ApiError::InvalidRecords(format!(
            "{} is not a public address",
            bad.to_string()
        )));
    }
    Ok(addresses.iter().map(ToString::to_string).collect())
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast())
}

fn is_public_v6(ip: &Ipv6Addr) -> bool {
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || ip.to_ipv4_mapped().is_some())
}

fn client_ip(headers: &HeaderMap, header: Option<&HeaderName>, peer: IpAddr) -> IpAddr {
    header
        .and_then(|header| headers.get(header))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(peer)
}

/// Fixed-window mint counter per source address.
// ponytail: in memory and per instance; move to Postgres if the service ever runs replicas.
struct MintLimiter {
    per_hour: u32,
    windows: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl MintLimiter {
    fn check(&self, ip: IpAddr) -> Result<(), ApiError> {
        // One IPv6 user trivially holds a /64, so count the /64.
        let key = match ip {
            IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & !u128::from(u64::MAX))),
            IpAddr::V4(_) => ip,
        };
        let now = Instant::now();
        let mut windows = self
            .windows
            .lock()
            .expect("mint limiter lock is never poisoned");
        windows.retain(|_, (start, _)| now.duration_since(*start) < MINT_WINDOW);
        let (start, count) = windows.entry(key).or_insert((now, 0));
        if *count >= self.per_hour {
            let retry_after_secs = (MINT_WINDOW - now.duration_since(*start)).as_secs().max(1);
            return Err(ApiError::RateLimited { retry_after_secs });
        }
        *count += 1;
        Ok(())
    }
}

/// Every failure the API returns, rendered as `{"error": code, "message": text}`.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    InvalidRecords(String),
    #[error("{0}")]
    InvalidCsr(String),
    #[error("missing or wrong bearer token")]
    Unauthorized,
    #[error("no such domain")]
    NotFound,
    #[error("domain was released and is retired")]
    Retired,
    #[error("too many domains minted from this address")]
    RateLimited { retry_after_secs: u64 },
    #[error("no free label found, try again")]
    NamespaceExhausted,
    #[error("dns provider: {0}")]
    Zone(#[from] ZoneError),
    #[error("certificate authority: {0}")]
    Ca(#[from] CaError),
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    #[error("token hashing: {0}")]
    Hash(#[from] bcrypt::BcryptError),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::InvalidRecords(_) => (StatusCode::UNPROCESSABLE_ENTITY, "invalid_records"),
            Self::InvalidCsr(_) => (StatusCode::UNPROCESSABLE_ENTITY, "invalid_csr"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Retired => (StatusCode::GONE, "retired"),
            Self::RateLimited { .. } => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Self::NamespaceExhausted => (StatusCode::SERVICE_UNAVAILABLE, "namespace_exhausted"),
            Self::Zone(_) => (StatusCode::BAD_GATEWAY, "dns_provider_error"),
            Self::Ca(CaError::RateLimited { .. }) => {
                (StatusCode::TOO_MANY_REQUESTS, "ca_rate_limited")
            }
            Self::Ca(CaError::Failed(_)) => (StatusCode::BAD_GATEWAY, "ca_error"),
            Self::Db(_) | Self::Hash(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        };
        // AWS errors can carry account ids; CA problems are safe and Cloud needs the reason.
        let message = if matches!(self, Self::Zone(_) | Self::Db(_) | Self::Hash(_)) {
            tracing::error!(error = %self, "request failed");
            "internal error".to_owned()
        } else {
            self.to_string()
        };
        let body = Json(serde_json::json!({ "error": code, "message": message }));
        let mut response = (status, body).into_response();
        let retry_after_secs = match self {
            Self::RateLimited { retry_after_secs } => Some(retry_after_secs),
            Self::Ca(CaError::RateLimited { until }) => Some(
                until
                    .duration_since(SystemTime::now())
                    .map_or(1, |left| left.as_secs().max(1)),
            ),
            _ => None,
        };
        if let Some(secs) = retry_after_secs {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(secs));
        }
        response
    }
}
