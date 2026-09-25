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

use crate::cert::{Ca, CaError, CertError, Issuer};
use crate::domain::{self, ClusterDomain, Token};
use crate::zone::{Change, RecordSet, RecordType, Zone, ZoneError};

const LEASE: TimeDelta = TimeDelta::days(7);
const UNUSED_RESERVATION: TimeDelta = TimeDelta::hours(24);
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
    /// Bearer keys that let `POST /domains` skip the per-IP limit (hosted Cloud).
    pub mint_keys: Vec<String>,
}

/// Shared state for every request.
pub struct AppState<Z, C> {
    db: PgPool,
    zone: Z,
    issuer: Issuer<C>,
    config: Config,
    mints: MintLimiter,
}

impl<Z, C> AppState<Z, C> {
    /// A path name that is not a label under the apex can not exist.
    fn domain(&self, name: &str) -> Result<ClusterDomain, ApiError> {
        ClusterDomain::parse(name, &self.config.apex).ok_or(ApiError::NotFound)
    }
}

impl<Z: Zone, C: Ca> AppState<Z, C> {
    /// Wires the database, the DNS zone, the certificate authority and settings.
    pub fn new(db: PgPool, zone: Z, ca: C, config: Config) -> Self {
        let mints = MintLimiter {
            per_hour: config.mints_per_hour,
            windows: Mutex::default(),
        };
        Self {
            db,
            zone,
            issuer: Issuer::new(ca),
            config,
            mints,
        }
    }
}

/// The service's routes, including `GET /healthz` for the platform's probe.
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
    name: ClusterDomain,
    token: Token,
}

async fn mint<Z: Zone, C: Ca>(
    State(state): State<Arc<AppState<Z, C>>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Option<Json<MintRequest>>, JsonRejection>,
) -> Result<(StatusCode, Json<MintResponse>), ApiError> {
    let body = body?;
    if headers.contains_key(header::AUTHORIZATION) {
        // A caller that presents a key never falls back to anonymous minting.
        let key = bearer(&headers).ok_or(ApiError::Unauthorized)?;
        let known = state
            .config
            .mint_keys
            .iter()
            .fold(false, |known, candidate| {
                known | constant_time_eq(candidate, key)
            });
        if !known {
            return Err(ApiError::Unauthorized);
        }
    } else {
        let client = client_ip(&headers, state.config.client_ip_header.as_ref(), peer.ip());
        state.mints.check(client)?;
    }
    let preferred = body.and_then(|Json(body)| body.preferred);
    let token = Token::generate();
    let token_hash = token.hash().await?;
    for label in domain::candidates(preferred.as_deref()).take(MINT_ATTEMPTS) {
        let name = ClusterDomain::new(&label, &state.config.apex);
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
    token: Token,
}

async fn rotate<Z: Zone, C: Ca>(
    State(state): State<Arc<AppState<Z, C>>>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Json<RotateResponse>, ApiError> {
    let name = state.domain(&name)?;
    let mut tx = state.db.begin().await?;
    authorize_and_renew(&mut tx, &name, &headers).await?;
    let token = Token::generate();
    sqlx::query("UPDATE domains SET token_hash = $2 WHERE name = $1")
        .bind(&name)
        .bind(token.hash().await?)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(RotateResponse { token }))
}

#[derive(Serialize)]
struct LeaseResponse {
    name: ClusterDomain,
    lease_expires_at: DateTime<Utc>,
}

async fn renew<Z: Zone, C: Ca>(
    State(state): State<Arc<AppState<Z, C>>>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Json<LeaseResponse>, ApiError> {
    let name = state.domain(&name)?;
    let mut tx = state.db.begin().await?;
    let lease_expires_at = authorize_and_renew(&mut tx, &name, &headers).await?;
    tx.commit().await?;
    Ok(Json(LeaseResponse {
        name,
        lease_expires_at,
    }))
}

/// The full apex address set; an omitted family is removed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApexAddresses {
    #[serde(default)]
    a: Vec<Ipv4Addr>,
    #[serde(default)]
    aaaa: Vec<Ipv6Addr>,
}

async fn put_records<Z: Zone, C: Ca>(
    State(state): State<Arc<AppState<Z, C>>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Result<Json<ApexAddresses>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let name = state.domain(&name)?;
    let Json(addresses) = body?;
    let mut tx = state.db.begin().await?;
    authorize_and_renew(&mut tx, &name, &headers).await?;
    let desired_apex = [
        (
            RecordType::A,
            public_addresses(addresses.a, |ip| is_public_v4(*ip))?,
        ),
        (
            RecordType::Aaaa,
            public_addresses(addresses.aaaa, is_public_v6)?,
        ),
    ];
    if desired_apex.iter().all(|(_, values)| values.is_empty()) {
        return Err(ApiError::InvalidRecords(
            "at least one address is required".into(),
        ));
    }

    let current_apex = state.zone.record_sets(name.as_str()).await?;
    let mut changes = Vec::new();
    for (kind, values) in desired_apex {
        if !values.is_empty() {
            changes.push(Change::Upsert(RecordSet {
                name: name.as_str().to_owned(),
                kind,
                ttl: RECORD_TTL,
                values,
            }));
        } else if let Some(stale) = current_apex.iter().find(|set| set.kind == kind) {
            changes.push(Change::Delete(stale.clone()));
        }
    }
    // Upserting an unchanged CNAME is a no-op, so no read is needed to write it "once".
    changes.push(Change::Upsert(RecordSet {
        name: name.wildcard(),
        kind: RecordType::Cname,
        ttl: RECORD_TTL,
        values: vec![name.as_str().to_owned()],
    }));
    state.zone.apply(changes).await?;

    mark_used(&mut tx, &name).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn release<Z: Zone, C: Ca>(
    State(state): State<Arc<AppState<Z, C>>>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let name = state.domain(&name)?;
    let mut tx = state.db.begin().await?;
    authorize_and_renew(&mut tx, &name, &headers).await?;
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
    let name = state.domain(&name)?;
    let Json(request) = body?;
    let mut tx = state.db.begin().await?;
    authorize_and_renew(&mut tx, &name, &headers).await?;
    // A certificate may exist from here on, so the reaper must never free this name.
    mark_used(&mut tx, &name).await?;
    // Issuance takes minutes; do not hold the row lock through it.
    tx.commit().await?;
    let certificate_chain_pem = state.issuer.issue(&state.zone, &name, &request.csr).await?;
    Ok(Json(CertificateResponse {
        certificate_chain_pem,
    }))
}

/// Frees reservations that never published records or asked for a certificate
/// within 24 hours, and retires names whose lease expired (removing their records).
///
/// # Errors
///
/// Returns [`ApiError`] on the first database or Route 53 failure; the next run retries.
pub async fn reap<Z: Zone, C: Ca>(state: &AppState<Z, C>) -> Result<(), ApiError> {
    sqlx::query(
        "DELETE FROM domains
         WHERE retired_at IS NULL AND NOT used AND reserved_at < now() - $1",
    )
    .bind(UNUSED_RESERVATION)
    .execute(&state.db)
    .await?;
    // ponytail: one name per transaction; a name Route 53 keeps refusing stalls the rest until fixed.
    loop {
        let mut tx = state.db.begin().await?;
        let Some(name) = sqlx::query_scalar::<_, ClusterDomain>(
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

/// Once records or a certificate exist, only the lease decides the name's fate.
async fn mark_used(tx: &mut PgConnection, name: &ClusterDomain) -> Result<(), ApiError> {
    sqlx::query("UPDATE domains SET used = true WHERE name = $1")
        .bind(name)
        .execute(tx)
        .await?;
    Ok(())
}

/// Removes the apex and wildcard records and marks the name retired forever.
async fn retire<Z: Zone>(
    zone: &Z,
    tx: &mut PgConnection,
    name: &ClusterDomain,
) -> Result<(), ApiError> {
    let mut changes = Vec::new();
    for set_name in name.names() {
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

/// Locks the name's row for the transaction, checks the bearer token, and
/// renews the lease: every authorized call keeps the name alive. Returns the
/// new lease expiry.
async fn authorize_and_renew(
    tx: &mut PgConnection,
    name: &ClusterDomain,
    headers: &HeaderMap,
) -> Result<DateTime<Utc>, ApiError> {
    let token = Token::from_bearer(bearer(headers).ok_or(ApiError::Unauthorized)?);
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
    if !token.verify(token_hash).await? {
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

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

/// Compares without an early exit on the first differing byte. Length still
/// leaks, which says nothing useful about a random key.
fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0, |diff, (x, y)| diff | (x ^ y))
            == 0
}

/// Sorts and dedups `addresses` into record values, refusing non-public
/// addresses and sets larger than [`MAX_ADDRESSES`].
fn public_addresses<T: Ord + ToString>(
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
    /// Malformed JSON, bad address syntax, or unknown fields: 400.
    #[error("{0}")]
    BadRequest(String),
    /// Empty, non-public or oversized address set: 422.
    #[error("{0}")]
    InvalidRecords(String),
    /// Missing or wrong bearer token or mint key: 401.
    #[error("missing or wrong bearer token")]
    Unauthorized,
    /// Never minted, or reaped: 404.
    #[error("no such domain")]
    NotFound,
    /// Released or lease expired: 410.
    #[error("domain was released and is retired")]
    Retired,
    /// Anonymous mint limit hit: 429 with `Retry-After`.
    #[error("too many domains minted from this address")]
    RateLimited { retry_after_secs: u64 },
    /// Every label attempt collided: 503.
    #[error("no free label found, try again")]
    NamespaceExhausted,
    /// CSR is not PEM PKCS#10 naming exactly `name` and `*.name`: 422.
    #[error("{0}")]
    InvalidCsr(String),
    /// CA rate limit (429 with `Retry-After`) or failure (502).
    #[error("certificate authority: {0}")]
    Ca(CaError),
    /// Route 53 failed: 502.
    #[error("dns provider: {0}")]
    Zone(#[from] ZoneError),
    /// Postgres failed: 500.
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    /// Token hashing failed: 500.
    #[error("token hashing: {0}")]
    Hash(#[from] bcrypt::BcryptError),
}

impl From<CertError> for ApiError {
    fn from(error: CertError) -> Self {
        match error {
            CertError::InvalidCsr(why) => Self::InvalidCsr(why),
            CertError::Ca(error) => Self::Ca(error),
            CertError::Zone(error) => Self::Zone(error),
        }
    }
}

impl From<JsonRejection> for ApiError {
    fn from(rejection: JsonRejection) -> Self {
        Self::BadRequest(rejection.body_text())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let seconds_until = |until: &SystemTime| {
            until
                .duration_since(SystemTime::now())
                .map_or(1, |left| left.as_secs().max(1))
        };
        // AWS errors can carry account ids, so upstream DNS and internal
        // failures are logged, not returned. CA problems are safe and Cloud
        // needs the reason.
        let (status, code, retry_after_secs, public) = match &self {
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, "invalid_request", None, true),
            Self::InvalidRecords(_) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_records",
                None,
                true,
            ),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized", None, true),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", None, true),
            Self::Retired => (StatusCode::GONE, "retired", None, true),
            Self::RateLimited { retry_after_secs } => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                Some(*retry_after_secs),
                true,
            ),
            Self::NamespaceExhausted => (
                StatusCode::SERVICE_UNAVAILABLE,
                "namespace_exhausted",
                None,
                true,
            ),
            Self::InvalidCsr(_) => (StatusCode::UNPROCESSABLE_ENTITY, "invalid_csr", None, true),
            Self::Ca(CaError::RateLimited { until }) => (
                StatusCode::TOO_MANY_REQUESTS,
                "ca_rate_limited",
                Some(seconds_until(until)),
                true,
            ),
            Self::Ca(CaError::Failed(_)) => (StatusCode::BAD_GATEWAY, "ca_error", None, true),
            Self::Zone(_) => (StatusCode::BAD_GATEWAY, "dns_provider_error", None, false),
            Self::Db(_) | Self::Hash(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal", None, false)
            }
        };
        let message = if public {
            self.to_string()
        } else {
            tracing::error!(error = %self, "request failed");
            "internal error".to_owned()
        };
        let body = Json(serde_json::json!({ "error": code, "message": message }));
        let mut response = (status, body).into_response();
        if let Some(secs) = retry_after_secs {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(secs));
        }
        response
    }
}
