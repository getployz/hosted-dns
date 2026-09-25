//! [`Ca`] backed by an ACME server (Google Trust Services) with an EAB-bound account.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::http::{HeaderMap, Request, StatusCode, header};
use bytes::Bytes;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use instant_acme::{
    Account, AccountCredentials, AuthorizationHandle, AuthorizationStatus, BodyWrapper,
    BytesResponse, ChallengeHandle, ChallengeType, ExternalAccountKey, HttpClient, Identifier,
    NewAccount, NewOrder, Order, OrderStatus, RetryPolicy,
};
use sqlx::PgPool;
use tokio::sync::OnceCell;

use crate::cert::{Ca, CaError};

/// Order validation and certificate download get this long.
const ORDER_POLL_POLICY: RetryPolicy = RetryPolicy::new()
    .initial_delay(Duration::from_secs(2))
    .backoff(1.5)
    .timeout(Duration::from_secs(300));
/// Used when a 429 carries no usable `Retry-After`.
const DEFAULT_BACKOFF: Duration = Duration::from_secs(3600);

/// Where the ACME account lives and how to create it.
pub struct AcmeConfig {
    /// ACME directory, e.g. Google Trust Services production or staging.
    pub directory_url: String,
    /// External Account Binding key id.
    pub eab_kid: String,
    /// Raw HMAC key bytes (the CA hands them out base64url-encoded).
    pub eab_hmac: Vec<u8>,
}

/// The production CA.
pub struct Acme {
    config: AcmeConfig,
    db: PgPool,
    account: OnceCell<Account>,
    rate_limited_until: Arc<Mutex<Option<SystemTime>>>,
}

impl Acme {
    /// The account is created (or loaded from Postgres) on first use.
    pub fn new(config: AcmeConfig, db: PgPool) -> Self {
        Self {
            config,
            db,
            account: OnceCell::new(),
            rate_limited_until: Arc::default(),
        }
    }

    /// EAB keys are single use, so the account's credentials are kept in Postgres.
    async fn account(&self) -> Result<&Account, CaError> {
        self.account
            .get_or_try_init(|| async {
                let url = &self.config.directory_url;
                let builder = Account::builder_with_http(Box::new(self.http()?));
                let stored: Option<String> = sqlx::query_scalar(
                    "SELECT credentials FROM acme_accounts WHERE directory_url = $1",
                )
                .bind(url)
                .fetch_optional(&self.db)
                .await
                .map_err(ca_failure)?;
                if let Some(stored) = stored {
                    let credentials: AccountCredentials =
                        serde_json::from_str(&stored).map_err(ca_failure)?;
                    return builder
                        .from_credentials(credentials)
                        .await
                        .map_err(|error| self.ca_error(error));
                }
                let eab =
                    ExternalAccountKey::new(self.config.eab_kid.clone(), &self.config.eab_hmac);
                let new_account = NewAccount {
                    contact: &[],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                };
                let (account, credentials) = builder
                    .create(&new_account, url.clone(), Some(&eab))
                    .await
                    .map_err(|error| self.ca_error(error))?;
                sqlx::query(
                    "INSERT INTO acme_accounts (directory_url, credentials) VALUES ($1, $2)",
                )
                .bind(url)
                .bind(serde_json::to_string(&credentials).map_err(ca_failure)?)
                .execute(&self.db)
                .await
                .map_err(ca_failure)?;
                tracing::info!(id = account.id(), "created ACME account");
                Ok(account)
            })
            .await
    }

    fn http(&self) -> Result<RetryAfterRecorder, CaError> {
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .try_with_platform_verifier()
            .map_err(ca_failure)?
            .https_only()
            .enable_http1()
            .enable_http2()
            .build();
        Ok(RetryAfterRecorder {
            inner: HyperClient::builder(TokioExecutor::new()).build(https),
            until: Arc::clone(&self.rate_limited_until),
        })
    }

    fn ca_error(&self, error: instant_acme::Error) -> CaError {
        match &error {
            instant_acme::Error::Api(problem) if problem.status == Some(429) => {
                let until = self
                    .rate_limited_until
                    .lock()
                    .expect("retry-after lock is never poisoned")
                    .take()
                    .unwrap_or_else(|| SystemTime::now() + DEFAULT_BACKOFF);
                CaError::RateLimited { until }
            }
            _ => CaError::Failed(error.to_string()),
        }
    }
}

impl Ca for Acme {
    type Order = Order;

    async fn new_order(&self, names: &[String]) -> Result<(Order, Vec<String>), CaError> {
        let identifiers: Vec<_> = names.iter().cloned().map(Identifier::Dns).collect();
        let mut order = self
            .account()
            .await?
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(|error| self.ca_error(error))?;
        let mut values = Vec::new();
        let mut authorizations = order.authorizations();
        while let Some(authorization) = authorizations.next().await {
            let mut authorization = authorization.map_err(|error| self.ca_error(error))?;
            match authorization.status {
                AuthorizationStatus::Valid => {}
                AuthorizationStatus::Pending => {
                    let challenge = dns01(&mut authorization)?;
                    values.push(challenge.key_authorization().dns_value());
                }
                status => return Err(CaError::Failed(format!("authorization is {status:?}"))),
            }
        }
        Ok((order, values))
    }

    async fn finalize(&self, mut order: Order, csr_der: &[u8]) -> Result<String, CaError> {
        let mut authorizations = order.authorizations();
        while let Some(authorization) = authorizations.next().await {
            let mut authorization = authorization.map_err(|error| self.ca_error(error))?;
            if authorization.status != AuthorizationStatus::Pending {
                continue;
            }
            let mut challenge = dns01(&mut authorization)?;
            challenge
                .set_ready()
                .await
                .map_err(|error| self.ca_error(error))?;
        }
        let status = order
            .poll_ready(&ORDER_POLL_POLICY)
            .await
            .map_err(|error| self.ca_error(error))?;
        if status != OrderStatus::Ready {
            return Err(CaError::Failed(format!(
                "order is {status:?} after validation"
            )));
        }
        order
            .finalize_csr(csr_der)
            .await
            .map_err(|error| self.ca_error(error))?;
        order
            .poll_certificate(&ORDER_POLL_POLICY)
            .await
            .map_err(|error| self.ca_error(error))
    }
}

type HttpsClient = HyperClient<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    BodyWrapper<Bytes>,
>;

/// instant-acme drops `Retry-After` from 429 problems, so record it on the way through.
// ponytail: one slot for all requests; two 429s racing may pair a problem with the
// other's Retry-After. Both come from the same account quota, so either is close.
struct RetryAfterRecorder {
    inner: HttpsClient,
    until: Arc<Mutex<Option<SystemTime>>>,
}

impl HttpClient for RetryAfterRecorder {
    fn request(
        &self,
        request: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        let response = HttpClient::request(&self.inner, request);
        let until = Arc::clone(&self.until);
        Box::pin(async move {
            let response = response.await?;
            if response.parts.status == StatusCode::TOO_MANY_REQUESTS {
                *until.lock().expect("retry-after lock is never poisoned") =
                    retry_after(&response.parts.headers);
            }
            Ok(response)
        })
    }
}

fn dns01<'a>(
    authorization: &'a mut AuthorizationHandle<'a>,
) -> Result<ChallengeHandle<'a>, CaError> {
    authorization
        .challenge(ChallengeType::Dns01)
        .ok_or_else(|| CaError::Failed("CA offered no dns-01 challenge".into()))
}

/// `Retry-After` as delay-seconds or an HTTP date.
fn retry_after(headers: &HeaderMap) -> Option<SystemTime> {
    let value = headers.get(header::RETRY_AFTER)?.to_str().ok()?.trim();
    match value.parse::<u64>() {
        Ok(secs) => Some(SystemTime::now() + Duration::from_secs(secs)),
        Err(_) => httpdate::parse_http_date(value).ok(),
    }
}

fn ca_failure(error: impl std::fmt::Display) -> CaError {
    CaError::Failed(error.to_string())
}
