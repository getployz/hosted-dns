//! Wildcard certificates: CSR scope check and DNS-01 issuance through the zone.

use std::collections::BTreeSet;
use std::sync::Mutex;
use std::time::SystemTime;

use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

use crate::domain::ClusterDomain;
use crate::zone::{Change, RecordSet, RecordType, Zone, ZoneError};

const CHALLENGE_TTL: i64 = 60;

/// The certificate authority seam: Google Trust Services over ACME in
/// production, a fake in tests.
pub trait Ca: Send + Sync + 'static {
    /// An open order, carried from [`Ca::new_order`] to [`Ca::finalize`].
    type Order: Send;

    /// Opens an order for `names` and returns the DNS-01 TXT values the CA
    /// expects at `_acme-challenge.<name>`. Empty when every authorization is
    /// already valid.
    ///
    /// # Errors
    ///
    /// Returns [`CaError`] when the CA refuses or fails the order.
    fn new_order(
        &self,
        names: &[String],
    ) -> impl Future<Output = Result<(Self::Order, Vec<String>), CaError>> + Send;

    /// Tells the CA the challenges are live, waits for validation, submits
    /// `csr_der` and returns the PEM certificate chain.
    ///
    /// # Errors
    ///
    /// Returns [`CaError`] when validation, finalisation or download fails.
    fn finalize(
        &self,
        order: Self::Order,
        csr_der: &[u8],
    ) -> impl Future<Output = Result<String, CaError>> + Send;
}

/// A CA failure.
#[derive(Debug, thiserror::Error)]
pub enum CaError {
    /// The CA answered 429; no call may reach it before `until`.
    #[error("certificate authority rate limit")]
    RateLimited { until: SystemTime },
    /// Any other refusal or failure, with the CA's explanation.
    #[error("{0}")]
    Failed(String),
}

/// Why a certificate request failed.
#[derive(Debug, thiserror::Error)]
pub enum CertError {
    /// The CSR is not PEM PKCS#10 naming exactly `name` and `*.name`.
    #[error("{0}")]
    InvalidCsr(String),
    #[error("certificate authority: {0}")]
    Ca(#[from] CaError),
    #[error("dns provider: {0}")]
    Zone(#[from] ZoneError),
}

/// Issues certificates through one CA account and owns its backoff: the CA's
/// quota is per account, so one 429 pauses every name until `Retry-After`.
pub(crate) struct Issuer<C> {
    ca: C,
    blocked_until: Mutex<Option<SystemTime>>,
}

impl<C: Ca> Issuer<C> {
    pub(crate) fn new(ca: C) -> Self {
        Self {
            ca,
            blocked_until: Mutex::default(),
        }
    }

    /// Checks `csr_pem`, orders `name` + `*.name`, publishes the DNS-01 TXT
    /// record, waits for the zone to sync, finalises and returns the PEM chain.
    /// The TXT record is removed whether or not issuance succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`CertError`] for a bad CSR, an active or new CA rate limit, or
    /// a CA or zone failure.
    pub(crate) async fn issue<Z: Zone>(
        &self,
        zone: &Z,
        name: &ClusterDomain,
        csr_pem: &str,
    ) -> Result<String, CertError> {
        let csr_der = csr_der(csr_pem, name)?;
        let blocked_until = *self
            .blocked_until
            .lock()
            .expect("backoff lock is never poisoned");
        if let Some(until) = blocked_until
            && until > SystemTime::now()
        {
            return Err(CaError::RateLimited { until }.into());
        }
        let issued = order_with_dns01(zone, &self.ca, name, &csr_der).await;
        if let Err(CertError::Ca(CaError::RateLimited { until })) = &issued {
            *self
                .blocked_until
                .lock()
                .expect("backoff lock is never poisoned") = Some(*until);
        }
        issued
    }
}

/// Returns the DER of `pem` if it is a CSR naming exactly `name` and `*.name`.
fn csr_der(pem: &str, name: &ClusterDomain) -> Result<Vec<u8>, CertError> {
    let invalid = |why: &str| CertError::InvalidCsr(why.to_owned());
    let (_, pem) =
        x509_parser::pem::parse_x509_pem(pem.as_bytes()).map_err(|_| invalid("csr is not PEM"))?;
    if pem.label != "CERTIFICATE REQUEST" {
        return Err(invalid("PEM block is not a CERTIFICATE REQUEST"));
    }
    let (_, csr) = X509CertificationRequest::from_der(&pem.contents)
        .map_err(|_| invalid("csr is not a valid PKCS#10 request"))?;

    let expected = BTreeSet::from([name.as_str().to_owned(), name.wildcard()]);
    let mut requested = BTreeSet::new();
    for extension in csr.requested_extensions().into_iter().flatten() {
        let ParsedExtension::SubjectAlternativeName(san) = extension else {
            continue;
        };
        for general_name in &san.general_names {
            let GeneralName::DNSName(dns) = general_name else {
                return Err(invalid("csr may only name DNS names"));
            };
            requested.insert((*dns).to_owned());
        }
    }
    let common_names_ok = csr
        .certification_request_info
        .subject
        .iter_common_name()
        .all(|cn| cn.as_str().is_ok_and(|cn| expected.contains(cn)));
    if requested != expected || !common_names_ok {
        return Err(CertError::InvalidCsr(format!(
            "csr must name exactly {name} and *.{name}"
        )));
    }
    Ok(pem.contents)
}

async fn order_with_dns01<Z: Zone, C: Ca>(
    zone: &Z,
    ca: &C,
    name: &ClusterDomain,
    csr_der: &[u8],
) -> Result<String, CertError> {
    let names = [name.as_str().to_owned(), name.wildcard()];
    let (order, values) = ca.new_order(&names).await?;
    if values.is_empty() {
        return Ok(ca.finalize(order, csr_der).await?);
    }
    // Both authorizations validate at the same name, so one set holds both values.
    let challenge = RecordSet {
        name: name.challenge_name(),
        kind: RecordType::Txt,
        ttl: CHALLENGE_TTL,
        values,
    };
    let change = zone.apply(vec![Change::Upsert(challenge.clone())]).await?;
    let issued = async {
        zone.wait_in_sync(&change).await?;
        Ok(ca.finalize(order, csr_der).await?)
    }
    .await;
    if let Err(error) = zone.apply(vec![Change::Delete(challenge)]).await {
        // The next issuance for this name overwrites it with an upsert.
        tracing::warn!(%name, %error, "could not remove DNS-01 challenge");
    }
    issued
}
