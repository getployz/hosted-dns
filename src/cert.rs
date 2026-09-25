//! Wildcard certificates: CSR scope check and DNS-01 issuance through the zone.

use std::collections::BTreeSet;
use std::time::SystemTime;

use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

use crate::api::ApiError;
use crate::zone::{Change, RecordSet, RecordType, Zone};

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
    #[error("{0}")]
    Failed(String),
}

/// Checks that `pem` is a CSR naming exactly `name` and `*.name`, and returns its DER.
///
/// # Errors
///
/// Returns [`ApiError::InvalidCsr`] for anything else.
pub(crate) fn csr_der(pem: &str, name: &str) -> Result<Vec<u8>, ApiError> {
    let invalid = |why: &str| ApiError::InvalidCsr(why.to_owned());
    let (_, pem) =
        x509_parser::pem::parse_x509_pem(pem.as_bytes()).map_err(|_| invalid("csr is not PEM"))?;
    if pem.label != "CERTIFICATE REQUEST" {
        return Err(invalid("PEM block is not a CERTIFICATE REQUEST"));
    }
    let (_, csr) = X509CertificationRequest::from_der(&pem.contents)
        .map_err(|_| invalid("csr is not a valid PKCS#10 request"))?;

    let expected = BTreeSet::from([name.to_owned(), format!("*.{name}")]);
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
        return Err(ApiError::InvalidCsr(format!(
            "csr must name exactly {name} and *.{name}"
        )));
    }
    Ok(pem.contents)
}

/// Orders `name` + `*.name`, publishes the DNS-01 TXT record, waits for Route 53
/// to sync, finalises with `csr_der` and returns the chain. The TXT record is
/// removed whether or not issuance succeeds.
pub(crate) async fn issue<Z: Zone, C: Ca>(
    zone: &Z,
    ca: &C,
    name: &str,
    csr_der: &[u8],
) -> Result<String, ApiError> {
    let names = [name.to_owned(), format!("*.{name}")];
    let (order, values) = ca.new_order(&names).await?;
    if values.is_empty() {
        return Ok(ca.finalize(order, csr_der).await?);
    }
    // Both authorizations validate at the same name, so one set holds both values.
    let challenge = RecordSet {
        name: format!("_acme-challenge.{name}"),
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
