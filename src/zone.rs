//! The DNS zone seam: Route 53 in production, a fake in tests.

/// Record types the service manages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecordType {
    A,
    Aaaa,
    Cname,
    /// Unquoted values; the provider adds and strips the quotes.
    Txt,
}

/// One Route 53 resource record set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordSet {
    /// Fully qualified name without the trailing dot, e.g. `*.acme.ployz.app`.
    pub name: String,
    pub kind: RecordType,
    pub ttl: i64,
    pub values: Vec<String>,
}

/// A change with Route 53 semantics: `Delete` must match the existing set exactly.
#[derive(Clone, Debug)]
pub enum Change {
    Upsert(RecordSet),
    Delete(RecordSet),
}

/// Identifies an applied batch so callers can wait for it to reach every nameserver.
#[derive(Clone, Debug)]
pub struct ChangeId(pub String);

/// The DNS provider refused or failed a call.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ZoneError(pub String);

/// The hosted zone that holds every Cluster Domain.
pub trait Zone: Send + Sync + 'static {
    /// Lists the managed record sets whose name is exactly `name`.
    ///
    /// # Errors
    ///
    /// Returns [`ZoneError`] when the provider call fails.
    fn record_sets(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Vec<RecordSet>, ZoneError>> + Send;

    /// Applies `changes` as one atomic batch.
    ///
    /// # Errors
    ///
    /// Returns [`ZoneError`] when the provider rejects or fails the batch.
    fn apply(
        &self,
        changes: Vec<Change>,
    ) -> impl Future<Output = Result<ChangeId, ZoneError>> + Send;

    /// Waits until the batch is served by every authoritative nameserver.
    ///
    /// # Errors
    ///
    /// Returns [`ZoneError`] when the provider call fails or the wait times out.
    fn wait_in_sync(&self, change: &ChangeId)
    -> impl Future<Output = Result<(), ZoneError>> + Send;
}
