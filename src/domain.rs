//! Cluster Domain names, their bearer tokens, and label choice for new names.

use bcrypt::BcryptError;
use rand::Rng;
use serde::Serialize;

/// Labels that are never granted verbatim; they get a suffix instead.
const RESERVED: &[&str] = &[
    "www",
    "api",
    "dns",
    "mail",
    "admin",
    "cloud",
    "app",
    "ployz",
    "ns",
    "ns1",
    "ns2",
    "smtp",
    "imap",
    "status",
    "docs",
    "dashboard",
    "support",
    "root",
    "autoconfig",
    "autodiscover",
];

const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
/// Length of a bearer token: 40 characters of `[a-z0-9]`, about 206 random bits.
const TOKEN_LEN: usize = 40;
// Tokens are 200+ random bits, so bcrypt's work factor guards nothing brute force could reach.
const BCRYPT_COST: u32 = 10;
const SUFFIX_LEN: usize = 4;
const RANDOM_LABEL_LEN: usize = 10;

/// Labels to try, best first: the preferred label if valid and not reserved,
/// then endless `preferred-xxxx` candidates, or endless random labels when the
/// preferred label is missing or invalid.
pub(crate) fn candidates(preferred: Option<&str>) -> impl Iterator<Item = String> + '_ {
    let base = preferred.filter(|label| is_valid(label));
    let exact = base
        .filter(|label| !RESERVED.contains(label))
        .map(str::to_owned);
    exact
        .into_iter()
        .chain(std::iter::repeat_with(move || match base {
            Some(base) => format!("{base}-{}", random_string(SUFFIX_LEN)),
            None => random_string(RANDOM_LABEL_LEN),
        }))
}

/// A preferred label: `[a-z0-9-]{3,40}` with no hyphen at either edge.
fn is_valid(label: &str) -> bool {
    (3..=40).contains(&label.len()) && is_ldh(label)
}

/// Lowercase letters, digits and inner hyphens only.
fn is_ldh(label: &str) -> bool {
    label
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

/// Random `[a-z0-9]` string.
fn random_string(len: usize) -> String {
    let mut rng = rand::rng();
    (0..len)
        .map(|_| char::from(ALPHABET[rng.random_range(0..ALPHABET.len())]))
        .collect()
}

/// A granted Cluster Domain, e.g. `acme.ployz.app`: one label under the apex.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(transparent)]
pub(crate) struct ClusterDomain(String);

impl ClusterDomain {
    pub(crate) fn new(label: &str, apex: &str) -> Self {
        Self(format!("{label}.{apex}"))
    }

    /// Accepts exactly one DNS label under `apex`. `None` for anything else,
    /// which callers treat like an unknown name.
    // The apex is runtime config, so this is a function rather than FromStr/serde.
    pub(crate) fn parse(name: &str, apex: &str) -> Option<Self> {
        let label = name.strip_suffix(apex)?.strip_suffix('.')?;
        let valid = (1..=63).contains(&label.len()) && is_ldh(label);
        valid.then(|| Self(name.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// `*.name`, the CNAME to the apex and the certificate's second name.
    pub(crate) fn wildcard(&self) -> String {
        format!("*.{}", self.0)
    }

    /// `[name, *.name]`: the records' owners and the certificate's names.
    pub(crate) fn names(&self) -> [String; 2] {
        [self.0.clone(), self.wildcard()]
    }

    /// `_acme-challenge.name`, where DNS-01 validates both `name` and `*.name`.
    pub(crate) fn challenge_name(&self) -> String {
        format!("_acme-challenge.{}", self.0)
    }
}

impl std::fmt::Display for ClusterDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A per-name bearer token. Shown to the caller once; only its bcrypt hash is stored.
#[derive(Serialize)]
#[serde(transparent)]
pub(crate) struct Token(String);

impl Token {
    pub(crate) fn generate() -> Self {
        Self(random_string(TOKEN_LEN))
    }

    pub(crate) fn from_bearer(token: &str) -> Self {
        Self(token.to_owned())
    }

    /// # Errors
    ///
    /// Returns [`BcryptError`] when hashing fails.
    pub(crate) async fn hash(&self) -> Result<String, BcryptError> {
        let token = self.0.clone();
        bcrypt_blocking(move || bcrypt::hash(token, BCRYPT_COST)).await
    }

    /// # Errors
    ///
    /// Returns [`BcryptError`] when `hash` is not a bcrypt hash.
    pub(crate) async fn verify(&self, hash: String) -> Result<bool, BcryptError> {
        let token = self.0.clone();
        bcrypt_blocking(move || bcrypt::verify(token, &hash)).await
    }
}

/// bcrypt is CPU-bound, so it runs off the async workers.
async fn bcrypt_blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, BcryptError> + Send + 'static,
) -> Result<T, BcryptError> {
    tokio::task::spawn_blocking(work)
        .await
        .expect("bcrypt does not panic")
}
