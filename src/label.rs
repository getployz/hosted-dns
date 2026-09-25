//! Label choice for new Cluster Domains.

use rand::Rng;

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

/// `[a-z0-9-]{3,40}` with no hyphen at either edge.
fn is_valid(label: &str) -> bool {
    (3..=40).contains(&label.len())
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

/// Random `[a-z0-9]` string; also used for bearer tokens.
pub(crate) fn random_string(len: usize) -> String {
    let mut rng = rand::rng();
    (0..len)
        .map(|_| char::from(ALPHABET[rng.random_range(0..ALPHABET.len())]))
        .collect()
}
