//! HTTP API tests against a fake Route 53, a fake ACME CA and a throwaway Postgres container.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Method, Request, StatusCode};
use hosted_dns::{
    AppState, Ca, CaError, Change, ChangeId, Config, MIGRATOR, RecordSet, RecordType, Zone,
    ZoneError, reap, router,
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ContainerAsync;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tower::ServiceExt;

const APEX: &str = "ployz.test";
const MINT_KEY: &str = "test-mint-key";

type Sets = HashMap<(String, RecordType), RecordSet>;

/// Route 53 semantics in memory: batches are atomic, a delete must match
/// exactly, and changes reach the public view (what resolvers see) only once
/// someone waits for them to sync.
#[derive(Clone, Default)]
struct FakeZone {
    sets: Arc<Mutex<Sets>>,
    public: Arc<Mutex<Sets>>,
    fail_next_apply: Arc<Mutex<bool>>,
}

impl FakeZone {
    fn values(&self, name: &str, kind: RecordType) -> Option<Vec<String>> {
        let sets = self.sets.lock().unwrap();
        sets.get(&(name.to_owned(), kind))
            .map(|set| set.values.clone())
    }

    fn resolve(&self, name: &str, kind: RecordType) -> Vec<String> {
        let public = self.public.lock().unwrap();
        public
            .get(&(name.to_owned(), kind))
            .map(|set| set.values.clone())
            .unwrap_or_default()
    }

    fn is_empty(&self) -> bool {
        self.sets.lock().unwrap().is_empty()
    }
}

impl Zone for FakeZone {
    async fn record_sets(&self, name: &str) -> Result<Vec<RecordSet>, ZoneError> {
        let sets = self.sets.lock().unwrap();
        Ok(sets
            .values()
            .filter(|set| set.name == name)
            .cloned()
            .collect())
    }

    async fn apply(&self, changes: Vec<Change>) -> Result<ChangeId, ZoneError> {
        if std::mem::take(&mut *self.fail_next_apply.lock().unwrap()) {
            return Err(ZoneError("Route 53 is down".into()));
        }
        let mut sets = self.sets.lock().unwrap();
        let mut next = sets.clone();
        for change in changes {
            match change {
                Change::Upsert(set) => {
                    next.insert((set.name.clone(), set.kind), set);
                }
                Change::Delete(set) => {
                    if next.remove(&(set.name.clone(), set.kind)).as_ref() != Some(&set) {
                        return Err(ZoneError(format!("delete of {} does not match", set.name)));
                    }
                }
            }
        }
        *sets = next;
        Ok(ChangeId("change".into()))
    }

    async fn wait_in_sync(&self, _change: &ChangeId) -> Result<(), ZoneError> {
        *self.public.lock().unwrap() = self.sets.lock().unwrap().clone();
        Ok(())
    }
}

/// An ACME CA that validates DNS-01 by resolving through the fake zone.
#[derive(Clone)]
struct FakeCa {
    zone: FakeZone,
    rate_limit_next_order: Arc<Mutex<Option<Duration>>>,
    refuse_next_finalize: Arc<Mutex<bool>>,
}

struct FakeOrder {
    names: Vec<String>,
    values: Vec<String>,
}

impl Ca for FakeCa {
    type Order = FakeOrder;

    async fn new_order(&self, names: &[String]) -> Result<(FakeOrder, Vec<String>), CaError> {
        if let Some(delay) = self.rate_limit_next_order.lock().unwrap().take() {
            return Err(CaError::RateLimited {
                until: SystemTime::now() + delay,
            });
        }
        let values: Vec<String> = names
            .iter()
            .enumerate()
            .map(|(i, name)| format!("dns01-{i}-{name}"))
            .collect();
        let order = FakeOrder {
            names: names.to_vec(),
            values: values.clone(),
        };
        Ok((order, values))
    }

    async fn finalize(&self, order: FakeOrder, csr_der: &[u8]) -> Result<String, CaError> {
        if std::mem::take(&mut *self.refuse_next_finalize.lock().unwrap()) {
            return Err(CaError::Failed(
                "urn:ietf:params:acme:error:serverInternal".into(),
            ));
        }
        for name in &order.names {
            let base = name.trim_start_matches("*.");
            let published = self
                .zone
                .resolve(&format!("_acme-challenge.{base}"), RecordType::Txt);
            if !order.values.iter().all(|value| published.contains(value)) {
                return Err(CaError::Failed(format!("dns-01 failed for {name}")));
            }
        }
        let csr = String::from_utf8_lossy(csr_der);
        assert!(order.names.iter().all(|name| csr.contains(name.as_str())));
        Ok(format!(
            "-----BEGIN CERTIFICATE-----\nleaf for {}\n-----END CERTIFICATE-----\n\
             -----BEGIN CERTIFICATE-----\nintermediate\n-----END CERTIFICATE-----\n",
            order.names.join(",")
        ))
    }
}

struct Harness {
    app: Router,
    state: Arc<AppState<FakeZone, FakeCa>>,
    zone: FakeZone,
    ca: FakeCa,
    db: PgPool,
    _postgres: ContainerAsync<Postgres>,
}

async fn harness(mints_per_hour: u32) -> Harness {
    let postgres = Postgres::default().start().await.unwrap();
    let url = format!(
        "postgres://postgres:postgres@{}:{}/postgres",
        postgres.get_host().await.unwrap(),
        postgres.get_host_port_ipv4(5432).await.unwrap()
    );
    let db = PgPool::connect(&url).await.unwrap();
    MIGRATOR.run(&db).await.unwrap();
    let zone = FakeZone::default();
    let ca = FakeCa {
        zone: zone.clone(),
        rate_limit_next_order: Arc::default(),
        refuse_next_finalize: Arc::default(),
    };
    let config = Config {
        apex: APEX.into(),
        mints_per_hour,
        client_ip_header: Some("x-real-ip".parse().unwrap()),
        mint_keys: vec!["other-key".into(), MINT_KEY.into()],
    };
    let state = Arc::new(AppState::new(db.clone(), zone.clone(), ca.clone(), config));
    let app = router(Arc::clone(&state))
        .layer(MockConnectInfo(SocketAddr::from(([198, 51, 100, 1], 4000))));
    Harness {
        app,
        state,
        zone,
        ca,
        db,
        _postgres: postgres,
    }
}

impl Harness {
    async fn call(
        &self,
        method: Method,
        uri: &str,
        headers: &[(&str, &str)],
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder().method(method).uri(uri);
        for (key, value) in headers {
            request = request.header(*key, *value);
        }
        let body = match body {
            Some(body) => {
                request = request.header("content-type", "application/json");
                Body::from(body.to_string())
            }
            None => Body::empty(),
        };
        let response = self
            .app
            .clone()
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, body)
    }

    async fn mint(&self, preferred: Option<&str>) -> (String, String) {
        let (status, body) = self
            .call(
                Method::POST,
                "/domains",
                &[],
                Some(json!({ "preferred": preferred })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        (
            body["name"].as_str().unwrap().to_owned(),
            body["token"].as_str().unwrap().to_owned(),
        )
    }

    async fn authed(
        &self,
        method: Method,
        name: &str,
        path: &str,
        token: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let bearer = format!("Bearer {token}");
        let uri = format!("/domains/{name}{path}");
        self.call(method, &uri, &[("authorization", &bearer)], body)
            .await
    }

    async fn put_records(&self, name: &str, token: &str, records: Value) -> StatusCode {
        self.authed(Method::PUT, name, "/records", token, Some(records))
            .await
            .0
    }
}

fn label_of(name: &str) -> &str {
    name.strip_suffix(&format!(".{APEX}")).unwrap()
}

#[tokio::test]
async fn mint_grants_preferred_suffixed_or_random_labels() {
    let h = harness(100).await;

    let (name, token) = h.mint(Some("acme")).await;
    assert_eq!(name, format!("acme.{APEX}"));
    assert!(
        token
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
        "{token}"
    );

    // Taken and reserved labels get a 4-character suffix.
    let (taken, other_token) = h.mint(Some("acme")).await;
    assert_ne!(token, other_token);
    let suffix = label_of(&taken).strip_prefix("acme-").unwrap();
    assert_eq!(suffix.len(), 4);
    let (reserved, _) = h.mint(Some("www")).await;
    assert!(label_of(&reserved).starts_with("www-"), "{reserved}");

    // Invalid, edge-hyphen and missing labels get a fully random label.
    for preferred in [Some("ab"), Some("-acme"), Some("Acme"), None] {
        let (random, _) = h.mint(preferred).await;
        let label = label_of(&random);
        assert_eq!(label.len(), 10, "{preferred:?} -> {random}");
        assert!(!label.contains('-'), "{random}");
    }

    // No body at all is a random label too.
    let (status, body) = h.call(Method::POST, "/domains", &[], None).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(label_of(body["name"].as_str().unwrap()).len(), 10);
}

#[tokio::test]
async fn mint_is_rate_limited_per_source_ip() {
    let h = harness(2).await;
    for (ip, expected) in [
        ("203.0.113.7", StatusCode::CREATED),
        ("203.0.113.7", StatusCode::CREATED),
        ("203.0.113.7", StatusCode::TOO_MANY_REQUESTS),
        ("203.0.113.8", StatusCode::CREATED),
    ] {
        let (status, body) = h
            .call(
                Method::POST,
                "/domains",
                &[("x-real-ip", ip)],
                Some(json!({})),
            )
            .await;
        assert_eq!(status, expected, "{ip}: {body}");
    }
}

#[tokio::test]
async fn mint_key_skips_the_limit_and_a_wrong_key_is_refused() {
    let h = &harness(1).await;
    let mint_with = |authorization: Option<&'static str>| {
        let headers: Vec<(&str, &str)> = authorization
            .map(|value| ("authorization", value))
            .into_iter()
            .collect();
        async move {
            h.call(Method::POST, "/domains", &headers, Some(json!({})))
                .await
        }
    };
    let key = "Bearer test-mint-key";

    // No header: anonymous and limited.
    assert_eq!(mint_with(None).await.0, StatusCode::CREATED);
    assert_eq!(mint_with(None).await.0, StatusCode::TOO_MANY_REQUESTS);
    // A known key bypasses the limit from the same address.
    assert_eq!(mint_with(Some(key)).await.0, StatusCode::CREATED);
    assert_eq!(mint_with(Some(key)).await.0, StatusCode::CREATED);
    // A wrong or malformed key is refused, not treated as anonymous.
    for wrong in ["Bearer test-mint-kez", "Bearer ", "test-mint-key"] {
        let (status, body) = mint_with(Some(wrong)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{wrong}");
        assert_eq!(body["error"], "unauthorized");
    }
}

#[tokio::test]
async fn rotate_kills_the_old_token_at_once() {
    let h = harness(100).await;
    let (name, old) = h.mint(Some("rotating")).await;

    let (status, body) = h.authed(Method::POST, &name, "/rotate", &old, None).await;
    assert_eq!(status, StatusCode::OK);
    let new = body["token"].as_str().unwrap().to_owned();
    assert_ne!(new, old);

    let (status, body) = h.authed(Method::POST, &name, "/lease", &old, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "unauthorized");
    let (status, _) = h.authed(Method::POST, &name, "/lease", &new, None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn authentication_failures_are_distinguished() {
    let h = harness(100).await;
    let (name, _) = h.mint(Some("guarded")).await;

    let (status, _) = h
        .call(Method::POST, &format!("/domains/{name}/lease"), &[], None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = h.authed(Method::POST, &name, "/lease", "wrong", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Unknown names and names that could never be granted look the same.
    for unknown in [
        "nope.ployz.test",
        "evil.example.com",
        "a.b.ployz.test",
        "-x.ployz.test",
        "ployz.test",
    ] {
        let (status, body) = h
            .authed(Method::POST, unknown, "/lease", "wrong", None)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{unknown}");
        assert_eq!(body["error"], "not_found");
    }
}

#[tokio::test]
async fn records_put_replaces_the_apex_set_and_writes_the_wildcard() {
    let h = harness(100).await;
    let (name, token) = h.mint(Some("records")).await;
    let wildcard = format!("*.{name}");

    let both =
        json!({ "a": ["203.0.113.2", "203.0.113.1", "203.0.113.2"], "aaaa": ["2001:db8::1"] });
    assert_eq!(
        h.put_records(&name, &token, both.clone()).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        h.zone.values(&name, RecordType::A).unwrap(),
        ["203.0.113.1", "203.0.113.2"]
    );
    assert_eq!(
        h.zone.values(&name, RecordType::Aaaa).unwrap(),
        ["2001:db8::1"]
    );
    assert_eq!(
        h.zone.values(&wildcard, RecordType::Cname).unwrap(),
        [name.as_str()]
    );

    // Idempotent.
    assert_eq!(
        h.put_records(&name, &token, both).await,
        StatusCode::NO_CONTENT
    );

    // Full set: an omitted family is removed.
    let v4_only = json!({ "a": ["198.51.100.9"] });
    assert_eq!(
        h.put_records(&name, &token, v4_only).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        h.zone.values(&name, RecordType::A).unwrap(),
        ["198.51.100.9"]
    );
    assert_eq!(h.zone.values(&name, RecordType::Aaaa), None);
    assert_eq!(
        h.zone.values(&wildcard, RecordType::Cname).unwrap(),
        [name.as_str()]
    );
}

#[tokio::test]
async fn records_put_refuses_empty_private_and_malformed_sets() {
    let h = harness(100).await;
    let (name, token) = h.mint(Some("strict")).await;

    for records in [
        json!({}),
        json!({ "a": [] }),
        json!({ "a": ["10.0.0.1"] }),
        json!({ "a": ["127.0.0.1"] }),
        json!({ "aaaa": ["fd00::1"] }),
    ] {
        let (status, body) = h
            .authed(
                Method::PUT,
                &name,
                "/records",
                &token,
                Some(records.clone()),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{records}");
        assert_eq!(body["error"], "invalid_records");
    }
    let (status, body) = h
        .authed(
            Method::PUT,
            &name,
            "/records",
            &token,
            Some(json!({ "a": ["nope"] })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(h.zone.is_empty());
}

#[tokio::test]
async fn authenticated_calls_renew_the_seven_day_lease() {
    let h = harness(100).await;
    let (name, token) = h.mint(Some("leased")).await;
    sqlx::query("UPDATE domains SET lease_expires_at = now() + interval '1 hour'")
        .execute(&h.db)
        .await
        .unwrap();

    let records = json!({ "a": ["203.0.113.1"] });
    assert_eq!(
        h.put_records(&name, &token, records).await,
        StatusCode::NO_CONTENT
    );
    let renewed: bool = sqlx::query_scalar(
        "SELECT lease_expires_at > now() + interval '6 days 23 hours' FROM domains",
    )
    .fetch_one(&h.db)
    .await
    .unwrap();
    assert!(renewed);
}

#[tokio::test]
async fn release_retires_the_name_forever() {
    let h = harness(100).await;
    let (name, token) = h.mint(Some("goner")).await;
    let records = json!({ "a": ["203.0.113.1"], "aaaa": ["2001:db8::1"] });
    assert_eq!(
        h.put_records(&name, &token, records).await,
        StatusCode::NO_CONTENT
    );

    let (status, _) = h.authed(Method::DELETE, &name, "", &token, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(h.zone.is_empty());

    let (status, body) = h.authed(Method::POST, &name, "/lease", &token, None).await;
    assert_eq!(status, StatusCode::GONE);
    assert_eq!(body["error"], "retired");
    let (reissued, _) = h.mint(Some("goner")).await;
    assert_ne!(reissued, name);
}

#[tokio::test]
async fn reaper_frees_unused_reservations_and_retires_expired_leases() {
    let h = harness(100).await;
    let (unused, unused_token) = h.mint(Some("unused")).await;
    let (fresh, fresh_token) = h.mint(Some("fresh")).await;
    let (expired, expired_token) = h.mint(Some("expired")).await;
    let (live, live_token) = h.mint(Some("live")).await;
    let records = json!({ "a": ["203.0.113.1"] });
    assert_eq!(
        h.put_records(&expired, &expired_token, records.clone())
            .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        h.put_records(&live, &live_token, records).await,
        StatusCode::NO_CONTENT
    );

    sqlx::query("UPDATE domains SET reserved_at = now() - interval '25 hours' WHERE name <> $1")
        .bind(&fresh)
        .execute(&h.db)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE domains SET lease_expires_at = now() - interval '1 minute' WHERE name = $1",
    )
    .bind(&expired)
    .execute(&h.db)
    .await
    .unwrap();
    reap(&h.state).await.unwrap();

    // Unused for 24 hours: gone, and the label is free again.
    let (status, _) = h
        .authed(Method::POST, &unused, "/lease", &unused_token, None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(h.mint(Some("unused")).await.0, unused);
    // Expired lease: records removed, name retired.
    let (status, _) = h
        .authed(Method::POST, &expired, "/lease", &expired_token, None)
        .await;
    assert_eq!(status, StatusCode::GONE);
    assert_eq!(h.zone.values(&expired, RecordType::A), None);
    assert_eq!(
        h.zone.values(&format!("*.{expired}"), RecordType::Cname),
        None
    );
    // Young reservations and live leases stay.
    let (status, _) = h
        .authed(Method::POST, &fresh, "/lease", &fresh_token, None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = h
        .authed(Method::POST, &live, "/lease", &live_token, None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(h.zone.values(&live, RecordType::A).is_some());
}

fn csr(names: &[&str]) -> String {
    let key = rcgen::KeyPair::generate().unwrap();
    let names = names
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    let mut params = rcgen::CertificateParams::new(names).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.serialize_request(&key).unwrap().pem().unwrap()
}

#[tokio::test]
async fn certificate_is_issued_through_dns01_and_the_challenge_removed() {
    let h = harness(100).await;
    let (name, token) = h.mint(Some("secure")).await;
    let wildcard = format!("*.{name}");

    let body = json!({ "csr": csr(&[&name, &wildcard]) });
    let (status, body) = h
        .authed(Method::POST, &name, "/certificate", &token, Some(body))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let chain = body["certificate_chain_pem"].as_str().unwrap();
    assert!(chain.contains(&format!("leaf for {name},{wildcard}")));
    assert_eq!(chain.matches("BEGIN CERTIFICATE").count(), 2);

    let challenge = format!("_acme-challenge.{name}");
    assert_eq!(h.zone.values(&challenge, RecordType::Txt), None);
}

#[tokio::test]
async fn certificate_refuses_csrs_outside_the_token_holders_name() {
    let h = harness(100).await;
    let (name, token) = h.mint(Some("scoped")).await;
    let (other, _) = h.mint(Some("victim")).await;
    let wildcard = format!("*.{name}");
    let other_wildcard = format!("*.{other}");

    let with_cn = {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec![name.clone(), wildcard.clone()]).unwrap();
        // rcgen's default subject CN is not one of the names.
        params.serialize_request(&key).unwrap().pem().unwrap()
    };
    for pem in [
        csr(&[&name]),
        csr(&[&wildcard]),
        csr(&[&name, &wildcard, &other]),
        csr(&[&other, &other_wildcard]),
        csr(&[&name, "*.*.scoped.ployz.test"]),
        with_cn,
        "not a csr".to_owned(),
    ] {
        let (status, body) = h
            .authed(
                Method::POST,
                &name,
                "/certificate",
                &token,
                Some(json!({ "csr": pem })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["error"], "invalid_csr");
    }

    // Only the token holder of the name may ask.
    let (status, _) = h
        .authed(
            Method::POST,
            &other,
            "/certificate",
            &token,
            Some(json!({ "csr": csr(&[&other, &other_wildcard]) })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(h.zone.is_empty());
}

#[tokio::test]
async fn certificate_honours_the_cas_retry_after() {
    let h = harness(100).await;
    let (name, token) = h.mint(Some("patient")).await;
    let body = json!({ "csr": csr(&[&name, &format!("*.{name}")]) });
    *h.ca.rate_limit_next_order.lock().unwrap() = Some(Duration::from_secs(120));

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/domains/{name}/certificate"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = h.app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after: u64 = response.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((100..=120).contains(&retry_after), "{retry_after}");

    // The CA would accept now, but the service waits out Retry-After for every name.
    let (status, body) = h
        .authed(Method::POST, &name, "/certificate", &token, Some(body))
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"], "ca_rate_limited");
}

#[tokio::test]
async fn failed_issuance_still_removes_the_challenge() {
    let h = harness(100).await;
    let (name, token) = h.mint(Some("unlucky")).await;
    *h.ca.refuse_next_finalize.lock().unwrap() = true;

    let body = json!({ "csr": csr(&[&name, &format!("*.{name}")]) });
    let (status, body) = h
        .authed(Method::POST, &name, "/certificate", &token, Some(body))
        .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body["error"], "ca_error");
    assert_eq!(
        h.zone
            .values(&format!("_acme-challenge.{name}"), RecordType::Txt),
        None
    );
}

#[tokio::test]
async fn reaper_never_frees_a_name_that_asked_for_a_certificate() {
    let h = harness(100).await;
    let (name, token) = h.mint(Some("certified")).await;
    let body = json!({ "csr": csr(&[&name, &format!("*.{name}")]) });
    let (status, _) = h
        .authed(Method::POST, &name, "/certificate", &token, Some(body))
        .await;
    assert_eq!(status, StatusCode::OK);

    // No records were ever published, and the reservation is over 24 hours old.
    sqlx::query("UPDATE domains SET reserved_at = now() - interval '25 hours'")
        .execute(&h.db)
        .await
        .unwrap();
    reap(&h.state).await.unwrap();

    let (status, _) = h.authed(Method::POST, &name, "/lease", &token, None).await;
    assert_eq!(status, StatusCode::OK);
    let (reissued, _) = h.mint(Some("certified")).await;
    assert_ne!(reissued, name);
}

#[tokio::test]
async fn reaper_keeps_an_expired_name_when_route53_fails_and_retries() {
    let h = harness(100).await;
    let (name, token) = h.mint(Some("stubborn")).await;
    let records = json!({ "a": ["203.0.113.1"] });
    assert_eq!(
        h.put_records(&name, &token, records).await,
        StatusCode::NO_CONTENT
    );
    sqlx::query("UPDATE domains SET lease_expires_at = now() - interval '1 minute'")
        .execute(&h.db)
        .await
        .unwrap();

    *h.zone.fail_next_apply.lock().unwrap() = true;
    assert!(reap(&h.state).await.is_err());
    let retired: bool = sqlx::query_scalar("SELECT retired_at IS NOT NULL FROM domains")
        .fetch_one(&h.db)
        .await
        .unwrap();
    assert!(!retired);
    assert!(h.zone.values(&name, RecordType::A).is_some());

    reap(&h.state).await.unwrap();
    let (status, _) = h.authed(Method::POST, &name, "/lease", &token, None).await;
    assert_eq!(status, StatusCode::GONE);
    assert_eq!(h.zone.values(&name, RecordType::A), None);
}
