//! HTTP API tests against a fake Route 53 and a throwaway Postgres container.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Method, Request, StatusCode};
use hosted_dns::{
    AppState, Change, Config, MIGRATOR, RecordSet, RecordType, Zone, ZoneError, reap, router,
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ContainerAsync;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tower::ServiceExt;

const APEX: &str = "ployz.test";

/// Route 53 semantics in memory: batches are atomic and a delete must match exactly.
#[derive(Clone, Default)]
struct FakeZone(Arc<Mutex<HashMap<(String, RecordType), RecordSet>>>);

impl FakeZone {
    fn values(&self, name: &str, kind: RecordType) -> Option<Vec<String>> {
        let sets = self.0.lock().unwrap();
        sets.get(&(name.to_owned(), kind))
            .map(|set| set.values.clone())
    }

    fn is_empty(&self) -> bool {
        self.0.lock().unwrap().is_empty()
    }
}

impl Zone for FakeZone {
    async fn record_sets(&self, name: &str) -> Result<Vec<RecordSet>, ZoneError> {
        let sets = self.0.lock().unwrap();
        Ok(sets
            .values()
            .filter(|set| set.name == name)
            .cloned()
            .collect())
    }

    async fn apply(&self, changes: Vec<Change>) -> Result<(), ZoneError> {
        let mut sets = self.0.lock().unwrap();
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
        Ok(())
    }
}

struct Harness {
    app: Router,
    state: Arc<AppState<FakeZone>>,
    zone: FakeZone,
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
    let config = Config {
        apex: APEX.into(),
        mints_per_hour,
        client_ip_header: Some("x-real-ip".parse().unwrap()),
    };
    let state = Arc::new(AppState::new(db.clone(), zone.clone(), config));
    let app = router(Arc::clone(&state))
        .layer(MockConnectInfo(SocketAddr::from(([198, 51, 100, 1], 4000))));
    Harness {
        app,
        state,
        zone,
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
    assert_eq!(token.len(), 40);

    // Taken and reserved labels get a 4-character suffix.
    let (taken, _) = h.mint(Some("acme")).await;
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
    let (status, body) = h
        .authed(Method::POST, "nope.ployz.test", "/lease", "wrong", None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "not_found");
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
