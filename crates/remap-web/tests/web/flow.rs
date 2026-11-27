// SPDX-License-Identifier: GPL-3.0-or-later
//! The API relays real control commands: validate, preview, apply, read.

use hyper::StatusCode;
use serde_json::{Value, json};

use crate::support::{Fixture, TestResult, assert_security_headers, uuid_v4};

fn set(pattern: &str, target: &str) -> Value {
    json!({
        "kind": "set",
        "pattern": pattern,
        "target": target,
        "host_policy": "preserve-client",
        "enabled": true
    })
}

#[tokio::test]
async fn validate_preview_apply_then_list() -> TestResult {
    let fixture = Fixture::start(None).await?;
    let validated = fixture
        .post(
            "/api/validate",
            &json!({"pattern": "API.Test", "target": "127.0.0.1", "host_policy": "preserve-client"}),
        )
        .await?;
    assert_eq!(validated.status, StatusCode::OK);
    assert_security_headers(&validated);
    let validation = validated.json()?;
    assert_eq!(validation["pattern"], "api.test");
    assert!(validation["target_kind"].is_string());

    let changes = json!([set("api.test", "127.0.0.1")]);
    let preview = fixture
        .post("/api/preview", &json!({"changes": changes}))
        .await?
        .json()?;
    assert_eq!(preview["base_revision"], 0);
    assert_eq!(preview["will_change"], true);
    assert_eq!(preview["effects"][0]["action"], "created");

    let operation = uuid_v4()?;
    let apply = json!({
        "expected_revision": preview["base_revision"],
        "operation_id": operation,
        "changes": changes
    });
    let receipt = fixture.post("/api/apply", &apply).await?;
    assert_eq!(receipt.status, StatusCode::OK);
    let receipt = receipt.json()?;
    assert_eq!(receipt["revision"], 1);
    assert_eq!(receipt["changed"], true);
    assert_eq!(receipt["operation_id"], operation);
    // A retry of the identical request reports the same commit.
    assert_eq!(fixture.post("/api/apply", &apply).await?.json()?, receipt);

    let list = fixture.get("/api/mappings").await?.json()?;
    assert_eq!(list["revision"], 1);
    assert_eq!(list["mappings"][0]["pattern"], "api.test");
    assert_eq!(list["next_cursor"], Value::Null);

    let mapping = fixture.get("/api/mapping?pattern=api.test").await?.json()?;
    assert_eq!(mapping["target"], "127.0.0.1");
    let absent = fixture.get("/api/mapping?pattern=none.test").await?;
    assert_eq!(
        (absent.status, absent.json()?),
        (StatusCode::OK, Value::Null)
    );
    let resolved = fixture.get("/api/resolve?name=API.test").await?.json()?;
    assert_eq!(resolved["mapping"]["pattern"], "api.test");
    let status = fixture.get("/api/status").await?.json()?;
    assert_eq!(
        (status["revision"].clone(), status["mapping_count"].clone()),
        (json!(1), json!(1))
    );
    fixture.stop().await
}

#[tokio::test]
async fn the_list_includes_disabled_mappings_and_every_page() -> TestResult {
    let fixture = Fixture::start(None).await?;
    let mut revision = 0;
    for batch in 0..3 {
        let count = if batch < 2 { 64 } else { 2 };
        let changes = (0..count)
            .map(|index| set(&format!("host-{batch}-{index:02}.test"), "127.0.0.1"))
            .collect::<Vec<_>>();
        let receipt = fixture
            .post(
                "/api/apply",
                &json!({"expected_revision": revision, "operation_id": uuid_v4()?, "changes": changes}),
            )
            .await?
            .json()?;
        revision = receipt["revision"].as_u64().unwrap_or_default();
    }
    let disable = json!([{"kind": "disable", "pattern": "host-0-00.test"}]);
    let receipt = fixture
        .post(
            "/api/apply",
            &json!({"expected_revision": revision, "operation_id": uuid_v4()?, "changes": disable}),
        )
        .await?
        .json()?;
    assert_eq!(receipt["effects"][0]["action"], "disabled");

    let list = fixture.get("/api/mappings").await?.json()?;
    let mappings = list["mappings"].as_array().cloned().unwrap_or_default();
    assert_eq!(mappings.len(), 130, "more than one 128-mapping page");
    assert_eq!(list["revision"], receipt["revision"]);
    let disabled = mappings
        .iter()
        .find(|mapping| mapping["pattern"] == "host-0-00.test");
    assert_eq!(
        disabled.map(|mapping| mapping["enabled"].clone()),
        Some(json!(false))
    );
    fixture.stop().await
}

#[tokio::test]
async fn a_stale_revision_is_a_409_with_the_daemon_diagnostic() -> TestResult {
    let fixture = Fixture::start(None).await?;
    let first = json!({
        "expected_revision": 0,
        "operation_id": uuid_v4()?,
        "changes": [set("api.test", "127.0.0.1")]
    });
    assert_eq!(
        fixture.post("/api/apply", &first).await?.status,
        StatusCode::OK
    );
    let stale = json!({
        "expected_revision": 0,
        "operation_id": uuid_v4()?,
        "changes": [set("web.test", "127.0.0.1")]
    });
    let refused = fixture.post("/api/apply", &stale).await?;
    assert_eq!(refused.status, StatusCode::CONFLICT);
    assert_security_headers(&refused);
    let diagnostic = refused.json()?;
    assert_eq!(diagnostic["code"], "E_REVISION_CONFLICT");
    assert!(
        diagnostic["message"]
            .as_str()
            .is_some_and(|message| message.contains("revision 1"))
    );
    assert!(diagnostic["hint"].is_string());
    assert_eq!(diagnostic["retryable"], false);
    fixture.stop().await
}

#[tokio::test]
async fn wait_reports_a_change_after_a_write() -> TestResult {
    let fixture = Fixture::start(None).await?;
    let waiting = fixture.get("/api/wait?after=0");
    let write = async {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let apply = json!({
            "expected_revision": 0,
            "operation_id": uuid_v4()?,
            "changes": [set("api.test", "127.0.0.1")]
        });
        fixture.post("/api/apply", &apply).await
    };
    let (notice, applied) = tokio::join!(waiting, write);
    assert_eq!(applied?.status, StatusCode::OK);
    let notice = notice?.json()?;
    assert_eq!(notice, json!({"revision": 1, "changed": true}));
    let later = fixture.get("/api/wait?after=0").await?.json()?;
    assert_eq!(later["changed"], true);
    fixture.stop().await
}

#[tokio::test]
async fn an_unchanged_registry_answers_the_wait_within_six_seconds() -> TestResult {
    let fixture = Fixture::start(None).await?;
    let started = tokio::time::Instant::now();
    let notice = fixture.get("/api/wait?after=0").await?.json()?;
    let waited = started.elapsed();
    assert_eq!(notice, json!({"revision": 0, "changed": false}));
    assert!(waited >= std::time::Duration::from_secs(4), "{waited:?}");
    assert!(waited < std::time::Duration::from_secs(6), "{waited:?}");
    fixture.stop().await
}

#[tokio::test]
async fn refusals_carry_daemon_and_web_diagnostics() -> TestResult {
    let fixture = Fixture::start(None).await?;
    let invalid = fixture
        .post(
            "/api/validate",
            &json!({"pattern": "api.test", "target": "http://", "host_policy": "preserve-client"}),
        )
        .await?;
    assert_eq!(invalid.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(invalid.code()?, "E_INVALID_TARGET");
    assert!(invalid.json()?["hint"].is_string());

    let unknown_field = fixture
        .post("/api/preview", &json!({"changes": [], "extra": 1}))
        .await?;
    assert_eq!(unknown_field.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(unknown_field.code()?, "web-body-invalid");
    let not_object = fixture.post("/api/preview", &json!([1, 2])).await?;
    assert_eq!(
        (not_object.status, not_object.code()?),
        (StatusCode::BAD_REQUEST, "web-body-malformed".to_owned())
    );
    let bad_operation = fixture
        .post(
            "/api/apply",
            &json!({"expected_revision": 0, "operation_id": "x", "changes": [set("a.test", "127.0.0.1")]}),
        )
        .await?;
    assert_eq!(bad_operation.code()?, "E_OPERATION_ID");
    for path in [
        "/api/resolve",
        "/api/resolve?name=a&name=b",
        "/api/wait?after=x",
        "/api/mapping?name=a",
    ] {
        let reply = fixture.get(path).await?;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(reply.code()?, "web-query-invalid");
    }
    let long = format!("/api/resolve?name={}", "a".repeat(3000));
    assert_eq!(fixture.get(&long).await?.code()?, "web-query-invalid");
    let encoded = fixture.get("/api/mapping?pattern=%2A.lab").await?;
    assert_eq!(
        (encoded.status, encoded.json()?),
        (StatusCode::OK, Value::Null)
    );
    fixture.stop().await
}
