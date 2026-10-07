use agentic_jwt::auth51::*;
use serde_json::{Value, json};

fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/auth51.json")).unwrap()
}

#[test]
fn checksums_match_auth51_python_all_versions() {
    for vector in vectors()["checksums"].as_array().unwrap() {
        let c: Components = serde_json::from_value(vector["components"].clone()).unwrap();
        assert_eq!(c.checksum_v1().unwrap(), vector["v1"]);
        assert_eq!(c.checksum_v2().unwrap(), vector["v2"]);
        assert_eq!(c.checksum_v3().unwrap(), vector["v3"]);
        assert_eq!(c.checksum_v4().unwrap(), vector["v4"]);
        assert_eq!(
            c.checksum_v5_with(|src| Ok(vector["normalized_sources"][src]
                .as_str()
                .unwrap()
                .into()))
                .unwrap(),
            vector["v5"]
        );
    }
}

#[test]
fn native_source_normalizer_matches_auth51() {
    for vector in vectors()["checksums"].as_array().unwrap() {
        let c: Components = serde_json::from_value(vector["components"].clone()).unwrap();
        assert_eq!(c.checksum_v5().unwrap(), vector["v5"]);
    }
}

#[test]
fn scope_and_value_hash_vectors_match_python() {
    for vector in vectors()["scopes"].as_array().unwrap() {
        assert_eq!(
            derive_scope(
                vector["rs"].as_str().unwrap(),
                vector["method"].as_str().unwrap(),
                vector["path"].as_str().unwrap()
            )
            .unwrap(),
            vector["scope"]
        );
    }
    for vector in vectors()["actions"].as_array().unwrap() {
        assert_eq!(
            action_hash(vector["operation"].as_str().unwrap(), &vector["params"]).unwrap(),
            vector["hash"]
        );
    }
    assert!(derive_scope("bad:rs", "GET", "/").is_err());
    assert!(derive_scope("rs", "TRACE", "/").is_err());
}

#[test]
fn identity_ignores_remote_tools_and_delegation_but_binds_process_interface() {
    let mut c = Components {
        agent_id: "a".into(),
        prompt_template: "p".into(),
        tools: vec![],
        configuration: json!({}),
    };
    let before = c.checksum_v4().unwrap();
    c.tools
        .push(json!({"name":"remote", "source":"mcp", "parameters":{}}));
    c.tools
        .push(json!({"name":"child", "is_agent":true, "parameters":{}}));
    assert_eq!(before, c.checksum_v4().unwrap());
    c.tools
        .push(json!({"name":"local", "parameters":{"type":"object"}}));
    assert_ne!(before, c.checksum_v4().unwrap());
}

#[test]
fn source_reformatting_is_identity_preserving_but_logic_is_bound() {
    let mut c: Components =
        serde_json::from_value(vectors()["checksums"][1]["components"].clone()).unwrap();
    let before = c.checksum_v4().unwrap();
    c.tools[0]["source_code"] = json!("def z(x): return x+2");
    assert_eq!(before, c.checksum_v4().unwrap());
    let first = c
        .checksum_v5_with(|_| Ok("def z(x):\n    return x + 1".into()))
        .unwrap();
    let changed = c
        .checksum_v5_with(|_| Ok("def z(x):\n    return x + 2".into()))
        .unwrap();
    assert_ne!(first, changed);
}

#[test]
fn holder_and_sequence_hashes_match_python() {
    let v = vectors();
    assert_eq!(jwk_thumbprint(&v["jwk"]).unwrap(), v["jkt"]);
    assert_eq!(access_token_hash("test.access.token"), v["ath"]);
    let sequence: Vec<String> = serde_json::from_value(v["sequence"].clone()).unwrap();
    assert_eq!(
        sequence_hash(&sequence, v["current_repr"].as_str()),
        v["sequence_hash"]
    );
    assert_ne!(sequence_hash(&sequence, None), v["sequence_hash"]);
    assert!(jwk_thumbprint(&json!({"kty":"RSA"})).is_err());
}
