use agentic_jwt::auth51::*;
use serde_json::{Value, json};
use std::sync::{Arc, OnceLock};
const NOW: u64 = 1_800_000_000;
fn key() -> Arc<IssuerKey> {
    static KEY: OnceLock<Arc<IssuerKey>> = OnceLock::new();
    KEY.get_or_init(|| Arc::new(IssuerKey::generate().unwrap()))
        .clone()
}
fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/auth51-policy.json")).unwrap()
}

#[test]
fn local_mint_matches_actual_auth51_functions() {
    for case in vectors()["mint"].as_array().unwrap() {
        let mut authority = LocalAuthority::new("https://local.example", "app", key()).unwrap();
        for a in case["agents"].as_array().unwrap() {
            let checksums = [
                "checksum",
                "checksum_v1",
                "checksum_v3",
                "checksum_v4",
                "checksum_v5",
            ]
            .iter()
            .filter_map(|k| a[*k].as_str().map(str::to_string))
            .collect();
            authority.provision(RegisteredAgent {
                agent_id: a["agent_id"].as_str().unwrap().into(),
                registration_id: a["registration_id"].as_str().unwrap().into(),
                checksums,
                subagents: serde_json::from_value(a["subagents"].clone()).unwrap(),
                public_jwk: None,
                grant: serde_json::from_value(a["grant"].clone()).unwrap(),
            });
        }
        for w in case["workflows"].as_array().unwrap() {
            authority
                .register_workflow(serde_json::from_value(w.clone()).unwrap())
                .unwrap();
        }
        if let Some(e) = case.get("execution") {
            let mut e = e.clone();
            e["app_id"] = json!("app");
            authority
                .restore_execution(serde_json::from_value(e).unwrap())
                .unwrap();
        }
        let req: MintRequest = serde_json::from_value(case["request"].clone()).unwrap();
        let scopes: Vec<String> = serde_json::from_value(case["caller_scopes"].clone()).unwrap();
        let got = authority.evaluate(&req, &scopes, NOW);
        let expected = case["expected"]["status"].as_u64().unwrap();
        match got {
            Ok(mut claims) => {
                assert_eq!(expected, 200, "{}", case["name"]);
                claims.as_object_mut().unwrap().remove("jti");
                assert_eq!(claims, case["expected"]["claims"], "{}", case["name"]);
            }
            Err(Error::Policy(status, _)) => {
                assert_eq!(u64::from(status), expected, "{}", case["name"])
            }
            Err(e) => panic!("{}: {e}", case["name"]),
        }
    }
}

#[test]
fn policy_and_predicates_match_shared_python_governance() {
    let policy = TierPolicy::default();
    let vectors = vectors();
    for c in vectors["classification"].as_array().unwrap() {
        let tags: Vec<String> = serde_json::from_value(c["tags"].clone()).unwrap();
        assert_eq!(
            policy
                .classify(
                    c["action"].as_str().unwrap(),
                    &tags,
                    c["risk"].as_str().unwrap()
                )
                .unwrap(),
            c["tier"],
            "{c}"
        );
    }
    for c in vectors["operators"].as_array().unwrap() {
        assert_eq!(
            apply_op(c["op"].as_str().unwrap(), &c["left"], &c["right"]),
            c["expected"].as_bool().unwrap(),
            "{c}"
        );
    }
}

#[test]
fn source_normalization_matches_authority_ast_unparse() {
    let mut mismatches = vec![];
    for c in vectors()["sources"].as_array().unwrap() {
        let got = normalize_python_source(c["source"].as_str().unwrap()).unwrap();
        if got != c["normalized"] {
            mismatches.push(format!(
                "source={} got={got:?} expected={}",
                c["source"], c["normalized"]
            ));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

#[test]
fn native_analysis_synthesis_and_resolution_match_governance() {
    let vectors = vectors();
    let policy = TierPolicy::default();
    for c in vectors["sources"].as_array().unwrap() {
        assert_eq!(
            serde_json::to_value(analyze_source(c["source"].as_str().unwrap())).unwrap(),
            c["effects"],
            "{}",
            c["source"]
        );
    }
    for c in vectors["synthesis"].as_array().unwrap() {
        let runs: Vec<Vec<Observation>> = serde_json::from_value(c["runs"].clone()).unwrap();
        let caps: Vec<Capability> = serde_json::from_value(c["capabilities"].clone()).unwrap();
        assert_eq!(
            synthesize("derived", &runs, &caps, &policy, c["min_support"].as_u64()),
            c["expected"]
        );
    }
    for c in vectors["consequence"].as_array().unwrap() {
        let bundle = serde_json::from_value(c["bundle"].clone()).unwrap();
        assert_eq!(
            resolve_consequence(&bundle, &policy).unwrap(),
            c["expected"]
        );
    }
}

#[test]
fn offline_rs256_and_dpop_enforce_sender_scope_url_and_values() {
    let key = key();
    let holder = ProofKey::generate();
    let uri = "https://resource.example/transfer?a=1";
    let claims = json!({"iss":"https://issuer.example","sub":"agent","aud":"resource","iat":NOW,"exp":NOW+300,
        "scope":"write","cnf":{"jkt":holder.thumbprint().unwrap()}});
    let token = key.sign(&claims).unwrap();
    let proof = holder.proof("POST", uri, Some(&token), None, NOW).unwrap();
    let values = json!({});
    let scopes = vec!["write".into()];
    let mut request = ResourceRequest {
        method: "POST",
        uri,
        audience: Some("resource"),
        scopes: &scopes,
        proof: Some(&proof),
        legacy_pop: None,
        legacy_timestamp: None,
        values: &values,
    };
    let mut verifier = ResourceVerifier::new("https://issuer.example", key.jwks());
    assert!(verifier.verify(&token, &request, NOW, |_| panic!()).is_ok());
    // Compatibility defaults match Python's current absence of a replay cache.
    assert!(verifier.verify(&token, &request, NOW, |_| panic!()).is_ok());
    verifier.reject_replay = true;
    assert!(verifier.verify(&token, &request, NOW, |_| panic!()).is_ok());
    assert!(
        verifier
            .verify(&token, &request, NOW, |_| panic!())
            .is_err()
    );
    request.uri = "https://resource.example/transfer?a=2";
    assert!(
        ResourceVerifier::new("https://issuer.example", key.jwks())
            .verify(&token, &request, NOW, |_| panic!())
            .is_err()
    );
    request.uri = uri;
    request.audience = Some("other");
    assert!(
        ResourceVerifier::new("https://issuer.example", key.jwks())
            .verify(&token, &request, NOW, |_| panic!())
            .is_err()
    );
    let thief = ProofKey::generate();
    let stolen = thief.proof("POST", uri, Some(&token), None, NOW).unwrap();
    request.audience = Some("resource");
    request.proof = Some(&stolen);
    assert!(
        ResourceVerifier::new("https://issuer.example", key.jwks())
            .verify(&token, &request, NOW, |_| panic!())
            .is_err()
    );
}

#[test]
fn value_binding_freezes_static_bounds_and_resource_references() {
    let params = json!({"amount":500,"charge":"ch1"});
    let raw = vec![
        json!({"target":"self.in.amount","op":">","operand":{"lit":0}}),
        json!({"target":"self.in.amount","op":"<=","operand":{"pref":{"provider":"charges","args":{"id":"self.in.charge"},"field":"amount"}}}),
    ];
    let binding =
        freeze_bounds(&raw, "refund", &params, &json!({}), &json!({}), "FINANCIAL").unwrap();
    assert!(evaluate_binding(&binding, &params));
    assert!(verify_binding(&binding, &params, |_| Ok(json!(600))).is_ok());
    assert!(verify_binding(&binding, &params, |_| Ok(json!(400))).is_err());
    assert!(
        verify_binding(&binding, &json!({"amount":100,"charge":"ch1"}), |_| Ok(
            json!(600)
        ))
        .is_err()
    );
    assert!(verify_binding(&binding, &json!({}), |_| Ok(json!(600))).is_err());
}

#[test]
fn resource_extraction_and_provider_use_actual_transport_values() {
    let view = RequestView {
        body: json!({"amount":500,"nested":{"id":"body-id"},"nullable":null}),
        query: [
            ("amount".into(), "900".into()),
            ("charge".into(), "query-id".into()),
        ]
        .into(),
        path_params: [("charge".into(), "path-id".into())].into(),
    };
    let targets = vec![
        "amount".into(),
        "nested.id".into(),
        "nullable".into(),
        "missing".into(),
    ];
    let found = extract_rest(&view, &targets, &json!({}));
    assert_eq!(found.values["amount"], 500);
    assert_eq!(found.values["nested.id"], "body-id");
    assert!(found.covered.contains("nullable"));
    assert!(!found.covered.contains("missing"));
    let explicit = extract_rest(
        &view,
        &targets,
        &json!({"amount":{"in":"query"},"nested.id":{"in":"path","name":"missing"}}),
    );
    assert_eq!(explicit.values["amount"], "900");
    assert!(!explicit.covered.contains("nested.id"));
    let reference =
        json!({"provider":"charges","args":{"id":"self.in.charge"},"field":"record.amount"});
    assert_eq!(
        resolve_reference(&reference, &view, &json!({}), |name, args| {
            assert_eq!(name, "charges");
            assert_eq!(args["id"], "query-id");
            Ok(json!({"record":{"amount":600}}))
        })
        .unwrap(),
        600
    );
    assert!(
        resolve_reference(
            &reference,
            &RequestView::default(),
            &json!({}),
            |_, _| panic!("missing arguments must not reach provider")
        )
        .is_err()
    );
    assert!(resolve_reference(&reference, &view, &json!({}), |_, _| Ok(json!({}))).is_err());
}

#[test]
fn numeric_bounds_keep_integer_precision_and_python_container_semantics() {
    let huge: Value = serde_json::from_str("123456789012345678901234567891").unwrap();
    assert!(apply_op(
        "<",
        &json!("123456789012345678901234567890"),
        &huge
    ));
    assert!(!apply_op(
        "==",
        &json!(9007199254740993_u64),
        &json!(9007199254740992.0)
    ));
    assert!(apply_op(
        ">",
        &json!(9007199254740993_u64),
        &json!(9007199254740992.0)
    ));
    assert!(apply_op("==", &json!("١_٢٣"), &json!(123)));
    assert!(!apply_op("==", &json!("NaN"), &json!("NaN")));
    assert!(apply_op(">", &json!("Infinity"), &huge));
    assert!(apply_op("<", &json!([1, 2]), &json!([1, 3])));
    assert!(apply_op("not_in", &json!(1), &json!({})));
    assert!(apply_op("not_in", &json!(1), &json!("")));
    assert_ne!(
        action_hash(
            "transfer",
            &json!({"amount":"123456789012345678901234567890"})
        )
        .unwrap(),
        action_hash("transfer", &json!({"amount":huge})).unwrap()
    );
}

#[test]
fn bound_authoring_matches_selector_and_operand_shapes() {
    let out = json!({"target":"self.out.amount","op":"<=","operand":{"lit":500}});
    let binding = freeze_bounds(
        &[out],
        "pay",
        &json!({"amount":100}),
        &json!({}),
        &json!({}),
        "FINANCIAL",
    )
    .unwrap();
    assert_eq!(binding.bounds[0].target, "amount");
    assert!(evaluate_binding(&binding, &json!({"amount":100})));
    let pref =
        json!({"target":"self.in.amount","op":"<=","operand":{"pref":{"provider":"charge"}}});
    let binding = freeze_bounds(
        &[pref],
        "refund",
        &json!({"amount":100}),
        &json!({}),
        &json!({}),
        "",
    )
    .unwrap();
    assert_eq!(
        binding.bounds[0].r#ref,
        Some(json!({"provider":"charge","args":{},"field":""}))
    );
    assert!(!valid_bound(
        &json!({"target":"self.in.amount","op":">","operand":{"sel":"unknown.x"}})
    ));
    assert!(!valid_bound(
        &json!({"target":"self.in.amount","op":">","operand":{"lit":0},"provenance_floor":"untrusted"})
    ));
}
