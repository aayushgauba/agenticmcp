use agentic_jwt::*;
use serde_json::json;

const ISSUER: &str = "https://idp.example.com";
const API: &str = "https://api.example.com";

fn spec(id: &str, prompt: &str) -> AgentSpec {
    AgentSpec {
        agent_id: id.into(),
        prompt_template: prompt.into(),
        tools: vec![],
        configuration: json!({"model_name": "demo-agent", "temperature": 0}),
    }
}

fn main() -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Time)?
        .as_secs();
    let mut authority = Authority::new(ISSUER)?;
    let client = KeyPair::generate();
    let planner_key = KeyPair::generate();
    let patcher_key = KeyPair::generate();
    let planner = spec("planner", "Inspect the repository and propose a patch.");
    let patcher = spec("patcher", "Apply only the exact approved patch.");
    authority.register_client("maintenance-app", client.public_key())?;
    for (spec, key, scope) in [
        (&planner, &planner_key, "repo:read"),
        (&patcher, &patcher_key, "repo:write"),
    ] {
        authority.register_agent(
            "maintenance-app",
            spec,
            key.public_key(),
            AgentPolicy {
                scopes: [scope.into()].into(),
                audiences: [API.into()].into(),
            },
        )?;
    }
    let inspect = Action::new(
        "GET",
        "https://api.example.com/repos/demo/commits/abc123",
        b"",
        "repo:read",
    )?;
    let patch = Action::new(
        "POST",
        "https://api.example.com/repos/demo/patches",
        br#"{"base_commit":"abc123","patch":"upgrade example dependency"}"#,
        "repo:write",
    )?;
    authority.register_workflow(Workflow {
        id: "patch-workflow-v1".into(),
        steps: vec![
            Step {
                id: "inspect".into(),
                agent_id: "planner".into(),
                audience: API.into(),
                action: inspect.clone(),
                requires_approval: false,
            },
            Step {
                id: "apply".into(),
                agent_id: "patcher".into(),
                audience: API.into(),
                action: patch.clone(),
                requires_approval: true,
            },
        ],
    })?;
    let run = authority.start_run("patch-workflow-v1", "alice")?;
    println!("Registered two agents with separate keys and configuration checksums.");

    let grant = SignedGrant::sign(
        "maintenance-app",
        ISSUER,
        authority.request_for(&run, &planner)?,
        &client,
        &planner_key,
        now,
    )?;
    let token = authority.issue(&grant, now)?;
    let proof = prove_request(&token.access_token, &inspect, "planner", &planner_key, now)?;
    let permit = authority.authorize(&token.access_token, &proof, API, &inspect, now)?;
    // The demo simulates a successful resource operation; no external API is called.
    authority.finish(permit, true)?;
    println!("ALLOW: planner inspects the pinned commit; resource host records completion.");

    let grant = SignedGrant::sign(
        "maintenance-app",
        ISSUER,
        authority.request_for(&run, &patcher)?,
        &client,
        &patcher_key,
        now,
    )?;
    match authority.issue(&grant, now) {
        Err(Error::Approval) => {
            println!("DENY: patcher cannot obtain an intent token before approval.")
        }
        _ => return Err(Error::Invalid("approval gate was not enforced")),
    }
    authority.approve(&run, "apply", "alice")?;
    let token = authority.issue(&grant, now)?;
    let claims = authority.inspect_token(&token.access_token, now)?;
    println!("Intent claims:\n{}", serde_json::to_string_pretty(&claims)?);

    let stolen_proof = prove_request(&token.access_token, &patch, "patcher", &planner_key, now)?;
    if !matches!(
        authority.authorize(&token.access_token, &stolen_proof, API, &patch, now),
        Err(Error::Signature)
    ) {
        return Err(Error::Invalid("wrong agent key was accepted"));
    }
    println!("DENY: planner cannot use patcher's stolen intent token.");

    let proof = prove_request(&token.access_token, &patch, "patcher", &patcher_key, now)?;
    let altered = Action::new("POST", &patch.uri, b"unapproved patch", "repo:write")?;
    if !matches!(
        authority.authorize(&token.access_token, &proof, API, &altered, now),
        Err(Error::Action)
    ) {
        return Err(Error::Invalid("altered body was accepted"));
    }
    println!("DENY: request body differs from the exact approved patch.");
    let permit = authority.authorize(&token.access_token, &proof, API, &patch, now)?;
    authority.finish(permit, true)?;
    println!("ALLOW: patcher applies the approved operation (simulated).");
    if !matches!(
        authority.authorize(&token.access_token, &proof, API, &patch, now),
        Err(Error::Replay)
    ) {
        return Err(Error::Invalid("replay was accepted"));
    }
    println!("DENY: replay of the same request proof.");
    assert!(authority.is_complete(&run)?);
    println!("Workflow complete. No LLM, credentials, or external services required.");
    Ok(())
}
