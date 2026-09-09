use super::{FileServer, McpResult};
use serde_json::{Value, json};
use std::io::{BufRead, Write};

const MAX_MESSAGE: usize = 131072;
const TOOLS: [&str; 4] = [
    "inspect_file",
    "propose_patch",
    "proposal_status",
    "apply_approved_patch",
];

fn definitions() -> Value {
    let entries = [
        (
            "Read an existing UTF-8 file in the configured directory and return its SHA-256.",
            vec!["path"],
            true,
        ),
        (
            "Propose an exact full-file replacement. Does not write the file. Requires separate signed approval before execution.",
            vec!["path", "before_sha256", "replacement"],
            false,
        ),
        (
            "Read the proposal and session status. Approval receipts are checked only when executing.",
            vec!["proposal_id"],
            true,
        ),
        (
            "Verify an independently signed approval and apply the stored replacement once. No approval can be created through MCP.",
            vec!["proposal_id", "approval"],
            false,
        ),
    ];
    Value::Array(TOOLS.iter().zip(entries).map(|(name, (description, fields, read_only))| {
        let properties: serde_json::Map<String,Value> = fields.iter().map(|f| ((*f).into(), json!({"type":"string"}))).collect();
        json!({"name":name,"description":description,"inputSchema":{"type":"object","properties":properties,"required":fields,"additionalProperties":false},
            "annotations":{"readOnlyHint":read_only,"destructiveHint":*name=="apply_approved_patch","idempotentHint":read_only,"openWorldHint":false}})
    }).collect())
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}

pub(super) fn serve(
    server: &mut FileServer,
    mut input: impl BufRead,
    mut output: impl Write,
) -> McpResult<()> {
    let mut state = 0; // 0 = new, 1 = initialize response sent, 2 = initialized notification received.
    let mut allowance = 60.0_f64;
    let mut last = std::time::Instant::now();
    loop {
        let mut bytes = Vec::new();
        // Bound framing allocations even when a client never sends a newline.
        let count = std::io::Read::take(&mut input, MAX_MESSAGE as u64 + 1)
            .read_until(b'\n', &mut bytes)?;
        if count == 0 {
            return Ok(());
        }
        if count > MAX_MESSAGE {
            return Err("MCP message too large; closing session".into());
        }
        let reply = match serde_json::from_slice::<Value>(&bytes) {
            Err(_) => Some(error(Value::Null, -32700, "Parse error")),
            Ok(message) => {
                let time = std::time::Instant::now();
                allowance = (allowance + time.duration_since(last).as_secs_f64() * 10.0).min(60.0);
                last = time;
                if allowance < 1.0 {
                    message
                        .get("id")
                        .map(|id| error(id.clone(), -32000, "Request rate exceeded"))
                } else {
                    allowance -= 1.0;
                    dispatch(server, &mut state, message)
                }
            }
        };
        if let Some(reply) = reply {
            serde_json::to_writer(&mut output, &reply)?;
            output.write_all(b"\n")?;
            output.flush()?;
        }
    }
}

fn dispatch(server: &mut FileServer, state: &mut u8, message: Value) -> Option<Value> {
    let id = message.get("id").cloned().unwrap_or(Value::Null);
    if !message.is_object()
        || message["jsonrpc"] != "2.0"
        || !message["method"].is_string()
        || (message.get("id").is_some() && !(id.is_string() || id.is_i64()))
    {
        return Some(error(Value::Null, -32600, "Invalid Request"));
    }
    let method = message["method"].as_str().unwrap_or_default();
    if message.get("id").is_none() {
        if method == "notifications/initialized" && *state == 1 {
            *state = 2;
        }
        return None;
    }
    let params = message.get("params").cloned().unwrap_or(json!({}));
    let result = match method {
        "initialize" => {
            if *state != 0 {
                return Some(error(id, -32600, "Session already initialized"));
            }
            if !params["protocolVersion"].is_string()
                || !params["capabilities"].is_object()
                || !params["clientInfo"]["name"].is_string()
                || !params["clientInfo"]["version"].is_string()
            {
                return Some(error(id, -32602, "Invalid initialize parameters"));
            }
            let requested = params["protocolVersion"].as_str().unwrap_or_default();
            let version =
                if ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"].contains(&requested) {
                    requested
                } else {
                    "2025-11-25"
                };
            *state = 1;
            json!({"protocolVersion":version,"capabilities":{"tools":{}},"serverInfo":{"name":"agentic-jwt-files","version":env!("CARGO_PKG_VERSION")},
                "instructions":"Inspect, propose, obtain independent human-signed approval, then apply. Approval is never an MCP tool. State is durable; uncertain execution outcomes require operator recovery."})
        }
        "ping" => json!({}),
        _ if *state != 2 => return Some(error(id, -32600, "Initialize the session first")),
        "tools/list" => {
            if !params.is_object() || params.get("cursor").is_some() {
                return Some(error(id, -32602, "Invalid list parameters"));
            }
            json!({"tools":definitions()})
        }
        "tools/call" => {
            let Some(name) = params["name"].as_str() else {
                return Some(error(id, -32602, "Tool name required"));
            };
            if !TOOLS.contains(&name) {
                return Some(error(id, -32602, "Unknown tool"));
            }
            let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
            if !arguments.is_object() {
                return Some(error(id, -32602, "Tool arguments must be an object"));
            }
            let started = std::time::Instant::now();
            let outcome = server.call(name, arguments);
            eprintln!(
                "{}",
                json!({"event":"tool_call","owner":server.owner,"tool":name,"success":outcome.is_ok(),"duration_ms":started.elapsed().as_millis()})
            );
            match outcome {
                Ok(value) => {
                    json!({"content":[{"type":"text","text":value.to_string()}],"structuredContent":value,"isError":false})
                }
                Err(err) => {
                    json!({"content":[{"type":"text","text":err.to_string()}],"isError":true})
                }
            }
        }
        _ => return Some(error(id, -32601, "Method not found")),
    };
    Some(json!({"jsonrpc":"2.0","id":id,"result":result}))
}
