//! End-to-end MCP smoke test over stdio.
//!
//! Spawns the real `hvlab mcp` binary, performs the MCP handshake, and
//! exercises the read-only tool surface. This is the only test that
//! crosses the process boundary; everything else tests the crates
//! in-process.

// A test binary asserts by panicking; that is the point of `expect` here.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{Value, json};

fn spawn_server() -> (Child, ChildStdin, BufReader<ChildStdout>) {
    let exe = env!("CARGO_BIN_EXE_hvlab");
    let mut child = Command::new(exe)
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn hvlab mcp");
    let stdin = child.stdin.take().expect("child stdin");
    let stdout = BufReader::new(child.stdout.take().expect("child stdout"));
    (child, stdin, stdout)
}

fn send(stdin: &mut ChildStdin, msg: &Value) {
    let mut line = serde_json::to_string(msg).expect("serialize request");
    line.push('\n');
    stdin.write_all(line.as_bytes()).expect("write request");
    stdin.flush().expect("flush request");
}

fn recv(reader: &mut BufReader<ChildStdout>) -> Value {
    let mut line = String::new();
    let n = reader.read_line(&mut line).expect("read response");
    assert!(n > 0, "server closed stdout before answering");
    serde_json::from_str(line.trim()).unwrap_or_else(|e| panic!("bad JSON frame: {e}: {line}"))
}

fn handshake(stdin: &mut ChildStdin, reader: &mut BufReader<ChildStdout>) {
    send(
        stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": { "name": "hvlab-smoke", "version": "0.1.0" }
            }
        }),
    );
    let init = recv(reader);
    assert_eq!(init["id"], 1, "initialize id echoed: {init}");
    assert!(
        init["result"]["serverInfo"]["name"] == "hvlab",
        "serverInfo: {init}"
    );
    send(
        stdin,
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    );
}

fn call(
    stdin: &mut ChildStdin,
    reader: &mut BufReader<ChildStdout>,
    id: u64,
    method: &str,
    params: &Value,
) -> Value {
    send(
        stdin,
        &json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }),
    );
    // Skip any server-initiated notifications/logs until our id arrives.
    for _ in 0..50 {
        let msg = recv(reader);
        if msg.get("id").and_then(Value::as_u64) == Some(id) {
            return msg;
        }
    }
    panic!("no response for id {id}");
}

#[test]
#[allow(clippy::too_many_lines, reason = "one end-to-end session, in order")]
fn stdio_smoke() {
    let (mut child, mut stdin, mut reader) = spawn_server();
    handshake(&mut stdin, &mut reader);

    let listed = call(&mut stdin, &mut reader, 2, "tools/list", &json!({}));
    let tools = listed["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list shape: {listed}"));
    // The default profile advertises a small, cheap listing — not the
    // whole catalogue — so a harness is not billed for schemas it will
    // not use.
    assert!(
        tools.len() == 18,
        "expected exactly 18 advertised tools (core profile), got {}",
        tools.len()
    );
    for t in tools {
        let name = t["name"].as_str().unwrap_or_default();
        assert!(!name.is_empty(), "unnamed tool: {t}");
        let desc = t["description"].as_str().unwrap_or_default();
        assert!(!desc.trim().is_empty(), "tool {name} has no description");
        // The lean projection drops output schemas: they are half the
        // payload and no client needs them to choose a tool.
        assert!(
            t.get("outputSchema").is_none(),
            "advertised tool {name} still carries an outputSchema"
        );
    }
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    for expected in [
        "hv_host_info",
        "hv_vm_list",
        "hv_dump_inspect",
        "hv_dump_find",
        "hv_plan",
        "hv_guest_exec",
        "hv_tools_search",
        "hv_tools_describe",
    ] {
        assert!(
            names.contains(&expected),
            "missing advertised tool {expected}"
        );
    }
    // A long-tail tool must NOT be advertised...
    assert!(
        !names.contains(&"hv_vhd_create"),
        "hv_vhd_create should be outside the core profile"
    );

    // ...but it must still be findable and callable.
    let searched = call(
        &mut stdin,
        &mut reader,
        20,
        "tools/call",
        &json!({ "name": "hv_tools_search", "arguments": { "query": "vhd_create" } }),
    );
    assert_eq!(searched["result"]["isError"], false, "search: {searched}");
    let hits = searched["result"]["structuredContent"]["tools"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        hits.iter().any(|t| t["name"] == "hv_vhd_create"),
        "search must find an unadvertised tool: {searched}"
    );

    let described = call(
        &mut stdin,
        &mut reader,
        21,
        "tools/call",
        &json!({ "name": "hv_tools_describe", "arguments": { "name": "hv_vhd_create" } }),
    );
    assert_eq!(
        described["result"]["isError"], false,
        "describe: {described}"
    );
    assert!(
        described["result"]["structuredContent"]["input_schema"]["properties"]
            .as_object()
            .is_some_and(|p| !p.is_empty()),
        "describe must return the real argument schema: {described}"
    );

    // The point of the whole arrangement: an unadvertised tool runs.
    let unlisted = call(
        &mut stdin,
        &mut reader,
        22,
        "tools/call",
        &json!({ "name": "hv_vhd_inspect", "arguments": { "path": "C:\\nope\\none.vhdx" } }),
    );
    // It must reach the backend (producing a real error about the path),
    // not be rejected as an unknown tool.
    let body = unlisted.to_string();
    assert!(
        !body.contains("tool not found"),
        "an unadvertised tool must still dispatch: {unlisted}"
    );
    assert!(
        body.contains("hv.not_found") || body.contains("hv.transport"),
        "unadvertised tool should reach the backend: {unlisted}"
    );

    // A read-only call that works without Hyper-V admin.
    let found = call(
        &mut stdin,
        &mut reader,
        3,
        "tools/call",
        &json!({ "name": "hv_dump_find", "arguments": { "limit": 3 } }),
    );
    assert_eq!(found["result"]["isError"], false, "hv_dump_find: {found}");
    let dumps = &found["result"]["structuredContent"]["dumps"];
    assert!(dumps.is_array(), "dumps array: {found}");

    // A plan-gated call with no token must be refused.
    let refused = call(
        &mut stdin,
        &mut reader,
        4,
        "tools/call",
        &json!({
            "name": "hv_checkpoint_delete",
            "arguments": { "vm": "Driver Testing", "checkpoint": "x" }
        }),
    );
    let is_error = refused["result"]["isError"] == true || refused.get("error").is_some();
    assert!(is_error, "plan-gated call must be refused: {refused}");

    // hv_plan mints a token for a gated action.
    let minted = call(
        &mut stdin,
        &mut reader,
        5,
        "tools/call",
        &json!({
            "name": "hv_plan",
            "arguments": {
                "action": "hv_checkpoint_delete",
                "args": { "vm": "Driver Testing", "checkpoint": "x" }
            }
        }),
    );
    assert_eq!(minted["result"]["isError"], false, "hv_plan: {minted}");
    let digest = minted["result"]["structuredContent"]["digest"]
        .as_str()
        .unwrap_or_else(|| panic!("digest: {minted}"));
    assert_eq!(digest.len(), 64, "digest is sha256 hex: {digest}");

    let _ = child.kill();
    let _ = child.wait();
}
