//! An MCP server (`grix mcp`): AI agents run programs in grix sandboxes
//! through the Model Context Protocol, over stdio (newline-delimited
//! JSON-RPC 2.0).
//!
//! Tools: `run` (a program in a fresh sandbox: files, an image, mounts,
//! stdin, capabilities, exports back in the answer) and `build_image` (a
//! grix image from a Grixfile). The agent gets only what the server allows:
//! host paths under its roots, capabilities from its list (no `net` unless
//! enabled, and then under its `allow_host` rules), and a time and memory
//! cap.

use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use grix_abi::policy::Capability;
use serde_json::{Value, json};

use crate::build::{BuildOptions, BuildPolicy, Grixfile};
use crate::export::ExportContent;
use crate::mount::MountState;
use crate::sandbox::{ExitStatus, MountMode, Sandbox};

/// What agents may do.
#[derive(Clone, Debug)]
pub struct McpConfig {
    /// Host directories (canonical) that imports, mounts, images and
    /// Grixfiles may come from.
    pub roots: Vec<PathBuf>,
    /// Capabilities an agent may grant.
    pub capabilities: Vec<Capability>,
    /// With `net` allowed: the only hosts runs may reach (none: anywhere
    /// but the host itself and special addresses).
    pub allow_hosts: Vec<String>,
    pub max_timeout: Duration,
    pub max_memory_mb: u64,
    /// Agents may change host files: writable mounts (`rw`, `on_exit`) and
    /// `build_image`'s output. Off by default.
    pub writable: bool,
}

impl McpConfig {
    /// Roots made canonical; guest-only capabilities.
    pub fn new(roots: &[PathBuf]) -> Result<McpConfig> {
        let roots = roots
            .iter()
            .map(|r| r.canonicalize().with_context(|| format!("root {}", r.display())))
            .collect::<Result<_>>()?;
        Ok(McpConfig {
            roots,
            capabilities: vec![Capability::FsWrite, Capability::Threads, Capability::Process],
            allow_hosts: Vec::new(),
            max_timeout: Duration::from_secs(300),
            max_memory_mb: 2048,
            writable: false,
        })
    }

    /// `p` if it's under a root (after resolving links). The same error
    /// whether it's missing or elsewhere: what's outside isn't the agent's
    /// to probe.
    fn host_path(&self, p: &str) -> Result<PathBuf> {
        match Path::new(p).canonicalize() {
            Ok(real) if self.roots.iter().any(|r| real.starts_with(r)) => Ok(real),
            _ => bail!("{p} doesn't exist in the directories this server allows"),
        }
    }

    /// What `build_image` builds may do: what runs may.
    fn build_policy(&self) -> BuildPolicy {
        let net = self.capabilities.contains(&Capability::Net);
        BuildPolicy {
            net,
            allow_hosts: self.allow_hosts.clone(),
            registries: net,
            docker: false,
            step_timeout: self.max_timeout,
            step_memory_mb: self.max_memory_mb,
        }
    }
}

const PROTOCOL: &str = "2025-06-18";
/// What a tool answer carries of stdout/stderr and exported files.
const OUTPUT_MAX: usize = 256 * 1024;
const EXPORT_MAX: usize = 1 << 20;
/// The most a run from a snapshot may export (a sandbox's default).
const EXPORT_LIMIT: usize = 256 << 20;
/// The longest message read (inline files and stdin come in them).
const MESSAGE_MAX: usize = 64 << 20;

/// Serve requests from `input` until it ends.
pub fn serve(config: &McpConfig, input: impl BufRead, output: impl Write) -> Result<()> {
    serve_with_limit(config, input, output, MESSAGE_MAX)
}

fn serve_with_limit(config: &McpConfig, mut input: impl BufRead, mut output: impl Write, max: usize) -> Result<()> {
    let mut line = Vec::new();
    loop {
        line.clear();
        // At most `max` bytes and the newline.
        if (&mut input).take(max as u64 + 1).read_until(b'\n', &mut line)? == 0 {
            break;
        }
        let reply = if line.len() > max && line.last() != Some(&b'\n') {
            input.skip_until(b'\n')?;
            Some(error(Value::Null, -32700, &format!("message over {max} bytes")))
        } else if line.trim_ascii().is_empty() {
            continue;
        } else {
            match serde_json::from_slice::<Value>(&line) {
                Ok(msg) => handle(config, &msg),
                Err(e) => Some(error(Value::Null, -32700, &format!("parse error: {e}"))),
            }
        };
        if let Some(reply) = reply {
            writeln!(output, "{reply}")?;
            output.flush()?;
        }
    }
    Ok(())
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// The answer to one message (none for notifications).
fn handle(config: &McpConfig, msg: &Value) -> Option<Value> {
    let id = msg.get("id").cloned()?;
    let method = msg["method"].as_str().unwrap_or("");
    let result = match method {
        "initialize" => json!({
            "protocolVersion": PROTOCOL,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "grix", "version": env!("CARGO_PKG_VERSION")},
            "instructions": "Run Linux (arm64) programs in fresh, isolated grix sandboxes. Each run boots a new \
                             microVM that sees only the files you give it, with only the capabilities you grant.",
        }),
        "ping" => json!({}),
        "tools/list" => json!({"tools": tools(config)}),
        "tools/call" => {
            let name = msg["params"]["name"].as_str().unwrap_or("");
            let args = &msg["params"]["arguments"];
            let outcome = match name {
                "run" => run(config, args),
                "snapshot" => snapshot(config, args),
                "build_image" => build_image(config, args),
                _ => return Some(error(id, -32602, &format!("unknown tool {name:?}"))),
            };
            match outcome {
                Ok((text, structured, failed)) => json!({
                    "content": [{"type": "text", "text": text}],
                    "structuredContent": structured,
                    "isError": failed,
                }),
                Err(e) => json!({"content": [{"type": "text", "text": format!("{e:#}")}], "isError": true}),
            }
        }
        _ => return Some(error(id, -32601, &format!("method {method:?} not found"))),
    };
    Some(json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

fn tools(config: &McpConfig) -> Value {
    let caps: Vec<&str> = config.capabilities.iter().map(|c| c.name()).collect();
    let mut snapshot_schema = sandbox_schema(&caps);
    snapshot_schema["properties"]["output"] =
        json!({"type": "string", "description": "Where to write the snapshot (under an allowed directory)."});
    snapshot_schema["required"] = json!(["output"]);
    let mut run_schema = sandbox_schema(&caps);
    run_schema["properties"]["stdin"] = json!({"type": "string"});
    run_schema["properties"]["snapshot"] = json!({"type": "string",
        "description": "Run from this snapshot (from the `snapshot` tool) instead: the program goes on from where it \
                        waited, with `stdin`. Then only stdin and timeout_secs apply; what comes back is what the \
                        snapshot's sandbox exported."});
    json!([
        {
            "name": "run",
            "description": format!(
                "Run a program in a fresh grix sandbox (an arm64 Linux microVM) and return its exit status, \
                 output and events: what it was denied, which files it looked for and didn't have. It sees only \
                 the files given (imports, inline files, a grix image, mounts) and has only the capabilities \
                 granted ({}). Host paths must be under {}.",
                caps.join(", "),
                config.roots.iter().map(|r| r.display().to_string()).collect::<Vec<_>>().join(", ")
            ),
            "inputSchema": run_schema
        },
        {
            "name": "snapshot",
            "description": "Start a program in a sandbox (the same options as `run`, but no mounts) and save the whole \
                            machine when it first waits for input, so each `run` with `snapshot` starts from there in \
                            milliseconds: start an interpreter that reads code from stdin, say, once its libraries are \
                            loaded. Needs a writable server.",
            "inputSchema": snapshot_schema
        },
        {
            "name": "build_image",
            "description": "Build a grix image (.grix: files, settings and the grix kernel) from a Grixfile on the host, \
                            for `run`'s `image`. The Grixfile's `from` may name a Docker/OCI image (e.g. python:3.12-alpine) \
                            or nothing.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "grixfile": {"type": "string", "description": "Path of the Grixfile."},
                    "output": {"type": "string", "description": "Where to write the image (under an allowed directory)."}
                },
                "required": ["grixfile", "output"]
            }
        }
    ])
}

/// What a sandbox is made of, for `run` and `snapshot`.
fn sandbox_schema(caps: &[&str]) -> Value {
    json!({
                "type": "object",
                "properties": {
                    "command": {"type": "array", "items": {"type": "string"},
                                "description": "Program (a path in the sandbox, or a name on PATH) and arguments. Optional with an image."},
                    "image": {"type": "string", "description": "A grix image file (.grix) on the host to run."},
                    "imports": {"type": "array", "items": {"type": "object", "properties": {
                        "host": {"type": "string"}, "guest": {"type": "string"}}, "required": ["host", "guest"]},
                        "description": "Host files or directories to copy in."},
                    "files": {"type": "array", "items": {"type": "object", "properties": {
                        "path": {"type": "string"}, "content": {"type": "string"},
                        "executable": {"type": "boolean"}}, "required": ["path", "content"]},
                        "description": "Files to create, with these contents."},
                    "mounts": {"type": "array", "items": {"type": "object", "properties": {
                        "host": {"type": "string"}, "guest": {"type": "string"},
                        "mode": {"type": "string", "enum": ["rw", "ro", "on_exit"]}}, "required": ["host", "guest"]},
                        "description": "Host directories to mount (rw: changes reach the host at once; on_exit: when the program ends; \
                                        both only if the server is writable)."},
                    "env": {"type": "object", "additionalProperties": {"type": "string"}},
                    "cwd": {"type": "string"},
                    "capabilities": {"type": "array", "items": {"type": "string", "enum": caps}},
                    "exports": {"type": "array", "items": {"type": "string"},
                                "description": "Sandbox directories whose contents to return when the program ends."},
                    "timeout_secs": {"type": "number"},
                    "memory_mb": {"type": "number"}
                }
    })
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect()).unwrap_or_default()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n[... {} more bytes]", &s[..end], s.len() - end)
}

/// The time limit an agent asks for, within the server's.
fn timeout(config: &McpConfig, args: &Value, default: Duration) -> Result<Duration> {
    let t = match &args["timeout_secs"] {
        Value::Null => default,
        v => {
            let secs = v.as_f64().filter(|s| *s >= 0.0).context("timeout_secs must be a number of seconds")?;
            Duration::try_from_secs_f64(secs.min(config.max_timeout.as_secs_f64()))?
        }
    };
    Ok(t.min(config.max_timeout))
}

fn run(config: &McpConfig, args: &Value) -> Result<(String, Value, bool)> {
    let stdin = args["stdin"].as_str().unwrap_or("").as_bytes().to_vec();
    let out = match args["snapshot"].as_str() {
        Some(path) => {
            // Whoever wrote the file, runs from it get only the network
            // this server allows.
            let snap = crate::Snapshot::open(config.host_path(path)?)?
                .restrict_net(config.capabilities.contains(&Capability::Net), &config.allow_hosts)?
                .limits(OUTPUT_MAX * 4, EXPORT_LIMIT, Duration::from_secs(5));
            // It sends back what it was made to export.
            for e in strings(&args["exports"]) {
                if !snap.exports().contains(&e) {
                    bail!("the snapshot doesn't export {e} (it exports {:?})", snap.exports());
                }
            }
            if snap.memory_mb() > config.max_memory_mb {
                bail!(
                    "the snapshot has {} MiB of memory; the server allows at most {} MiB",
                    snap.memory_mb(),
                    config.max_memory_mb
                );
            }
            let t = timeout(config, args, snap.default_timeout())?;
            snap.timeout(t).run(stdin)?
        }
        None => {
            let (sandbox, command) = sandbox(config, args)?;
            match args["stdin"].as_str() {
                Some(_) => sandbox.run_with_stdin(&command, stdin)?,
                None => sandbox.run(&command)?,
            }
        }
    };
    Ok(describe(&out))
}

fn snapshot(config: &McpConfig, args: &Value) -> Result<(String, Value, bool)> {
    if !config.writable {
        bail!("this server doesn't write host files (it isn't --writable), so it can't save snapshots");
    }
    if args["mounts"].as_array().is_some_and(|m| !m.is_empty()) {
        bail!("a snapshot can't have mounts");
    }
    let out = output_path(config, args)?;
    let (sandbox, command) = sandbox(config, args)?;
    let started = std::time::Instant::now();
    let snap = sandbox.snapshot(&command, &out)?;
    let size = std::fs::metadata(&out).map_or(0, |m| m.len());
    let text = format!(
        "saved {} ({} MiB of memory) after {} ms: pass it as `snapshot` to `run`",
        out.display(),
        snap.memory_mb(),
        started.elapsed().as_millis()
    );
    Ok((text, json!({"snapshot": out, "bytes": size, "memory_mb": snap.memory_mb()}), false))
}

/// `args["output"]`: a new file in an allowed directory.
fn output_path(config: &McpConfig, args: &Value) -> Result<PathBuf> {
    let output = args["output"].as_str().context("no output")?;
    let out_path = Path::new(output);
    let dir = out_path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let dir = config.host_path(&dir.to_string_lossy())?;
    Ok(dir.join(out_path.file_name().context("output needs a file name")?))
}

/// The sandbox `args` describe, within the server's policy, and its command.
fn sandbox(config: &McpConfig, args: &Value) -> Result<(Sandbox, Vec<String>)> {
    let mut b = Sandbox::builder().max_output(OUTPUT_MAX * 4);
    if let Some(image) = args["image"].as_str() {
        let image = crate::Image::open(config.host_path(image)?)?;
        for name in &image.config.capabilities {
            let cap = Capability::from_name(name).with_context(|| format!("unknown capability {name:?}"))?;
            if cap != Capability::Net && !config.capabilities.contains(&cap) {
                bail!("the image asks for the {name} capability, which this server doesn't allow");
            }
        }
        // Its files and settings, with the server's kernel (the one it trusts).
        let kernel = b.kernel_path().to_path_buf();
        b = b.image(&image)?.kernel(kernel);
    }
    for imp in args["imports"].as_array().into_iter().flatten() {
        let host = imp["host"].as_str().context("import without host")?;
        b = b.import(config.host_path(host)?, imp["guest"].as_str().context("import without guest")?)?;
    }
    for f in args["files"].as_array().into_iter().flatten() {
        let mode = if f["executable"].as_bool() == Some(true) { 0o755 } else { 0o644 };
        let path = f["path"].as_str().context("file without path")?;
        b = b.file(path, f["content"].as_str().unwrap_or("").as_bytes().to_vec(), mode)?;
    }
    for m in args["mounts"].as_array().into_iter().flatten() {
        let host = config.host_path(m["host"].as_str().context("mount without host")?)?;
        let mode = match m["mode"].as_str().unwrap_or("rw") {
            "rw" => MountMode::ReadWrite,
            "ro" => MountMode::ReadOnly,
            "on_exit" => MountMode::OnExit,
            other => bail!("mount mode {other:?} isn't rw, ro or on_exit"),
        };
        if mode != MountMode::ReadOnly && !(config.writable && config.capabilities.contains(&Capability::FsWrite)) {
            bail!("this server doesn't allow writable mounts (only \"ro\")");
        }
        b = b.mount_with(host, m["guest"].as_str().context("mount without guest")?, mode)?;
    }
    if let Some(env) = args["env"].as_object() {
        for (k, v) in env {
            b = b.env(k, v.as_str().unwrap_or(""));
        }
    }
    if let Some(cwd) = args["cwd"].as_str() {
        b = b.cwd(cwd);
    }
    for name in strings(&args["capabilities"]) {
        let cap = Capability::from_name(&name).with_context(|| format!("unknown capability {name:?}"))?;
        if !config.capabilities.contains(&cap) {
            bail!("this server doesn't allow the {name} capability");
        }
        b = b.allow(cap);
    }
    for rule in &config.allow_hosts {
        b = b.allow_host(rule)?;
    }
    let exports = strings(&args["exports"]);
    for e in &exports {
        b = b.export(e)?;
    }
    b = b.timeout(timeout(config, args, Duration::from_secs(60))?);
    // What it asks for (within the cap), or more if the files need it.
    let asked = match &args["memory_mb"] {
        Value::Null => 0,
        v => {
            let mb = v.as_f64().filter(|m| *m >= 0.0).context("memory_mb must be a number of MiB")?;
            (mb.ceil() as u64).min(config.max_memory_mb)
        }
    };
    let memory_mb = asked.max(b.current_memory_mb());
    if memory_mb > config.max_memory_mb {
        bail!("this needs {memory_mb} MiB of memory; the server allows at most {} MiB", config.max_memory_mb);
    }
    b = b.memory_mb(memory_mb);
    let sandbox = b.build()?;
    let mut command = strings(&args["command"]);
    if command.is_empty() {
        command = sandbox.command().to_vec();
    }
    if command.is_empty() {
        bail!("no command (and the image has none)");
    }
    Ok((sandbox, command))
}

/// A run's result, for the agent: text, structured, and whether it's an error.
fn describe(out: &crate::RunOutput) -> (String, Value, bool) {
    let stdout = truncate(&out.stdout_str(), OUTPUT_MAX);
    let stderr = truncate(&out.stderr_str(), OUTPUT_MAX);
    let events: Vec<String> = out.events.iter().map(|e| e.to_string()).collect();
    let mut text = format!("exit: {:?} (code {}) in {} ms\n", out.status, out.status.code(), out.duration.as_millis());
    if !stdout.is_empty() {
        text += &format!("--- stdout ---\n{stdout}\n");
    }
    if !stderr.is_empty() {
        text += &format!("--- stderr ---\n{stderr}\n");
    }
    if !events.is_empty() {
        text += &format!("--- events ---\n{}\n", events.join("\n"));
    }
    let missing = out.missing_capabilities();
    if !missing.is_empty() {
        text += &format!("--- missing capabilities ---\n{}\n", missing.join(", "));
    }
    // Exported files, as text where they are, within a budget.
    let mut budget = EXPORT_MAX;
    let mut exported = Vec::new();
    for ex in &out.exports {
        let mut entries = Vec::new();
        for e in &ex.entries {
            let entry = match &e.content {
                ExportContent::Dir => json!({"path": e.path, "kind": "dir"}),
                ExportContent::Symlink(t) => json!({"path": e.path, "kind": "symlink", "target": t}),
                ExportContent::File(data) => match std::str::from_utf8(data) {
                    Ok(s) if s.len() <= budget => {
                        budget -= s.len();
                        json!({"path": e.path, "kind": "file", "size": data.len(), "content": s})
                    }
                    _ => json!({"path": e.path, "kind": "file", "size": data.len()}),
                },
            };
            entries.push(entry);
        }
        text += &format!("--- export {} ({:?}, {} entries) ---\n", ex.dir, ex.state, entries.len());
        for e in &entries {
            text += &format!("{}{}\n", e["path"].as_str().unwrap_or(""), if e["kind"] == "dir" { "/" } else { "" });
        }
        exported.push(json!({"dir": ex.dir, "state": ex.state, "entries": entries}));
    }
    // Changes the program made that didn't reach the host: the program
    // ended normally, so that's a failure the agent must hear about.
    let mut lost = false;
    for m in &out.mount_changes {
        text += &format!(
            "--- mount {} ({:?}): {} written, {} removed, {} conflicts ---\n",
            m.guest,
            m.state,
            m.written.len(),
            m.removed.len(),
            m.conflicts.len()
        );
        lost |= match &m.state {
            MountState::Applied => false,
            MountState::NotApplied => matches!(out.status, ExitStatus::Exited(_)),
            MountState::Failed(_) => true,
        };
    }
    let structured = json!({
        "status": out.status,
        "exit_code": out.status.code(),
        "stdout": stdout,
        "stderr": stderr,
        "events": events,
        "missing_capabilities": missing,
        "exports": exported,
        "mount_changes": out.mount_changes,
        "duration_ms": out.duration.as_millis() as u64,
    });
    // A program that failed is a result to show, not a tool error.
    (text, structured, lost)
}

fn build_image(config: &McpConfig, args: &Value) -> Result<(String, Value, bool)> {
    if !config.writable {
        bail!("this server doesn't write host files (it isn't --writable), so it can't build images");
    }
    let grixfile = config.host_path(args["grixfile"].as_str().context("no grixfile")?)?;
    let out = output_path(config, args)?;
    let mut log = Vec::new();
    let image = Grixfile::build_file(
        &grixfile,
        BuildOptions {
            kernel: None,
            on_output: &mut |_, d| {
                if log.len() < OUTPUT_MAX * 4 {
                    log.extend_from_slice(d)
                }
            },
            policy: config.build_policy(),
        },
    )?;
    image.write_to(&out)?;
    let (n, bytes) = image.size();
    let text = format!(
        "built {} ({n} entries, {} MiB)\n--- build output ---\n{}",
        out.display(),
        bytes >> 20,
        truncate(&String::from_utf8_lossy(&log), OUTPUT_MAX)
    );
    Ok((text, json!({"image": out, "entries": n, "bytes": bytes, "config": image.config}), false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_basics() {
        let config = McpConfig::new(&[std::env::temp_dir()]).unwrap();
        let input = [
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run","arguments":{"command":["/x"],"capabilities":["net"]}}}"#,
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"run","arguments":{"imports":[{"host":"/etc/passwd","guest":"/p"}],"command":["/p"]}}}"#,
            r#"{"jsonrpc":"2.0","id":5,"method":"nope"}"#,
            "not json",
            &format!(r#"{{"jsonrpc":"2.0","id":6,"method":"ping","pad":"{}"}}"#, "x".repeat(200)),
            r#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#,
        ]
        .join("\n");
        let mut out = Vec::new();
        serve_with_limit(&config, input.as_bytes(), &mut out, 150).unwrap();
        let replies: Vec<Value> =
            String::from_utf8(out).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(replies.len(), 8, "no answer to the notification");
        assert_eq!(replies[0]["result"]["serverInfo"]["name"], "grix");
        let names: Vec<&str> =
            replies[1]["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["run", "snapshot", "build_image"]);
        // net isn't allowed by default; paths outside the roots aren't either.
        assert_eq!(replies[2]["result"]["isError"], true);
        assert!(replies[2]["result"]["content"][0]["text"].as_str().unwrap().contains("doesn't allow the net"));
        assert!(
            replies[3]["result"]["content"][0]["text"].as_str().unwrap().contains("doesn't exist in the directories")
        );
        assert_eq!(replies[4]["error"]["code"], -32601);
        assert_eq!(replies[5]["error"]["code"], -32700);
        // A message too long is refused, and the next one is still read.
        assert_eq!(replies[6]["error"]["code"], -32700);
        assert!(replies[6]["error"]["message"].as_str().unwrap().contains("over 150 bytes"));
        assert_eq!(replies[7]["id"], 7);
    }
}
