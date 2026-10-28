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
//!
//! Tool calls run on their own threads (at most `max_parallel` at once),
//! so the server keeps reading: `notifications/cancelled` stops a call's
//! sandbox (or its build) and its answer isn't sent. When input ends, the
//! calls in progress finish and are answered. A call that comes with a
//! `progressToken` gets the program's output as it comes, in
//! `notifications/progress`.

use std::collections::HashMap;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use grix_abi::policy::Capability;
use serde_json::{Value, json};

use crate::RunControl;
use crate::build::{BuildOptions, BuildPolicy, Grixfile};
use crate::export::ExportContent;
use crate::mount::MountState;
use crate::sandbox::{ExitStatus, MountMode, Sandbox, Stream};

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
    /// The most CPUs a run may have.
    pub max_cpus: u32,
    /// Agents may change host files: writable mounts (`rw`, `on_exit`) and
    /// `build_image`'s output. Off by default.
    pub writable: bool,
    /// `build_image` may pull images with the user's registry logins. Off
    /// by default: what an agent builds is anonymous.
    pub registry_credentials: bool,
    /// How many tool calls run at once (each boots a VM, with up to
    /// `max_memory_mb`); more wait their turn.
    pub max_parallel: usize,
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
            max_cpus: 4,
            writable: false,
            registry_credentials: false,
            max_parallel: 2,
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
            credentials: self.registry_credentials,
            local_registries: false,
            cache: true,
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
/// How many tool calls may wait for a turn, besides those running.
const QUEUE_MAX: usize = 8;
/// The most of a call's output streamed as progress, and how often.
const STREAM_MAX: usize = OUTPUT_MAX * 4;
const STREAM_EVERY: Duration = Duration::from_millis(250);
const STREAM_CHUNK: usize = 8192;

/// Serve requests from `input` until it ends.
pub fn serve(config: &McpConfig, input: impl BufRead, output: impl Write + Send) -> Result<()> {
    serve_with_limit(config, input, output, MESSAGE_MAX)
}

/// Writes whole messages, one per line, from any thread.
type Sender<'a> = &'a (dyn Fn(&Value) + Sync);

fn serve_with_limit(config: &McpConfig, mut input: impl BufRead, output: impl Write + Send, max: usize) -> Result<()> {
    let output = Mutex::new(output);
    // A client that has gone has no use for answers: write errors are dropped.
    let send = |v: &Value| {
        let mut o = output.lock().unwrap();
        let _ = writeln!(o, "{v}").and_then(|()| o.flush());
    };
    let send: Sender = &send;
    // Calls in progress, by id (as JSON, so 1 and "1" differ), and whether
    // the client withdrew them (then they aren't answered).
    let calls: Mutex<HashMap<String, (RunControl, bool)>> = Mutex::new(HashMap::new());
    let slots = Slots { free: Mutex::new(config.max_parallel.max(1)), freed: Condvar::new() };
    std::thread::scope(|scope| -> Result<()> {
        let mut line = Vec::new();
        loop {
            line.clear();
            // At most `max` bytes and the newline.
            if (&mut input).take(max as u64 + 1).read_until(b'\n', &mut line)? == 0 {
                break;
            }
            if line.len() > max && line.last() != Some(&b'\n') {
                input.skip_until(b'\n')?;
                send(&error(Value::Null, -32700, &format!("message over {max} bytes")));
                continue;
            }
            if line.trim_ascii().is_empty() {
                continue;
            }
            let msg = match serde_json::from_slice::<Value>(&line) {
                Ok(msg) => msg,
                Err(e) => {
                    send(&error(Value::Null, -32700, &format!("parse error: {e}")));
                    continue;
                }
            };
            match (msg["method"].as_str(), msg.get("id")) {
                (Some("notifications/cancelled"), _) => {
                    let id = msg["params"]["requestId"].to_string();
                    if let Some((c, withdrawn)) = calls.lock().unwrap().get_mut(&id) {
                        *withdrawn = true;
                        c.cancel();
                    }
                }
                (Some("tools/call"), Some(id)) => {
                    let (id, key, control) = (id.clone(), id.to_string(), RunControl::new());
                    {
                        let mut calls = calls.lock().unwrap();
                        if calls.contains_key(&key) {
                            send(&error(id, -32600, "a request with this id is still in progress"));
                            continue;
                        }
                        // Each call waiting its turn holds its message (up to
                        // MESSAGE_MAX) and a thread: only so many wait.
                        if calls.len() >= config.max_parallel.max(1) + QUEUE_MAX {
                            send(&error(id, -32000, "too many tool calls in progress: wait for some to finish"));
                            continue;
                        }
                        calls.insert(key.clone(), (control.clone(), false));
                    }
                    let (calls, slots) = (&calls, &slots);
                    let reply_id = id.clone();
                    let spawned = std::thread::Builder::new().spawn_scoped(scope, move || {
                        let token = msg["params"]["_meta"]["progressToken"].clone();
                        let progress = Progress::new(send, token);
                        let reply = match slots.take(&control, &progress) {
                            Some(_slot) => {
                                let work = || call_tool(config, &msg, id.clone(), &control, &progress);
                                // A bug in a tool is that call's error, not the server's end.
                                match progress.ticking(|| std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)))
                                {
                                    Ok(reply) => reply,
                                    Err(_) => {
                                        control.cancel();
                                        Some(error(id, -32603, "internal error"))
                                    }
                                }
                            }
                            None => Some(error(id, -32800, "cancelled")),
                        };
                        let withdrawn = calls.lock().unwrap().remove(&key).is_some_and(|(_, w)| w);
                        // A call the client cancelled isn't answered (as the
                        // protocol has it).
                        if let Some(reply) = reply.filter(|_| !withdrawn) {
                            progress.flush();
                            send(&reply);
                        }
                    });
                    if let Err(e) = spawned {
                        calls.lock().unwrap().remove(&reply_id.to_string());
                        send(&error(reply_id, -32000, &format!("can't start the call: {e}")));
                    }
                }
                _ => {
                    if let Some(reply) = handle(config, &msg) {
                        send(&reply);
                    }
                }
            }
        }
        // The client has closed its end: the calls it made still finish and
        // are answered (the scope waits for them), as before calls ran in
        // parallel. A client that's leaving cancels them, or ends the server.
        Ok(())
    })
}

/// Turns for tool calls: at most `max_parallel` at once.
struct Slots {
    free: Mutex<usize>,
    freed: Condvar,
}

struct Slot<'a>(&'a Slots);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        *self.0.free.lock().unwrap() += 1;
        self.0.freed.notify_one();
    }
}

impl Slots {
    /// Wait for a turn, unless the call is cancelled meanwhile.
    fn take(&self, control: &RunControl, progress: &Progress) -> Option<Slot<'_>> {
        let mut free = self.free.lock().unwrap();
        let mut said = false;
        loop {
            if control.is_cancelled() {
                return None;
            }
            if *free > 0 {
                *free -= 1;
                return Some(Slot(self));
            }
            if !said {
                said = true;
                progress.note("waiting for another call to finish (the server runs a few at a time)");
            }
            free = self.freed.wait_timeout(free, Duration::from_millis(100)).unwrap().0;
        }
    }
}

/// A call's progress notifications: its output as it comes, a few times a
/// second (`ticking` sends what waits even when no more comes), up to
/// `STREAM_MAX` (the answer has the output too).
struct Progress<'a> {
    send: Sender<'a>,
    token: Value,
    state: Mutex<Streamed>,
}

#[derive(Default)]
struct Streamed {
    count: u64,
    bytes: usize,
    pending: [Vec<u8>; 2],
    last: Option<Instant>,
}

impl<'a> Progress<'a> {
    fn new(send: Sender<'a>, token: Value) -> Progress<'a> {
        Progress { send, token, state: Mutex::default() }
    }

    fn wanted(&self) -> bool {
        self.token.is_string() || self.token.is_number()
    }

    fn notify(&self, s: &mut Streamed, message: &str) {
        s.count += 1;
        (self.send)(&json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {
            "progressToken": self.token, "progress": s.count, "message": message}}));
    }

    /// Something the server has to say.
    fn note(&self, message: &str) {
        if self.wanted() {
            let mut s = self.state.lock().unwrap();
            self.send_pending(&mut s);
            self.notify(&mut s, message);
        }
    }

    fn output(&self, stream: Stream, data: &[u8]) {
        if !self.wanted() {
            return;
        }
        let mut s = self.state.lock().unwrap();
        if s.bytes >= STREAM_MAX {
            return;
        }
        let take = data.len().min(STREAM_MAX - s.bytes);
        s.bytes += take;
        s.pending[(stream == Stream::Stderr) as usize].extend_from_slice(&data[..take]);
        let waiting = s.pending.iter().map(Vec::len).sum::<usize>();
        if waiting >= STREAM_CHUNK || s.last.is_none_or(|t| t.elapsed() >= STREAM_EVERY) {
            self.send_pending(&mut s);
        }
        if s.bytes >= STREAM_MAX {
            self.send_pending(&mut s);
            let note = format!("[output past {} KiB isn't streamed; the answer has what fits]", STREAM_MAX >> 10);
            self.notify(&mut s, &note);
        }
    }

    fn flush(&self) {
        let mut s = self.state.lock().unwrap();
        self.send_pending(&mut s);
    }

    fn send_pending(&self, s: &mut Streamed) {
        s.last = Some(Instant::now());
        for (i, prefix) in [(0, ""), (1, "[stderr] ")] {
            if !s.pending[i].is_empty() {
                let text = format!("{prefix}{}", String::from_utf8_lossy(&std::mem::take(&mut s.pending[i])));
                self.notify(s, &text);
            }
        }
    }

    /// Do `work`, sending what output waits every `STREAM_EVERY` meanwhile.
    fn ticking<T>(&self, work: impl FnOnce() -> T) -> T {
        if !self.wanted() {
            return work();
        }
        let done = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                while !done.load(std::sync::atomic::Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(50));
                    let mut s = self.state.lock().unwrap();
                    if s.last.is_none_or(|t| t.elapsed() >= STREAM_EVERY) {
                        self.send_pending(&mut s);
                    }
                }
            });
            let out = work();
            done.store(true, std::sync::atomic::Ordering::Relaxed);
            out
        })
    }
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// A tool call's answer.
fn call_tool(config: &McpConfig, msg: &Value, id: Value, control: &RunControl, progress: &Progress) -> Option<Value> {
    let name = msg["params"]["name"].as_str().unwrap_or("");
    let args = &msg["params"]["arguments"];
    let outcome = match name {
        "run" => run(config, args, control, progress),
        "snapshot" => snapshot(config, args, control),
        "build_image" => build_image(config, args, control, progress),
        _ => return Some(error(id, -32602, &format!("unknown tool {name:?}"))),
    };
    let result = match outcome {
        Ok((text, structured, failed)) => json!({
            "content": [{"type": "text", "text": text}],
            "structuredContent": structured,
            "isError": failed,
        }),
        Err(e) => json!({"content": [{"type": "text", "text": format!("{e:#}")}], "isError": true}),
    };
    Some(json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

/// The answer to a message that isn't a tool call (none for notifications).
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
                        waited, with `stdin`. Then only stdin, timeout_secs and mounts apply (each of the snapshot's \
                        live mounts needs its host directory again); what comes back is what the snapshot's sandbox \
                        exported."});
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
            "description": "Start a program in a sandbox (the same options as `run`, but no on_exit mounts) and save the whole \
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
                        "mode": {"type": "string", "enum": ["rw", "ro", "on_exit", "lazy"]}}, "required": ["host", "guest"]},
                        "description": "Host directories to mount (rw: changes reach the host at once; on_exit: when the program ends; \
                                        both only if the server is writable; lazy: imported without copying, read as used, changes \
                                        stay in the sandbox)."},
                    "env": {"type": "object", "additionalProperties": {"type": "string"}},
                    "cwd": {"type": "string"},
                    "capabilities": {"type": "array", "items": {"type": "string", "enum": caps}},
                    "exports": {"type": "array", "items": {"type": "string"},
                                "description": "Sandbox directories whose contents to return when the program ends."},
                    "timeout_secs": {"type": "number"},
                    "memory_mb": {"type": "number"},
                    "x86_64": {"type": "string",
                               "description": "Run x86_64 Linux programs with this translator (a host file: an arm64 \
                                               qemu-x86_64 in user mode (needs threads); box64 untested)."},
                    "cpus": {"type": "integer", "minimum": 1,
                             "description": "CPUs for the program's threads (default 1; a run from a snapshot has the snapshot's)."}
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

fn run(config: &McpConfig, args: &Value, control: &RunControl, progress: &Progress) -> Result<(String, Value, bool)> {
    let stdin = args["stdin"].as_str().unwrap_or("").as_bytes().to_vec();
    let out = match args["snapshot"].as_str() {
        Some(path) => {
            // Whoever wrote the file, runs from it get only the network
            // this server allows.
            let mut snap = crate::Snapshot::open(config.host_path(path)?)?
                .restrict_net(config.capabilities.contains(&Capability::Net), &config.allow_hosts)?
                .limits(OUTPUT_MAX * 4, EXPORT_LIMIT, Duration::from_secs(5));
            // Its live mounts' host directories, under the roots; writable
            // only if this server lets agents change host files.
            for m in args["mounts"].as_array().into_iter().flatten() {
                let host = config.host_path(m["host"].as_str().context("mount without host")?)?;
                let guest = m["guest"].as_str().context("mount without guest")?;
                let writable = m["mode"].as_str().unwrap_or("rw") == "rw"
                    && config.writable
                    && config.capabilities.contains(&Capability::FsWrite);
                snap = if writable { snap.mount(host, guest)? } else { snap.mount_read_only(host, guest)? };
            }
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
            if snap.cpus() > config.max_cpus {
                bail!("the snapshot has {} CPUs; the server allows at most {}", snap.cpus(), config.max_cpus);
            }
            let t = timeout(config, args, snap.default_timeout())?;
            snap.timeout(t).control(control).run_streaming(std::io::Cursor::new(stdin), |s, d| progress.output(s, d))?
        }
        None => {
            let (sandbox, command) = sandbox(config, args, control)?;
            match args["stdin"].as_str() {
                Some(_) => sandbox
                    .run_streaming_with_stdin(&command, std::io::Cursor::new(stdin), |s, d| progress.output(s, d))?,
                None => sandbox.run_streaming(&command, |s, d| progress.output(s, d))?,
            }
        }
    };
    Ok(describe(&out))
}

fn snapshot(config: &McpConfig, args: &Value, control: &RunControl) -> Result<(String, Value, bool)> {
    if !config.writable {
        bail!("this server doesn't write host files (it isn't --writable), so it can't save snapshots");
    }
    if args["mounts"].as_array().into_iter().flatten().any(|m| m["mode"] == "on_exit") {
        bail!("a snapshot can't have on_exit mounts");
    }
    let out = output_path(config, args)?;
    let (sandbox, command) = sandbox(config, args, control)?;
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
fn sandbox(config: &McpConfig, args: &Value, control: &RunControl) -> Result<(Sandbox, Vec<String>)> {
    let cpus = match &args["cpus"] {
        Value::Null => 1,
        v => v.as_u64().filter(|n| *n >= 1).context("cpus must be a whole number of CPUs")?,
    };
    if cpus > config.max_cpus as u64 {
        bail!("{cpus} CPUs: the server allows at most {}", config.max_cpus);
    }
    let mut b = Sandbox::builder().max_output(OUTPUT_MAX * 4).cpus(cpus as u32);
    if let Some(t) = args["x86_64"].as_str() {
        b = b.x86_64(config.host_path(t)?)?;
    }
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
            "lazy" => MountMode::Lazy,
            other => bail!("mount mode {other:?} isn't rw, ro or on_exit"),
        };
        if !matches!(mode, MountMode::ReadOnly | MountMode::Lazy)
            && !(config.writable && config.capabilities.contains(&Capability::FsWrite))
        {
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
    b = b.memory_mb(memory_mb).control(control);
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

fn build_image(
    config: &McpConfig,
    args: &Value,
    control: &RunControl,
    progress: &Progress,
) -> Result<(String, Value, bool)> {
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
            on_output: &mut |s, d| {
                progress.output(s, d);
                if log.len() < OUTPUT_MAX * 4 {
                    log.extend_from_slice(d)
                }
            },
            policy: config.build_policy(),
            control: Some(control.clone()),
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
        let mut replies: Vec<Value> =
            String::from_utf8(out).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        // Tool calls answer when they're done: in order of id (the two
        // errors without one came in order too).
        let key = |v: &Value| v["id"].as_u64().unwrap_or(5);
        replies.sort_by_key(key);
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
