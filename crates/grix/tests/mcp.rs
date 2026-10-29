//! The MCP server, through the `grix mcp` binary, as an agent sees it.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{Value, json};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/build").canonicalize().unwrap()
}

fn x86_64_guest() -> bool {
    grix::Arch::from_env() == grix::Arch::X86_64
}

/// Alpine's static busybox for the guest's architecture (`GRIX_ARCH`).
fn busybox(fixtures: &Path) -> PathBuf {
    fixtures.join(if x86_64_guest() { "alpine-x86_64" } else { "alpine" }).join("bin/busybox.static")
}

struct Server {
    child: Child,
    to: Option<ChildStdin>,
    from: BufReader<ChildStdout>,
    next: u64,
}

impl Server {
    fn start(args: &[&str], roots: &[&Path]) -> Server {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_grix"));
        cmd.arg("mcp").args(args);
        for r in roots {
            cmd.arg("--root").arg(r);
        }
        let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let to = child.stdin.take();
        let from = BufReader::new(child.stdout.take().unwrap());
        Server { child, to, from, next: 1 }
    }

    fn call(&mut self, msg: Value) -> Value {
        self.send(msg);
        self.read()
    }

    fn send(&mut self, msg: Value) {
        writeln!(self.to.as_mut().unwrap(), "{msg}").unwrap();
    }

    fn read(&mut self) -> Value {
        let mut line = String::new();
        self.from.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    /// A tool call's result.
    fn tool(&mut self, name: &str, arguments: Value) -> Value {
        self.next += 1;
        let id = self.next;
        let reply = self.call(json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
                                     "params": {"name": name, "arguments": arguments}}));
        reply["result"].clone()
    }

    fn end(mut self) {
        drop(self.to.take());
        assert!(self.child.wait().unwrap().success());
    }
}

fn text(result: &Value) -> &str {
    result["content"][0]["text"].as_str().unwrap()
}

#[test]
fn an_agent_runs_programs_over_mcp() {
    let fixtures = fixtures();
    let mut server = Server::start(&[], &[&fixtures]);
    let mut call = |msg: Value| server.call(msg);
    let init =
        call(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}));
    assert_eq!(init["result"]["capabilities"]["tools"], json!({}));
    let busybox = busybox(&fixtures);
    let run = call(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "run", "arguments": {
        "imports": [{"host": busybox, "guest": "/bin/busybox"}],
        "files": [{"path": "/in.txt", "content": "pear\napple\n"}],
        "command": ["/bin/busybox", "sh", "-c", "/bin/busybox sort /in.txt | /bin/busybox tee /out/sorted; /bin/busybox wget -q -O- http://example.com"],
        "stdin": "",
        "capabilities": ["fs_write", "process"],
        "exports": ["/out"]
    }}}));
    let r = &run["result"];
    assert_eq!(r["isError"], false, "{r}");
    let s = &r["structuredContent"];
    assert_eq!(s["stdout"], "apple\npear\n");
    assert_eq!(s["exports"][0]["entries"][0]["content"], "apple\npear\n");
    // No net: wget's socket is denied, and the agent hears which capability.
    assert_eq!(s["missing_capabilities"], json!(["net"]));
    assert!(r["content"][0]["text"].as_str().unwrap().contains("--- events ---"));
    // Only what the server allows.
    let denied =
        call(json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "run", "arguments": {
        "command": ["/bin/busybox"], "capabilities": ["net"]}}}));
    assert_eq!(denied["result"]["isError"], true);
    // Limits the agent can't talk its way past.
    for (args, why) in [
        (json!({"command": ["/bin/busybox"], "timeout_secs": -1}), "timeout_secs"),
        (json!({"command": ["/bin/busybox"], "timeout_secs": "soon"}), "timeout_secs"),
        (json!({"command": ["/bin/busybox"], "memory_mb": -5}), "memory_mb"),
        (json!({"command": ["/bin/busybox"], "imports": [{"host": "/etc/hosts", "guest": "/h"}]}), "doesn't exist in"),
        (
            json!({"command": ["/bin/busybox"], "imports": [{"host": fixtures.join("nope"), "guest": "/h"}]}),
            "doesn't exist in",
        ),
        (
            json!({"command": ["/bin/busybox"], "mounts": [{"host": fixtures, "guest": "/m", "mode": "rw"}]}),
            "writable mounts",
        ),
        (
            json!({"command": ["/bin/busybox"], "mounts": [{"host": fixtures, "guest": "/m", "mode": "on_exit"}]}),
            "writable mounts",
        ),
    ] {
        let r = server.tool("run", args);
        assert_eq!(r["isError"], true, "{r}");
        assert!(text(&r).contains(why), "{why}: {}", text(&r));
    }
    let r =
        server.tool("build_image", json!({"grixfile": fixtures.join("Grixfile"), "output": fixtures.join("x.grix")}));
    assert!(text(&r).contains("isn't --writable"), "{}", text(&r));
    server.end();
}

/// With `--writable`: mounts that write back, and images built from what
/// the server allows (no registry or Docker without `net`).
#[test]
fn a_writable_server_builds_images_and_writes_mounts() {
    let fixtures = fixtures();
    let dir = std::env::temp_dir().join(format!("grix-mcp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("work")).unwrap();
    std::fs::create_dir_all(dir.join("ctx")).unwrap();
    std::fs::copy(busybox(&fixtures), dir.join("ctx/busybox")).unwrap();
    let dir = dir.canonicalize().unwrap();
    let mut server = Server::start(&["--writable", "--max-mem", "1024"], &[&fixtures, &dir]);
    let busybox = busybox(&fixtures);

    let r = server.tool(
        "run",
        json!({
            "imports": [{"host": busybox, "guest": "/bin/busybox"}],
            "mounts": [{"host": dir.join("work"), "guest": "/work", "mode": "on_exit"}],
            "command": ["/bin/busybox", "sh", "-c", "echo made > /work/new.txt"],
            "capabilities": ["fs_write", "process"],
        }),
    );
    assert_eq!(r["isError"], false, "{r}");
    let m = &r["structuredContent"]["mount_changes"][0];
    assert_eq!(m["state"], "applied", "{m}");
    assert_eq!(m["written"], json!(["new.txt"]));
    assert_eq!(std::fs::read_to_string(dir.join("work/new.txt")).unwrap(), "made\n");
    // More memory than the server allows is capped; more than it can give fails.
    let r = server.tool(
        "run",
        json!({"imports": [{"host": busybox, "guest": "/bin/busybox"}],
                                      "command": ["/bin/busybox", "true"], "memory_mb": 99999}),
    );
    assert_eq!(r["structuredContent"]["exit_code"], 0, "{r}");

    for (from, why) in [("alpine:3.21", "may not pull images from registries"), ("docker:alpine", "Docker daemon")] {
        std::fs::write(dir.join("ctx/Grixfile"), format!("from = {from:?}\n")).unwrap();
        let r = server.tool("build_image", json!({"grixfile": dir.join("ctx/Grixfile"), "output": dir.join("x.grix")}));
        assert_eq!(r["isError"], true, "{r}");
        assert!(text(&r).contains(why), "{from}: {}", text(&r));
    }
    // From nothing, with a build step (which runs with the server's caps).
    std::fs::write(
        dir.join("ctx/Grixfile"),
        "command = [\"/bin/busybox\", \"cat\", \"/msg\"]\n\
         capabilities = [\"process\"]\n\
         run = [[\"/bin/busybox\", \"sh\", \"-c\", \"echo built > /msg\"]]\n\
         [[copy]]\nhost = \"busybox\"\nguest = \"/bin/busybox\"\n",
    )
    .unwrap();
    let r = server.tool("build_image", json!({"grixfile": dir.join("ctx/Grixfile"), "output": dir.join("x.grix")}));
    assert_eq!(r["isError"], false, "{r}");
    let r = server.tool("run", json!({"image": dir.join("x.grix")}));
    assert_eq!(r["structuredContent"]["stdout"], "built\n", "{r}");
    // A snapshot of a shell waiting for a line, and runs from it.
    let r = server.tool(
        "snapshot",
        json!({
            "imports": [{"host": busybox, "guest": "/bin/busybox"}],
            "command": ["/bin/busybox", "sh", "-c", "read line; echo \"hello $line\""],
            "output": dir.join("sh.snap"),
        }),
    );
    if x86_64_guest() {
        assert!(text(&r).contains("snapshots of x86_64 machines"), "{}", text(&r));
    } else if grix::Sandbox::builder().vmm_path().is_some() {
        assert_eq!(r["isError"], false, "{r}");
        for who in ["agent", "again"] {
            let r = server.tool("run", json!({"snapshot": dir.join("sh.snap"), "stdin": format!("{who}\n")}));
            assert_eq!(r["structuredContent"]["stdout"], format!("hello {who}\n"), "{r}");
        }
        // One with two CPUs, for the server below that allows one.
        let r = server.tool(
            "snapshot",
            json!({
                "imports": [{"host": busybox, "guest": "/bin/busybox"}],
                "command": ["/bin/busybox", "sh", "-c", "read line; echo \"hello $line\""],
                "output": dir.join("sh2.snap"),
                "cpus": 2,
            }),
        );
        assert_eq!(r["isError"], false, "{r}");
    } else {
        assert!(text(&r).contains("grix's own VMM"), "{}", text(&r));
    }
    // An image may ask only for what the server allows.
    std::fs::write(
        dir.join("ctx/Grixfile"),
        "command = [\"/bin/busybox\"]\ncapabilities = [\"threads\"]\n[[copy]]\nhost = \"busybox\"\nguest = \"/bin/busybox\"\n",
    )
    .unwrap();
    server.end();
    let mut server = Server::start(&["--writable", "-a", "process", "-a", "fs_write", "--max-cpus", "1"], &[&dir]);
    // A snapshot's CPUs are capped like a sandbox's.
    if dir.join("sh2.snap").exists() {
        let r = server.tool("run", json!({"snapshot": dir.join("sh2.snap"), "stdin": "x\n"}));
        assert!(text(&r).contains("the server allows at most 1"), "{}", text(&r));
    }
    let r = server.tool("build_image", json!({"grixfile": dir.join("ctx/Grixfile"), "output": dir.join("y.grix")}));
    assert_eq!(r["isError"], false, "{r}");
    let r = server.tool("run", json!({"image": dir.join("y.grix")}));
    assert!(text(&r).contains("threads capability, which this server doesn't allow"), "{}", text(&r));
    server.end();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// With `net` and an allow-list, a build's registry pulls connect only
/// where the list allows, as its steps do: not this machine under another
/// name for it, and not anywhere the list doesn't name.
#[test]
fn registry_pulls_keep_to_the_network_policy() {
    let dir = std::env::temp_dir().join(format!("grix-mcp-pull-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let dir = dir.canonicalize().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let mut server = Server::start(&["--writable", "--allow", "net", "--allow-host", "allowed.invalid:443"], &[&dir]);
    for (from, why) in [
        (format!("127.0.0.2:{port}/review/probe:1"), "on this machine"),
        (format!("[::ffff:127.0.0.1]:{port}/review/probe:1"), "on this machine"),
        ("example.com/review/probe:1".to_string(), "isn't in the allow-list"),
    ] {
        std::fs::write(dir.join("Grixfile"), format!("from = {from:?}\n")).unwrap();
        let r = server.tool("build_image", json!({"grixfile": dir.join("Grixfile"), "output": dir.join("x.grix")}));
        assert_eq!(r["isError"], true, "{r}");
        assert!(text(&r).contains(why), "{from}: {}", text(&r));
    }
    server.end();
    assert!(listener.accept().is_err(), "a pull connected to this machine");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn progress_and_cancellation() {
    // Two calls at once: one streams its output as progress, the other is
    // withdrawn mid-run and never answered.
    let fixtures = fixtures();
    let busybox = busybox(&fixtures);
    let mut server = Server::start(&["--max-parallel", "2"], &[&fixtures]);
    let started = std::time::Instant::now();
    let call = |id: u64, token: Value, script: &str| {
        json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {
        "name": "run",
        "_meta": {"progressToken": token},
        "arguments": {
            "imports": [{"host": busybox, "guest": "/bin/busybox"}],
            "command": ["/bin/busybox", "sh", "-c", script],
            "capabilities": ["process"],
            "timeout_secs": 120,
        }}})
    };
    server.send(call(10, json!("long"), "/bin/busybox sleep 100"));
    server.send(call(11, json!(7), "echo one; /bin/busybox sleep 1; echo two >&2; echo three"));
    let (mut messages, mut last) = (String::new(), 0);
    let reply = loop {
        let v = server.read();
        assert_ne!(v["id"], 10, "{v}");
        if v["method"] == "notifications/progress" {
            assert_eq!(v["params"]["progressToken"], 7, "{v}");
            let n = v["params"]["progress"].as_u64().unwrap();
            assert!(n > last, "progress goes up");
            last = n;
            messages.push_str(v["params"]["message"].as_str().unwrap());
        } else {
            break v;
        }
    };
    assert_eq!(reply["id"], 11, "{reply}");
    assert_eq!(reply["result"]["structuredContent"]["stdout"], "one\nthree\n");
    assert!(messages.contains("one\n") && messages.contains("[stderr] two\n"), "{messages:?}");
    // Output that waits is sent even when no more comes.
    server.send(call(13, json!("tick"), "echo a; /bin/busybox usleep 50000; echo b; /bin/busybox sleep 3; echo c"));
    let mut b_at = None;
    let reply = loop {
        let v = server.read();
        if v["method"] == "notifications/progress" {
            if v["params"]["message"].as_str().unwrap().contains('b') {
                b_at.get_or_insert(std::time::Instant::now());
            }
        } else {
            break v;
        }
    };
    assert_eq!(reply["id"], 13, "{reply}");
    let b_at = b_at.expect("b was streamed");
    assert!(b_at.elapsed() > std::time::Duration::from_secs(1), "b came during the sleep, not with the answer");
    // Withdrawn: it stops, and only the ping is answered.
    server.send(
        json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 10, "reason": "test"}}),
    );
    let pong = server.call(json!({"jsonrpc": "2.0", "id": 12, "method": "ping"}));
    assert_eq!(pong["id"], 12, "{pong}");
    server.end();
    assert!(started.elapsed() < std::time::Duration::from_secs(60), "the sleep was stopped");
}
