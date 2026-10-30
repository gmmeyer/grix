//! End-to-end tests with real language runtimes: Alpine's python3 and nodejs,
//! unmodified. Needs `make fixtures` (or `make test`).

use std::path::PathBuf;
use std::time::Duration;

use grix::{Capability, ExitStatus, ExportContent, ExportState, GuestEvent, RunOutput, Sandbox, SandboxBuilder};

/// A runtime's root (or a fixture) for the guest's architecture
/// (`GRIX_ARCH`): x86_64's are `<name>-x86_64`.
fn runtime(name: &str) -> PathBuf {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/build");
    let p = match (grix::Arch::from_env(), name.split_once('/')) {
        (grix::Arch::X86_64, Some((root, rest))) => base.join(format!("{root}-x86_64")).join(rest),
        (grix::Arch::X86_64, None) => base.join(format!("{name}-x86_64")),
        _ => base.join(name),
    };
    assert!(p.exists(), "missing runtime {} — run `make fixtures`", p.display());
    p
}

/// A sandbox containing one runtime's root filesystem, with threads allowed.
fn sandbox(name: &str) -> SandboxBuilder {
    Sandbox::builder()
        .timeout(Duration::from_secs(120))
        .memory_mb(1024)
        .allow(Capability::Threads)
        .import(runtime(name), "/")
        .unwrap()
        .file("/data/msg.txt", "hello from the host\n", 0o644)
        .unwrap()
}

fn run(b: SandboxBuilder, argv: &[&str]) -> RunOutput {
    let out = b.build().unwrap().run(argv).unwrap();
    assert_eq!(
        out.status,
        ExitStatus::Exited(0),
        "stdout:\n{}\nstderr:\n{}\n{:?}",
        out.stdout_str(),
        out.stderr_str(),
        out.events
    );
    out
}

/// Anything besides harmless path probing and pycache writes means a missing kernel feature.
fn assert_no_surprises(out: &RunOutput) {
    for e in &out.events {
        let fine = matches!(e, GuestEvent::MissingPath { .. })
            || matches!(e, GuestEvent::Denied { capability, .. } if capability == "fs_write");
        assert!(fine, "unexpected event: {e}");
    }
}

const PYTHON: &str = r#"
import asyncio, hashlib, json, os, re, threading, time
print("sha256", hashlib.sha256(b"hello").hexdigest())
print("json", json.dumps({"a": [1, 2, {"b": 3}]}))
results = []
threads = [threading.Thread(target=lambda: results.append(sum(range(100000)))) for _ in range(4)]
for t in threads: t.start()
for t in threads: t.join()
print("threads", results)
async def main():
    t0 = time.monotonic()
    await asyncio.gather(*(asyncio.sleep(0.05) for _ in range(10)))
    return time.monotonic() - t0
print("asyncio", asyncio.run(main()) < 0.5)
print("file", open("/data/msg.txt").read().strip())
print("misc", len(os.urandom(16)), re.findall(r"\d+", "a1b22c333"))
"#;

#[test]
fn python() {
    let b = sandbox("python").env("PYTHONDONTWRITEBYTECODE", "1").file("/data/test.py", PYTHON, 0o644).unwrap();
    let out = run(b, &["/usr/bin/python3", "/data/test.py"]);
    assert_eq!(
        out.stdout_str(),
        "sha256 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\n\
         json {\"a\": [1, 2, {\"b\": 3}]}\n\
         threads [4999950000, 4999950000, 4999950000, 4999950000]\n\
         asyncio True\n\
         file hello from the host\n\
         misc 16 ['1', '22', '333']\n"
    );
    assert_no_surprises(&out);
}

/// AF_UNIX sockets from Python: an asyncio server on a path, descriptors
/// passed with send_fds, and a multiprocessing Manager (a listener on a
/// path, in another process).
#[test]
fn unix_sockets_from_python() {
    let script = r#"
import asyncio, multiprocessing, os, socket, tempfile
async def main():
    path = os.path.join(tempfile.mkdtemp(), "srv.sock")
    async def handle(r, w):
        w.write((await r.readline()).upper()); await w.drain(); w.close()
    srv = await asyncio.start_unix_server(handle, path)
    r, w = await asyncio.open_unix_connection(path)
    w.write(b"hello\n"); await w.drain()
    print("asyncio", (await r.readline()).decode().strip())
    srv.close()
asyncio.run(main())
a, b = socket.socketpair()
rd, wr = os.pipe()
socket.send_fds(a, [b"fd"], [wr])
msg, fds, flags, addr = socket.recv_fds(b, 16, 1)
os.write(fds[0], b"passed")
print("send_fds", msg.decode(), os.read(rd, 16).decode())
if __name__ == "__main__":
    with multiprocessing.Manager() as m:
        d = m.dict(); d["x"] = 42
        print("manager", d["x"])
"#;
    let b =
        sandbox("python").allow(Capability::Process).allow(Capability::FsWrite).file("/t.py", script, 0o644).unwrap();
    let out = run(b, &["/usr/bin/python3", "/t.py"]);
    assert_eq!(out.stdout_str(), "asyncio HELLO\nsend_fds fd passed\nmanager 42\n");
    assert_no_surprises(&out);
}

/// Several processes writing one SQLite database in WAL mode: POSIX
/// record locks between them, and the -shm file mapped shared.
#[test]
fn sqlite_from_several_processes() {
    let script = r#"
import os, sqlite3
db = "/tmp/t.db"
c = sqlite3.connect(db)
print(c.execute("pragma journal_mode=wal").fetchone()[0])
c.execute("create table t (v)")
c.commit()
c.close()
pids = []
for w in range(4):
    pid = os.fork()
    if pid == 0:
        c = sqlite3.connect(db, timeout=60)
        for i in range(200):
            c.execute("insert into t values (?)", (w * 1000 + i,))
            c.commit()
        os._exit(0)
    pids.append(pid)
print([os.waitpid(pid, 0)[1] for pid in pids])
print(sqlite3.connect(db).execute("select count(*), count(distinct v) from t").fetchone())
"#;
    let b =
        sandbox("python").allow(Capability::Process).allow(Capability::FsWrite).file("/t.py", script, 0o644).unwrap();
    let out = run(b, &["/usr/bin/python3", "/t.py"]);
    assert_eq!(out.stdout_str(), "wal\n[0, 0, 0, 0]\n(800, 800)\n");
    assert_no_surprises(&out);
}

/// An interactive shell on a pseudo-terminal, driven from Python: job
/// control (^Z, jobs, fg), ^C, and the terminal's echo and CR NL.
#[test]
fn an_interactive_shell_on_a_pty() {
    let script = r#"
import os, pty, select, time
pid, fd = pty.fork()
if pid == 0:
    os.environ["PS1"] = "$ "
    os.execv("/bin/busybox", ["sh", "-i"])
def drain(until):
    out = b""
    end = time.time() + 20
    while until not in out and time.time() < end:
        if select.select([fd], [], [], 0.05)[0]:
            out += os.read(fd, 4096)
    return out.decode()
log = drain(b"$ ")
for cmd, until in [("echo hi\n", "$ "), ("/bin/busybox sleep 30\n", "sleep 30\r\n"), ("\x1a", "$ "),
                   ("jobs\n", "$ "), ("fg\n", "sleep 30\r\n"), ("\x03", "$ "), ("echo $?\n", "$ "), ("exit\n", "exit")]:
    time.sleep(0.2)
    os.write(fd, cmd.encode())
    log += drain(until.encode())
print(log.replace("\x1b[6n", ""))
print("status", os.waitpid(pid, 0)[1])
"#;
    let b = sandbox("python")
        .import(runtime("alpine/bin/busybox.static"), "/bin/busybox")
        .unwrap()
        .allow(Capability::Process)
        .file("/t.py", script, 0o644)
        .unwrap();
    let out = run(b, &["/usr/bin/python3", "/t.py"]);
    let stdout = out.stdout_str();
    for want in
        ["echo hi\r\nhi\r\n", "^Z[1]+  Stopped", "jobs\r\n[1]+  Stopped", "^C\r\n", "echo $?\r\n130\r\n", "status 0"]
    {
        assert!(stdout.contains(want), "{want:?} in {stdout}");
    }
    assert_no_surprises(&out);
}

const PYTHON_FILES: &str = r#"
import json, os, pathlib, shutil, sqlite3, tempfile
d = tempfile.mkdtemp()
p = pathlib.Path(d, "a", "b")
p.mkdir(parents=True)
(p / "x.json").write_text(json.dumps({"k": [1, 2]}))
shutil.copy(p / "x.json", p / "y.json")
os.replace(p / "y.json", p / "z.json")
db = sqlite3.connect(os.path.join(d, "t.db"))
db.execute("create table t (v)")
db.executemany("insert into t values (?)", [(i,) for i in range(1000)])
db.commit()
print("sqlite", db.execute("select count(*), sum(v) from t").fetchone())
db.close()
with tempfile.TemporaryFile() as f:
    f.write(b"scratch")
    f.seek(0)
    print("tempfile", f.read())
print("tree", sorted(str(q.relative_to(d)) for q in pathlib.Path(d).rglob("*")))
print("json", json.loads((p / "z.json").read_text()))
shutil.rmtree(d)
print("removed", not os.path.exists(d))
"#;

#[test]
fn python_files() {
    let b = sandbox("python")
        .allow(Capability::FsWrite)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .file("/data/test.py", PYTHON_FILES, 0o644)
        .unwrap();
    let out = run(b, &["/usr/bin/python3", "/data/test.py"]);
    assert_eq!(
        out.stdout_str(),
        "sqlite (1000, 499500)\n\
         tempfile b'scratch'\n\
         tree ['a', 'a/b', 'a/b/x.json', 'a/b/z.json', 't.db']\n\
         json {'k': [1, 2]}\n\
         removed True\n"
    );
    assert_no_surprises(&out);
}

const NODE: &str = r#"
const crypto = require('crypto');
const fs = require('fs');
const { Worker, isMainThread, parentPort } = require('worker_threads');
if (!isMainThread) {
  let s = 0; for (let i = 0; i < 1e6; i++) s += i;
  parentPort.postMessage(s);
} else {
  (async () => {
    const t0 = Date.now();
    await new Promise(r => setTimeout(r, 50));
    console.log('timer', Date.now() - t0 >= 50);
    console.log('sha256', crypto.createHash('sha256').update('hello').digest('hex'));
    console.log('file', fs.readFileSync('/data/msg.txt', 'utf8').trim());
    const sum = await new Promise((res, rej) => { const w = new Worker(__filename); w.on('message', res); w.on('error', rej); });
    console.log('worker', sum);
    console.log('json', JSON.stringify({a: [1, 2, {b: 3}]}));
  })().catch(e => { console.error(e); process.exit(1); });
}
"#;

#[test]
fn node() {
    let b = sandbox("node").file("/data/test.js", NODE, 0o644).unwrap();
    let out = run(b, &["/usr/bin/node", "/data/test.js"]);
    assert_eq!(
        out.stdout_str(),
        "timer true\n\
         sha256 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\n\
         file hello from the host\n\
         worker 499999500000\n\
         json {\"a\":[1,2,{\"b\":3}]}\n"
    );
    assert_no_surprises(&out);
}

const PYTHON_SIGNALS: &str = r#"
import os, signal, threading, time
got = []
signal.signal(signal.SIGUSR1, lambda sig, frame: got.append(sig))
os.kill(os.getpid(), signal.SIGUSR1)
print("handler", got)
# A signal interrupts the main thread's sleep; Python runs the handler and
# sleeps for the rest of the time (PEP 475).
main = threading.main_thread().ident
threading.Timer(0.05, signal.pthread_kill, (main, signal.SIGUSR1)).start()
t0 = time.monotonic()
time.sleep(0.2)
print("sleep", time.monotonic() - t0 >= 0.2, len(got))
# os.kill from another thread interrupts the main thread's pause().
threading.Timer(0.05, os.kill, (os.getpid(), signal.SIGUSR1)).start()
signal.pause()
print("pause", len(got))
try:
    os.kill(os.getpid(), signal.SIGINT)
    time.sleep(1)
except KeyboardInterrupt:
    print("KeyboardInterrupt")
signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR2})
os.kill(os.getpid(), signal.SIGUSR2)
print("sigwait", int(signal.sigwait({signal.SIGUSR2})))
"#;

#[test]
fn python_signals() {
    let b = sandbox("python").env("PYTHONDONTWRITEBYTECODE", "1").file("/data/test.py", PYTHON_SIGNALS, 0o644).unwrap();
    let out = run(b, &["/usr/bin/python3", "/data/test.py"]);
    assert_eq!(out.stdout_str(), "handler [10]\nsleep True 2\npause 3\nKeyboardInterrupt\nsigwait 12\n");
    assert_no_surprises(&out);
}

const PYTHON_TIMERS: &str = r#"
import signal, time
hits = []
signal.signal(signal.SIGALRM, lambda sig, frame: hits.append(sig))
signal.setitimer(signal.ITIMER_REAL, 0.05)
t0 = time.monotonic()
time.sleep(0.2)
print("one-shot", hits, time.monotonic() - t0 >= 0.2)
signal.setitimer(signal.ITIMER_REAL, 0.01, 0.01)
while len(hits) < 6:
    signal.pause()
signal.setitimer(signal.ITIMER_REAL, 0)
print("periodic", len(hits) >= 6, signal.getitimer(signal.ITIMER_REAL))
print("alarm", signal.alarm(3), signal.alarm(0))
# CPU time counts running, not sleeping.
c0 = time.process_time()
time.sleep(0.1)
slept = time.process_time() - c0
w0 = time.monotonic()
while time.monotonic() - w0 < 0.1:
    pass
print("cpu", slept < 0.05, time.process_time() - c0 > 0.08)
"#;

#[test]
fn python_timers() {
    let b = sandbox("python").env("PYTHONDONTWRITEBYTECODE", "1").file("/data/test.py", PYTHON_TIMERS, 0o644).unwrap();
    let out = run(b, &["/usr/bin/python3", "/data/test.py"]);
    assert_eq!(out.stdout_str(), "one-shot [14] True\nperiodic True (0.0, 0.0)\nalarm 0 3\ncpu True True\n");
    assert_no_surprises(&out);
}

const NODE_SIGNALS: &str = r#"
const timeout = setTimeout(() => { console.log('no signal'); process.exit(1); }, 5000);
process.on('SIGUSR2', (name) => { console.log('got', name); clearTimeout(timeout); });
process.kill(process.pid, 'SIGUSR2');
"#;

#[test]
fn node_signals() {
    let b = sandbox("node").file("/data/test.js", NODE_SIGNALS, 0o644).unwrap();
    let out = run(b, &["/usr/bin/node", "/data/test.js"]);
    assert_eq!(out.stdout_str(), "got SIGUSR2\n");
    assert_no_surprises(&out);
}

const NODE_FILES: &str = r#"
const fs = require('fs'), path = require('path'), os = require('os');
const d = fs.mkdtempSync(path.join(os.tmpdir(), 'n-'));
fs.mkdirSync(path.join(d, 'a/b'), { recursive: true });
fs.writeFileSync(path.join(d, 'a/b/f.txt'), 'node wrote this');
fs.appendFileSync(path.join(d, 'a/b/f.txt'), '!');
fs.renameSync(path.join(d, 'a/b/f.txt'), path.join(d, 'g.txt'));
fs.copyFileSync(path.join(d, 'g.txt'), path.join(d, 'h.txt'));
console.log('read', fs.readFileSync(path.join(d, 'h.txt'), 'utf8'), fs.statSync(path.join(d, 'h.txt')).size);
console.log('list', JSON.stringify(fs.readdirSync(d).sort()));
(async () => {
  await fs.promises.writeFile(path.join(d, 'p.txt'), 'promise');
  console.log('promise', await fs.promises.readFile(path.join(d, 'p.txt'), 'utf8'));
  fs.rmSync(d, { recursive: true });
  console.log('exists', fs.existsSync(d));
})();
"#;

#[test]
fn node_files() {
    let b = sandbox("node").allow(Capability::FsWrite).file("/data/test.js", NODE_FILES, 0o644).unwrap();
    let out = run(b, &["/usr/bin/node", "/data/test.js"]);
    assert_eq!(
        out.stdout_str(),
        "read node wrote this! 16\nlist [\"a\",\"g.txt\",\"h.txt\"]\npromise promise\nexists false\n"
    );
    assert_no_surprises(&out);
}

#[test]
fn node_network_interfaces() {
    let b = sandbox("node");
    let out = run(
        b,
        &[
            "/usr/bin/node",
            "-e",
            "const n = require('os').networkInterfaces(); console.log(Object.keys(n), n.lo.map(a => a.cidr))",
        ],
    );
    assert_eq!(out.stdout_str(), "[ 'lo' ] [ '127.0.0.1/8', '::1/128' ]\n");
    assert_no_surprises(&out);
    // With `net`, the guest's own interface too.
    let code = "const e = require('os').networkInterfaces().eth0; \
                console.log(e.map(a => [a.cidr, a.mac, a.internal].join(' ')))";
    let out = run(sandbox("node").allow(Capability::Net), &["/usr/bin/node", "-e", code]);
    assert_eq!(out.stdout_str(), "[ '10.0.2.15/24 52:54:00:12:34:56 false' ]\n");
    assert_no_surprises(&out);
}

#[test]
fn results_from_python_and_node() {
    // The programs write into the exported /out; the host gets it back.
    let py = "import json, sqlite3; json.dump({'ok': True}, open('/out/report.json', 'w')); \
              db = sqlite3.connect('/out/r.db'); db.execute('create table t(x)'); db.commit()";
    let b = sandbox("python").allow(Capability::FsWrite).env("PYTHONDONTWRITEBYTECODE", "1").export("/out").unwrap();
    let out = run(b, &["/usr/bin/python3", "-c", py]);
    let ex = out.export("/out").unwrap();
    assert_eq!(ex.state, ExportState::Complete);
    let report = ex.entries.iter().find(|e| e.path == "report.json").unwrap();
    assert_eq!(report.content, ExportContent::File(br#"{"ok": true}"#.to_vec()));
    let db = ex.entries.iter().find(|e| e.path == "r.db").unwrap();
    assert!(matches!(&db.content, ExportContent::File(d) if d.starts_with(b"SQLite format 3\0")));

    let js = "const fs = require('fs'); fs.mkdirSync('/out/js'); fs.writeFileSync('/out/js/out.txt', 'from node')";
    let b = sandbox("node").allow(Capability::FsWrite).export("/out").unwrap();
    let out = run(b, &["/usr/bin/node", "-e", js]);
    let paths: Vec<_> = out.exports[0].entries.iter().map(|e| (e.path.as_str(), e.content.clone())).collect();
    assert_eq!(paths, [("js", ExportContent::Dir), ("js/out.txt", ExportContent::File(b"from node".to_vec()))]);
}

/// A runtime that can run programs: busybox's applets in /bin.
fn with_shell(name: &str) -> SandboxBuilder {
    let mut b =
        sandbox(name).allow(Capability::Process).import(runtime("alpine/bin/busybox.static"), "/bin/busybox").unwrap();
    for applet in ["sh", "echo", "tr", "ls", "cat"] {
        b = b.symlink(&format!("/bin/{applet}"), "busybox").unwrap();
    }
    b
}

#[test]
fn subprocesses_from_python_and_node() {
    let py = r#"
import os, subprocess, sys
print(subprocess.run(["echo", "hi"], capture_output=True, text=True).stdout.strip())
r = subprocess.run("echo $((6*7)) | tr 4 X; exit 5", shell=True, capture_output=True, text=True)
print("shell", r.returncode, r.stdout.strip())
p = subprocess.Popen([sys.executable, "-c", "import sys; print(sys.stdin.read().upper())"],
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
print("child", p.communicate("through python")[0].strip(), p.returncode)
pid = os.fork()
if pid == 0:
    os._exit(9)
print("fork", os.waitpid(pid, 0)[1] >> 8)
"#;
    let out = run(with_shell("python").env("PYTHONDONTWRITEBYTECODE", "1"), &["/usr/bin/python3", "-c", py]);
    assert_eq!(out.stdout_str(), "hi\nshell 5 X2\nchild THROUGH PYTHON 0\nfork 9\n");
    assert_no_surprises(&out);

    let js = r#"
const cp = require('child_process');
console.log(cp.execSync('echo hi | tr a-z A-Z').toString().trim());
const r = cp.spawnSync('sh', ['-c', 'echo out; echo err >&2; exit 6']);
console.log('spawnSync', r.status, r.stdout.toString().trim(), r.stderr.toString().trim());
const child = cp.spawn(process.execPath, ['-e', 'process.stdin.pipe(process.stdout)']);
let out = '';
child.stdout.on('data', d => out += d);
child.on('close', code => console.log('spawn', code, out.trim()));
child.stdin.end('through node');
"#;
    let out = run(with_shell("node"), &["/usr/bin/node", "-e", js]);
    assert_eq!(out.stdout_str(), "HI\nspawnSync 6 out err\nspawn 0 through node\n");
    assert_no_surprises(&out);
}

/// An HTTP server on the host's loopback that answers every request with
/// `body`; returns its port.
fn http_server(body: &'static str) -> u16 {
    use std::io::{Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            let mut req = Vec::new();
            let mut buf = [0u8; 1024];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                match c.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => req.extend_from_slice(&buf[..n]),
                }
            }
            let _ = write!(c, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        }
    });
    port
}

#[test]
fn network_from_python_and_node() {
    let port = http_server("hello from the host");
    let host = format!("host.grix.internal:{port}");
    let py = format!(
        r#"
import asyncio, urllib.request
print(urllib.request.urlopen("http://{host}/").read().decode())
async def main():
    async def echo(r, w):
        w.write((await r.read()).upper()); await w.drain(); w.close()
    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    r, w = await asyncio.open_connection("localhost", server.sockets[0].getsockname()[1])
    w.write(b"x" * 100000); w.write_eof()
    got = await r.read()
    print("loopback", len(got), got[:2].decode())
    server.close()
asyncio.run(main())
"#
    );
    let b = sandbox("python").allow(Capability::Net).allow_host(&host).unwrap().env("PYTHONDONTWRITEBYTECODE", "1");
    let out = run(b, &["/usr/bin/python3", "-c", &py]);
    assert_eq!(out.stdout_str(), "hello from the host\nloopback 100000 XX\n");
    assert_no_surprises(&out);

    // A Node server, reached from the host through a forwarded port, that
    // itself fetches from the host.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let forwarded = listener.local_addr().unwrap().port();
    let js = format!(
        r#"
const http = require('http');
const srv = http.createServer((req, res) => {{
  http.get('http://{host}/', up => {{
    let body = '';
    up.on('data', d => body += d);
    up.on('end', () => {{ res.end(`node saw: ${{body}} for ${{req.url}}`); srv.close(); }});
  }});
}});
srv.listen(8000);
"#
    );
    let sb = sandbox("node")
        .allow(Capability::Net)
        .allow_host(&host)
        .unwrap()
        .forward_listener(listener, 8000)
        .unwrap()
        .build()
        .unwrap();
    let guest = std::thread::spawn(move || sb.run(&["/usr/bin/node", "-e", &js]).unwrap());
    let started = std::time::Instant::now();
    let reply = loop {
        assert!(started.elapsed() < Duration::from_secs(60), "node never answered");
        if let Some(r) = get(forwarded, "/page") {
            break r;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(reply.ends_with("node saw: hello from the host for /page"), "{reply}");
    let out = guest.join().unwrap();
    assert_eq!(out.status, ExitStatus::Exited(0), "{}", out.stderr_str());
    assert_no_surprises(&out);
}

/// GET `path` from the host's localhost:`port`; None if nobody answered.
fn get(port: u16, path: &str) -> Option<String> {
    use std::io::{Read, Write};
    let mut c = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
    c.set_read_timeout(Some(Duration::from_secs(20))).ok()?;
    write!(c, "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").ok()?;
    let mut s = String::new();
    c.read_to_string(&mut s).ok()?;
    (!s.is_empty()).then_some(s)
}

#[test]
fn stdin_for_python_and_node() {
    let py = sandbox("python").env("PYTHONDONTWRITEBYTECODE", "1").build().unwrap();
    let out = py
        .run_with_stdin(&["/usr/bin/python3", "-c", "import sys; print(sorted(sys.stdin.read().split()))"], "b a c\n")
        .unwrap();
    assert_eq!(out.stdout_str(), "['a', 'b', 'c']\n");
    let node = sandbox("node").build().unwrap();
    let js = "let s = ''; process.stdin.on('data', d => s += d); process.stdin.on('end', () => console.log(s.trim().toUpperCase()))";
    let out = node.run_with_stdin(&["/usr/bin/node", "-e", js], "from the host\n").unwrap();
    assert_eq!(out.stdout_str(), "FROM THE HOST\n");
}

#[test]
fn node_needs_threads() {
    let b = Sandbox::builder().timeout(Duration::from_secs(120)).memory_mb(1024).import(runtime("node"), "/").unwrap();
    let out = b.build().unwrap().run(&["/usr/bin/node", "-e", "1"]).unwrap();
    assert_ne!(out.status, ExitStatus::Exited(0));
    assert_eq!(out.missing_capabilities(), ["threads"]);
}

/// Python from lazy imports of its /lib and /usr: nothing copied in at
/// start, and with fs_write it installs a module into its own
/// site-packages and writes bytecode caches, which stay in the sandbox.
#[test]
fn python_from_lazy_imports() {
    let root = runtime("python");
    let site = root.join("usr/lib/python3.12/site-packages");
    let before: Vec<_> = std::fs::read_dir(&site).unwrap().map(|e| e.unwrap().file_name()).collect();
    let b = Sandbox::builder()
        .timeout(Duration::from_secs(120))
        .allow(Capability::Threads)
        .allow(Capability::FsWrite)
        .import_lazy(root.join("lib"), "/lib")
        .unwrap()
        .import_lazy(root.join("usr"), "/usr")
        .unwrap();
    let script = "import json, os, sys\n\
                  site = '/usr/lib/python3.12/site-packages'\n\
                  open(site + '/grixmod.py', 'w').write('def six(): return 6\\n')\n\
                  import grixmod, importlib\n\
                  print(grixmod.six() * 7, os.path.exists(site + '/__pycache__'))";
    let out = run(b, &["/usr/bin/python3", "-c", script]);
    assert_eq!(out.stdout_str(), "42 True\n");
    let after: Vec<_> = std::fs::read_dir(&site).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(before, after, "the host's directory changed");
}

#[test]
fn python_from_live_mounts() {
    // Nothing copied in: the interpreter, its loader, shared libraries
    // (mapped, page by page from the host) and modules all come from
    // read-only live mounts, and a script writes to a read-write one.
    let root = runtime("python");
    let work = std::env::temp_dir().join(format!("grix-py-live-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir(&work).unwrap();
    std::fs::write(work.join("in.json"), r#"{"n": 6}"#).unwrap();
    let b = Sandbox::builder()
        .timeout(Duration::from_secs(120))
        .allow(Capability::Threads)
        .mount_read_only(root.join("lib"), "/lib")
        .unwrap()
        .mount_read_only(root.join("usr"), "/usr")
        .unwrap()
        .mount(&work, "/work")
        .unwrap();
    let script = "import json, hashlib, sqlite3\n\
                  n = json.load(open('/work/in.json'))['n']\n\
                  db = sqlite3.connect('/work/db.sqlite')\n\
                  db.execute('create table t (x)'); db.execute('insert into t values (?)', (n * 7,)); db.commit()\n\
                  open('/work/out.txt', 'w').write(hashlib.sha256(str(n).encode()).hexdigest()[:8])\n\
                  print(db.execute('select x from t').fetchone()[0])";
    let out = run(b, &["/usr/bin/python3", "-c", script]);
    assert_eq!(out.stdout_str(), "42\n");
    assert_eq!(std::fs::read_to_string(work.join("out.txt")).unwrap(), "e7f6c011");
    let db = std::fs::read(work.join("db.sqlite")).unwrap();
    assert!(db.starts_with(b"SQLite format 3\0"));
    std::fs::remove_dir_all(&work).unwrap();
}

/// Python started once, its libraries imported, then snapshotted: each run
/// from the snapshot runs new code at once.
#[test]
fn python_from_a_snapshot() {
    let b = sandbox("python").cpus(1);
    if b.vmm_path().is_none() {
        return; // Only grix-vmm can (the guest tests check QEMU says so).
    }
    let dir = std::env::temp_dir().join(format!("grix-pysnap-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("python.snap");
    let started = std::time::Instant::now();
    let snap = b
        .build()
        .unwrap()
        .snapshot(
            &["/usr/bin/python3", "-c", "import json, decimal, email, asyncio, sys; exec(sys.stdin.read())"],
            &path,
        )
        .unwrap();
    let took = started.elapsed();
    for (code, want) in [
        ("print(json.dumps({'sum': sum(range(10))}))", "{\"sum\": 45}\n"),
        ("print(decimal.Decimal(1) / decimal.Decimal(8))", "0.125\n"),
    ] {
        let started = std::time::Instant::now();
        let out = snap.run(code).unwrap();
        assert_eq!(out.status, ExitStatus::Exited(0), "{}{}", out.stderr_str(), out.kernel_log);
        assert_eq!(out.stdout_str(), want);
        assert_no_surprises(&out);
        eprintln!("python: snapshot taken in {took:?}, a run from it took {:?}", started.elapsed());
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// x86_64 Alpine (dynamically linked: busybox, CPython) through qemu-x86_64
/// in user mode, which the kernel runs for every x86_64 program it execs.
#[test]
fn x86_64_python_through_a_translator() {
    // An x86_64 kernel runs it itself.
    if grix::Arch::from_env() == grix::Arch::X86_64 {
        return;
    }
    let qemu = runtime("qemu-x86_64/usr/bin/qemu-x86_64");
    // Emulation in emulation under TCG: minutes.
    let b = Sandbox::builder()
        .timeout(Duration::from_secs(600))
        .memory_mb(1024)
        .allow(Capability::Threads)
        .allow(Capability::Process)
        .import(runtime("x86_64"), "/")
        .unwrap()
        .x86_64(&qemu)
        .unwrap()
        // The x86_64 programs' own libraries are at the root.
        .env("QEMU_LD_PREFIX", "/");
    let code = "import hashlib, json, platform, threading\n\
                out = []\n\
                t = threading.Thread(target=lambda: out.append(hashlib.sha256(b'grix').hexdigest()[:12]))\n\
                t.start(); t.join()\n\
                print(platform.machine(), json.dumps(out))";
    let out =
        run(b, &["/bin/busybox", "sh", "-c", &format!("/usr/bin/python3 -c \"{code}\" | /bin/busybox tr a-z A-Z")]);
    assert_eq!(out.stdout_str(), "X86_64 [\"837CCAB607AA\"]\n", "{}", out.stderr_str());
    assert_no_surprises(&out);
}

/// glibc programs (Debian's bash, coreutils, perl, util-linux), as a
/// Docker image runs them: as the image's user, root, which may become
/// another (as apt does to fetch packages).
#[test]
fn glibc_programs_from_debian() {
    let mut g = grix::build::Grixfile::parse(&format!("from = \"oci:{}\"", runtime("oci/debian").display())).unwrap();
    g.from_outside_context = true;
    let image = g
        .build(
            std::path::Path::new("."),
            grix::build::BuildOptions {
                arch: None,
                kernel: None,
                on_output: &mut |_, _| {},
                policy: Default::default(),
                control: None,
            },
        )
        .unwrap();
    let b = Sandbox::builder()
        .image(&image)
        .unwrap()
        .timeout(Duration::from_secs(120))
        .allow(Capability::Process)
        .allow(Capability::FsWrite);
    let script = r#"
        echo "bash ${BASH_VERSION%%(*}"
        id
        perl -e '$) = "1000 1000"; $( = 1000; $> = $< = 1000; print "now $< $> $(\n"; $< = 0; print "back? $<\n"'
        perl -e '$> = 33; $< = 0; print "saved $< $>\n"'  # euid away and back: the saved id allows it
        cd /tmp && echo one > a && echo two > b && mv -f a b && cat b
        sort -r <<< $'x\ny' | tr '\n' ' '; echo
        perl -e 'printf("perl %vd\n", $^V)'
        getent passwd root | cut -d: -f1,3
    "#;
    let out = run(b, &["/bin/bash", "-c", script]);
    assert_eq!(
        out.stdout_str(),
        "bash 5.2.15\nuid=0(root) gid=0(root) groups=0(root)\nnow 1000 1000 1000 1000\nback? 1000\n\
         saved 0 33\none\ny x \nperl 5.36.0\nroot:0\n",
        "{}",
        out.stderr_str()
    );
    // Not even glibc asking for nscd's socket.
    assert!(out.events.iter().all(|e| matches!(e, GuestEvent::MissingPath { .. })), "{:?}", out.events);
}
