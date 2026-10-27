//! End-to-end tests with real language runtimes: Alpine's python3 and nodejs,
//! unmodified. Needs `make fixtures` (or `make test`).

use std::path::PathBuf;
use std::time::Duration;

use grix::{Capability, ExitStatus, GuestEvent, RunOutput, Sandbox, SandboxBuilder};

fn runtime(name: &str) -> PathBuf {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/build").join(name);
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
"#;

#[test]
fn python_timers() {
    let b = sandbox("python").env("PYTHONDONTWRITEBYTECODE", "1").file("/data/test.py", PYTHON_TIMERS, 0o644).unwrap();
    let out = run(b, &["/usr/bin/python3", "/data/test.py"]);
    assert_eq!(out.stdout_str(), "one-shot [14] True\nperiodic True (0.0, 0.0)\nalarm 0 3\n");
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
fn node_needs_threads() {
    let b = Sandbox::builder().timeout(Duration::from_secs(120)).memory_mb(1024).import(runtime("node"), "/").unwrap();
    let out = b.build().unwrap().run(&["/usr/bin/node", "-e", "1"]).unwrap();
    assert_ne!(out.status, ExitStatus::Exited(0));
    assert_eq!(out.missing_capabilities(), ["threads"]);
}
