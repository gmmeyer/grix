//! grix from Python without the `grix` command: `grix._native`, which the
//! `grix` package uses when it's built (`make python`). Runs release the
//! GIL, so Python threads can run sandboxes side by side; output can come
//! back as it's written (`on_output`); a `Control` signals, stops or
//! cancels a run from another thread; and Ctrl-C stops the run.
//!
//! The sandbox is described by a dict of the `grix.Sandbox` fields (all of
//! them present, None where unset). Results come back as the JSON `grix
//! run --json` prints, plus `exit_code`.

use std::io::Cursor;
use std::path::PathBuf;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, bail};
use grix::{Capability, MountMode, RunControl, RunOutput, Sandbox, SandboxBuilder, Stream};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

pyo3::create_exception!(_native, Error, pyo3::exceptions::PyException, "grix couldn't run the sandbox.");

fn err(e: anyhow::Error) -> PyErr {
    Error::new_err(format!("{e:#}"))
}

/// A sandbox, as `grix.Sandbox` describes it.
#[derive(FromPyObject)]
#[pyo3(from_item_all)]
struct Config {
    image: Option<PathBuf>,
    imports: Vec<(PathBuf, String)>,
    files: Vec<(String, Vec<u8>, u32)>,
    env: Vec<(String, String)>,
    cwd: Option<String>,
    hostname: Option<String>,
    default_env: bool,
    host_timezone: bool,
    capabilities: Vec<String>,
    memory_mb: Option<u64>,
    cpus: Option<u32>,
    x86_64: Option<PathBuf>,
    timeout: Option<f64>,
    grace: Option<f64>,
    allow_hosts: Vec<String>,
    publish: Vec<String>,
    mounts: Vec<(PathBuf, String, String)>,
    exports: Vec<(String, PathBuf)>,
    max_output_mb: Option<usize>,
    /// Where grix is installed (its kernel and grix-vmm): never beside the
    /// Python interpreter, which is what "the running program" is here.
    install_dir: PathBuf,
}

fn seconds(what: &str, s: f64) -> anyhow::Result<Duration> {
    Duration::try_from_secs_f64(s).with_context(|| format!("{what} must be a number of seconds"))
}

impl Config {
    fn builder(&self) -> anyhow::Result<SandboxBuilder> {
        let mut b = Sandbox::builder().install_dir(&self.install_dir);
        if let Some(image) = &self.image {
            b = b.image(&grix::Image::open(image)?)?;
        }
        for (host, guest) in &self.imports {
            b = b.import(host, guest)?;
        }
        for (guest, data, mode) in &self.files {
            b = b.file(guest, data.clone(), *mode)?;
        }
        for (k, v) in &self.env {
            b = b.env(k, v);
        }
        if let Some(cwd) = &self.cwd {
            b = b.cwd(cwd);
        }
        if let Some(name) = &self.hostname {
            b = b.hostname(name)?;
        }
        if self.default_env {
            b = b.default_env();
        }
        if self.host_timezone {
            b = b.host_timezone();
        }
        for name in &self.capabilities {
            b = b.allow(Capability::from_name(name).with_context(|| format!("unknown capability {name:?}"))?);
        }
        if let Some(mb) = self.memory_mb {
            b = b.memory_mb(mb);
        }
        if let Some(n) = self.cpus {
            b = b.cpus(n);
        }
        if let Some(t) = &self.x86_64 {
            b = b.x86_64(t)?;
        }
        if let Some(s) = self.grace {
            b = b.grace(seconds("grace", s)?);
        }
        if let Some(s) = self.timeout {
            b = b.timeout(seconds("timeout", s)?);
        }
        for rule in &self.allow_hosts {
            b = b.allow_host(rule)?;
        }
        // [ADDR:]HOSTPORT:GUESTPORT[/udp], as `grix run -p` takes it.
        for spec in &self.publish {
            b = b.publish(spec)?;
        }
        for (host, guest, mode) in &self.mounts {
            let mode = match mode.as_str() {
                "rw" => MountMode::ReadWrite,
                "ro" => MountMode::ReadOnly,
                "on-exit" | "on_exit" => MountMode::OnExit,
                "lazy" => MountMode::Lazy,
                other => bail!("mount mode {other:?} isn't rw, ro, on-exit or lazy"),
            };
            b = b.mount_with(host, guest, mode)?;
        }
        for (guest, _) in &self.exports {
            b = b.export(guest)?;
        }
        if let Some(mb) = self.max_output_mb {
            b = b.max_output(mb << 20);
        }
        Ok(b)
    }
}

/// Signals, stops or cancels runs it's given to, from any thread.
#[pyclass(frozen)]
struct Control {
    inner: RunControl,
}

#[pymethods]
impl Control {
    #[new]
    fn new() -> Self {
        Control { inner: RunControl::new() }
    }

    /// Send a signal (2 SIGINT, 15 SIGTERM, 9 SIGKILL, ...) to the
    /// program's process group. False if nothing is running.
    fn signal(&self, sig: i32) -> bool {
        self.inner.signal(sig)
    }

    /// End the run in progress now. False if nothing is running.
    fn stop(&self) -> bool {
        self.inner.stop()
    }

    /// Stop the run in progress and any started later with this control.
    fn cancel(&self) {
        self.inner.cancel()
    }
}

/// What `on_output` gets, from the thread that reads the VM.
type Forward<'a> = &'a mut dyn FnMut(Stream, &[u8]);

/// Do `work` on a thread of its own with the GIL released, calling
/// `on_output(stream, bytes)` with output as it comes. Ctrl-C (or any
/// pending signal's exception), and an exception in `on_output`, stop the
/// run and become the result.
fn wait<T: Send + 'static>(
    py: Python<'_>,
    control: &RunControl,
    on_output: Option<Py<PyAny>>,
    work: impl FnOnce(Forward) -> anyhow::Result<T> + Send + 'static,
) -> PyResult<T> {
    let (tx, rx) = mpsc::channel();
    let failed: Arc<Mutex<Option<PyErr>>> = Arc::default();
    let (c, f) = (control.clone(), failed.clone());
    std::thread::spawn(move || {
        let mut forward = |s: Stream, d: &[u8]| {
            let Some(cb) = &on_output else { return };
            if f.lock().unwrap().is_some() {
                return;
            }
            Python::attach(|py| {
                let name = if s == Stream::Stdout { "stdout" } else { "stderr" };
                if let Err(e) = cb.call1(py, (name, PyBytes::new(py, d))) {
                    *f.lock().unwrap() = Some(e);
                    c.stop();
                }
            });
        };
        let _ = tx.send(work(&mut forward));
    });
    // Waited on with the GIL released (by this thread only).
    let rx = Mutex::new(rx);
    loop {
        match py.detach(|| rx.lock().unwrap().recv_timeout(Duration::from_millis(100))) {
            Ok(result) => {
                if let Some(e) = failed.lock().unwrap().take() {
                    return Err(e);
                }
                return result.map_err(err);
            }
            Err(RecvTimeoutError::Timeout) => {
                if let Err(e) = py.check_signals() {
                    // Stopped as soon as it has started (it may not have
                    // yet), however long that takes.
                    loop {
                        control.stop();
                        match py.detach(|| rx.lock().unwrap().recv_timeout(Duration::from_millis(100))) {
                            Err(RecvTimeoutError::Timeout) => {}
                            _ => return Err(e),
                        }
                    }
                }
            }
            Err(RecvTimeoutError::Disconnected) => return Err(Error::new_err("the run ended without a result")),
        }
    }
}

/// `grix run --json`'s answer, and the exit code `grix run` would have:
/// 125 if exports or mount changes didn't reach the host, with what
/// happened in `messages`.
fn result(out: &RunOutput, exports: &grix::results::Destinations) -> PyResult<String> {
    let mut notes = Vec::new();
    let wrote = exports.write(out, true, &mut notes);
    let applied = grix::results::report_mounts(out, true, &mut notes);
    let mut v = serde_json::to_value(out).map_err(|e| err(e.into()))?;
    v["missing_capabilities"] = serde_json::json!(out.missing_capabilities());
    v["exit_code"] = serde_json::json!(if wrote && applied { out.status.code() } else { 125 });
    v["messages"] = serde_json::json!(notes.iter().map(|n| format!("grix: {n}\n")).collect::<String>());
    Ok(v.to_string())
}

/// Run `command` (or the image's) in a fresh sandbox and wait for it.
#[pyfunction]
#[pyo3(signature = (config, command=None, stdin=None, on_output=None, control=None))]
fn run(
    py: Python<'_>,
    config: Config,
    command: Option<Vec<String>>,
    stdin: Option<Vec<u8>>,
    on_output: Option<Py<PyAny>>,
    control: Option<PyRef<'_, Control>>,
) -> PyResult<String> {
    let control = control.map(|c| c.inner.clone()).unwrap_or_default();
    let sandbox = config.builder().and_then(|b| b.control(&control).build()).map_err(err)?;
    // As `grix run` checks them: mounts are applied first.
    let mounted: Vec<PathBuf> = config.mounts.iter().map(|(host, _, _)| host.clone()).collect();
    let exports = grix::results::check_destinations(&config.exports, &mounted).map_err(err)?;
    let command = command.filter(|c| !c.is_empty()).unwrap_or_else(|| sandbox.command().to_vec());
    if command.is_empty() {
        return Err(Error::new_err("no command given (and the image has none)"));
    }
    let out = wait(py, &control, on_output, move |forward| match stdin {
        Some(data) => sandbox.run_streaming_with_stdin(&command, Cursor::new(data), forward),
        None => sandbox.run_streaming(&command, forward),
    })?;
    result(&out, &exports)
}

/// Start `command` (or the image's) and save the machine to `path` when it
/// first waits for input.
#[pyfunction]
#[pyo3(signature = (config, path, command=None))]
fn snapshot(py: Python<'_>, config: Config, path: PathBuf, command: Option<Vec<String>>) -> PyResult<()> {
    let control = RunControl::new();
    let sandbox = config.builder().and_then(|b| b.control(&control).build()).map_err(err)?;
    let command = command.filter(|c| !c.is_empty()).unwrap_or_else(|| sandbox.command().to_vec());
    if command.is_empty() {
        return Err(Error::new_err("no command given (and the image has none)"));
    }
    wait(py, &control, None, move |_| sandbox.snapshot(&command, &path).map(|_| ()))
}

/// Run from a snapshot, with this stdin.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
#[pyo3(signature = (path, install_dir, stdin=None, timeout=None, on_output=None, control=None, mounts=Vec::new(), allow_net=false, allow_hosts=Vec::new()))]
fn snapshot_run(
    py: Python<'_>,
    path: PathBuf,
    install_dir: PathBuf,
    stdin: Option<Vec<u8>>,
    timeout: Option<f64>,
    on_output: Option<Py<PyAny>>,
    control: Option<PyRef<'_, Control>>,
    mounts: Vec<(PathBuf, String, String)>,
    allow_net: bool,
    allow_hosts: Vec<String>,
) -> PyResult<String> {
    let control = control.map(|c| c.inner.clone()).unwrap_or_default();
    let mut snap = grix::Snapshot::open(path).map_err(err)?.install_dir(install_dir).control(&control);
    // The file's network policy is never used: only what's allowed here.
    if allow_net {
        snap = snap.allow_net(&allow_hosts).map_err(err)?;
    }
    // Its live mounts' host directories (mode "ro" makes one read-only).
    for (host, guest, mode) in mounts {
        snap = if mode == "ro" { snap.mount_read_only(host, &guest) } else { snap.mount(host, &guest) }.map_err(err)?;
    }
    if let Some(s) = timeout {
        snap = snap.timeout(seconds("timeout", s).map_err(err)?);
    }
    let input = stdin.unwrap_or_default();
    let out = wait(py, &control, on_output, move |forward| snap.run_streaming(Cursor::new(input), forward))?;
    // What a snapshot exports comes back in the result.
    result(&out, &grix::results::check_destinations(&[], &[]).map_err(err)?)
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(run, m)?)?;
    m.add_function(wrap_pyfunction!(snapshot, m)?)?;
    m.add_function(wrap_pyfunction!(snapshot_run, m)?)?;
    m.add_class::<Control>()?;
    m.add("Error", m.py().get_type::<Error>())?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
