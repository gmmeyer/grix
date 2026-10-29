//! Prometheus metrics for sandbox runs ([`Metrics`]): how runs ended and how
//! long they took, what their programs were denied, what their VMs cost the
//! host, and what their kernels say of their resources ([`GuestStats`]),
//! live while they run.
//!
//! Labels come from fixed sets only. A guest-reported name that isn't one
//! of grix's own (a denied capability) is `other`, so a program can't make
//! the host keep series without end.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use grix_abi::policy::Capability;
use grix_abi::stats::{Limit, Resource};

use crate::sandbox::{ExitStatus, HostUsage, RunOutput, Stream};
use crate::{GuestEvent, GuestStats};

/// Metrics for the runs of every sandbox given them
/// ([`SandboxBuilder::metrics`](crate::SandboxBuilder::metrics),
/// [`Snapshot::metrics`](crate::Snapshot::metrics)); clones share them.
/// [`serve`](Metrics::serve) them for Prometheus, or
/// [`render`](Metrics::render) them yourself.
///
/// While a run goes on, the host asks its kernel for a report every few
/// seconds: the `grix_guest_*` gauges are what the running sandboxes use
/// now (summed over them), and the counters grow as they go. When a run
/// ends, its gauges go and its status, duration, cost and peaks are
/// counted.
#[derive(Clone)]
pub struct Metrics(Arc<Inner>);

impl Default for Metrics {
    fn default() -> Self {
        Metrics::new()
    }
}

impl std::fmt::Debug for Metrics {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Metrics").field("runs_started", &self.0.started.load(Relaxed)).finish()
    }
}

/// How a run ended, as `grix_runs_total`'s `status`.
const STATUSES: [&str; 8] =
    ["ok", "exit_nonzero", "signaled", "timeout", "stopped", "kernel_panic", "vm_failed", "error"];

const DURATION_BUCKETS: &[f64] = &[0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 300.0, 1800.0, 3600.0];
const MEMORY_BUCKETS: &[f64] = &[
    (32u64 << 20) as f64,
    (64u64 << 20) as f64,
    (128u64 << 20) as f64,
    (256u64 << 20) as f64,
    (512u64 << 20) as f64,
    (1u64 << 30) as f64,
    (2u64 << 30) as f64,
    (4u64 << 30) as f64,
    (8u64 << 30) as f64,
    (16u64 << 30) as f64,
];
const RATIO_BUCKETS: &[f64] = &[0.1, 0.25, 0.5, 0.75, 0.9, 0.95, 0.99, 1.0];

/// How long a scraper has to send its request and take the answer.
const ANSWER_TIME: Duration = Duration::from_secs(2);

/// How often a run with metrics asks its kernel for a report.
pub(crate) const REPORT_EVERY: Duration = Duration::from_secs(5);

struct Inner {
    started: AtomicU64,
    active: AtomicI64,
    ended: [AtomicU64; STATUSES.len()],
    duration: Histogram,
    /// (kind, capability) of events.
    events: Mutex<BTreeMap<(&'static str, &'static str), u64>>,
    output: [AtomicU64; 2],
    vmm_cpu_ns: [AtomicU64; 2],
    vmm_memory: Histogram,
    guest_cpu_ns: AtomicU64,
    guest_syscalls: AtomicU64,
    guest_faults: AtomicU64,
    guest_switches: AtomicU64,
    guest_forks: AtomicU64,
    guest_hits: [AtomicU64; Limit::ALL.len()],
    /// What running sandboxes use now, and have, summed over them.
    guest_used: [AtomicI64; Resource::ALL.len()],
    guest_limit: [AtomicI64; Resource::ALL.len()],
    guest_peak_ratio: Vec<Histogram>,
}

impl Metrics {
    pub fn new() -> Metrics {
        Metrics(Arc::new(Inner {
            started: AtomicU64::new(0),
            active: AtomicI64::new(0),
            ended: Default::default(),
            duration: Histogram::new(DURATION_BUCKETS),
            events: Mutex::default(),
            output: Default::default(),
            vmm_cpu_ns: Default::default(),
            vmm_memory: Histogram::new(MEMORY_BUCKETS),
            guest_cpu_ns: AtomicU64::new(0),
            guest_syscalls: AtomicU64::new(0),
            guest_faults: AtomicU64::new(0),
            guest_switches: AtomicU64::new(0),
            guest_forks: AtomicU64::new(0),
            guest_hits: Default::default(),
            guest_used: Default::default(),
            guest_limit: Default::default(),
            guest_peak_ratio: Resource::ALL.iter().map(|_| Histogram::new(RATIO_BUCKETS)).collect(),
        }))
    }

    /// A run starts: its part in the metrics, until it's dropped.
    pub(crate) fn start(&self) -> Recorder {
        self.0.started.fetch_add(1, Relaxed);
        self.0.active.fetch_add(1, Relaxed);
        Recorder { m: self.clone(), last: GuestStats::default(), ended: false }
    }

    /// An event from a run (the guest's, or the host's network policy's).
    pub(crate) fn event(&self, e: &GuestEvent) {
        let key = match e {
            GuestEvent::Denied { capability, .. } => ("denied", capability_label(capability)),
            GuestEvent::Unimplemented { .. } => ("unsupported", ""),
            GuestEvent::MissingPath { .. } => ("missing_path", ""),
            GuestEvent::Fault { .. } => ("fault", ""),
            GuestEvent::ExecFailed { .. } => ("exec_failed", ""),
            GuestEvent::Stopped { .. } => ("stopped", ""),
            GuestEvent::Continued => ("continued", ""),
        };
        *self.0.events.lock().unwrap().entry(key).or_default() += 1;
    }

    /// Serve the metrics at `addr` (`HOST:PORT`; port 0 picks one), as
    /// Prometheus's text format at `/metrics`, on a thread of its own for
    /// as long as this process runs. The address it listens on.
    pub fn serve(&self, addr: &str) -> Result<SocketAddr> {
        let listener = TcpListener::bind(addr).with_context(|| format!("serving metrics at {addr}"))?;
        let local = listener.local_addr()?;
        let m = self.clone();
        std::thread::Builder::new()
            .name("grix-metrics".into())
            .spawn(move || {
                // One at a time, each with a short time limit: a scraper
                // asks every few seconds.
                for conn in listener.incoming().flatten() {
                    let _ = m.answer(conn);
                }
            })
            .context("starting the metrics server")?;
        Ok(local)
    }

    fn answer(&self, mut conn: TcpStream) -> std::io::Result<()> {
        conn.set_write_timeout(Some(ANSWER_TIME))?;
        // The request line is all that matters; the rest of the head is
        // read (up to a bound) so the client sees its request taken. All
        // of it within `ANSWER_TIME`: a client that trickles bytes would
        // otherwise hold the one thread that answers.
        let until = Instant::now() + ANSWER_TIME;
        let mut head = Vec::new();
        let mut buf = [0u8; 1024];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 8192 {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(ErrorKind::TimedOut.into());
            }
            conn.set_read_timeout(Some(left))?;
            let n = conn.read(&mut buf)?;
            if n == 0 {
                break;
            }
            head.extend_from_slice(&buf[..n]);
        }
        let line = head.split(|&b| b == b'\n').next().unwrap_or_default();
        let line = String::from_utf8_lossy(line);
        let mut words = line.split_whitespace();
        let (method, path) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
        let path = path.split('?').next().unwrap_or("");
        let (status, kind, body) = match (method, path) {
            ("GET" | "HEAD", "/metrics") => ("200 OK", "text/plain; version=0.0.4; charset=utf-8", self.render()),
            ("GET" | "HEAD", _) => ("404 Not Found", "text/plain", "grix's metrics are at /metrics\n".into()),
            _ => ("405 Method Not Allowed", "text/plain", "GET /metrics\n".into()),
        };
        write!(
            conn,
            "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )?;
        if method != "HEAD" {
            conn.write_all(body.as_bytes())?;
        }
        conn.flush()
    }

    /// The metrics, in Prometheus's text format.
    pub fn render(&self) -> String {
        let m = &self.0;
        let mut out = Out(String::new());
        out.family("grix_runs_started_total", "counter", "Sandbox runs started.");
        out.sample("grix_runs_started_total", &[], m.started.load(Relaxed) as f64);
        out.family("grix_runs_active", "gauge", "Sandbox runs in progress.");
        out.sample("grix_runs_active", &[], m.active.load(Relaxed) as f64);
        out.family(
            "grix_runs_total",
            "counter",
            "Sandbox runs ended, by how: ok (exit status 0), exit_nonzero, signaled, timeout, stopped, \
             kernel_panic, vm_failed, or error (the VM couldn't be run).",
        );
        for (i, status) in STATUSES.iter().enumerate() {
            out.sample("grix_runs_total", &[("status", status)], m.ended[i].load(Relaxed) as f64);
        }
        out.family("grix_run_duration_seconds", "histogram", "How long sandbox runs took, boot to end.");
        m.duration.render(&mut out, "grix_run_duration_seconds", &[]);
        out.family(
            "grix_events_total",
            "counter",
            "What programs tried and grix refused or lacks (denied, by capability; unsupported; missing_path; \
             fault; exec_failed), and job control (stopped, continued).",
        );
        for ((kind, cap), n) in m.events.lock().unwrap().iter() {
            let labels: &[(&str, &str)] =
                if cap.is_empty() { &[("kind", kind)] } else { &[("kind", kind), ("capability", cap)] };
            out.sample("grix_events_total", labels, *n as f64);
        }
        out.family("grix_output_bytes_total", "counter", "Bytes programs wrote to stdout and stderr.");
        for (i, stream) in ["stdout", "stderr"].iter().enumerate() {
            out.sample("grix_output_bytes_total", &[("stream", stream)], m.output[i].load(Relaxed) as f64);
        }
        out.family(
            "grix_vmm_cpu_seconds_total",
            "counter",
            "CPU time the VMs' processes (grix-vmm or QEMU) used on the host, as the host measured it, \
             counted when each run ends.",
        );
        for (i, mode) in ["user", "system"].iter().enumerate() {
            out.sample("grix_vmm_cpu_seconds_total", &[("mode", mode)], ns_to_secs(m.vmm_cpu_ns[i].load(Relaxed)));
        }
        out.family(
            "grix_vmm_peak_memory_bytes",
            "histogram",
            "Each VM process's peak resident memory on the host: guest RAM it touched, and its own.",
        );
        m.vmm_memory.render(&mut out, "grix_vmm_peak_memory_bytes", &[]);

        // What the guests say.
        out.family("grix_guest_cpu_seconds_total", "counter", "CPU time programs ran, as their kernels report it.");
        out.sample("grix_guest_cpu_seconds_total", &[], ns_to_secs(m.guest_cpu_ns.load(Relaxed)));
        for (name, help, v) in [
            ("grix_guest_syscalls_total", "System calls programs made.", &m.guest_syscalls),
            ("grix_guest_page_faults_total", "Page faults the kernels handled for programs.", &m.guest_faults),
            ("grix_guest_context_switches_total", "Times a guest CPU switched threads.", &m.guest_switches),
            ("grix_guest_processes_started_total", "Processes programs forked.", &m.guest_forks),
        ] {
            out.family(name, "counter", help);
            out.sample(name, &[], v.load(Relaxed) as f64);
        }
        out.family(
            "grix_guest_limit_hits_total",
            "counter",
            "Times a kernel limit refused a program something (ENOMEM, ENOSPC, EAGAIN, ...), by limit.",
        );
        for l in Limit::ALL {
            out.sample(
                "grix_guest_limit_hits_total",
                &[("limit", l.name())],
                m.guest_hits[l as usize].load(Relaxed) as f64,
            );
        }
        out.family(
            "grix_guest_resource_used",
            "gauge",
            "What running sandboxes use now, summed over them, by resource: bytes for memory, kernel_memory, \
             file_data and file_metadata; a count for processes and threads.",
        );
        for r in Resource::ALL {
            out.sample(
                "grix_guest_resource_used",
                &[("resource", r.name())],
                m.guest_used[r as usize].load(Relaxed) as f64,
            );
        }
        out.family(
            "grix_guest_resource_limit",
            "gauge",
            "How much of each resource running sandboxes have, summed over them (units as grix_guest_resource_used).",
        );
        for r in Resource::ALL {
            out.sample(
                "grix_guest_resource_limit",
                &[("resource", r.name())],
                m.guest_limit[r as usize].load(Relaxed) as f64,
            );
        }
        out.family(
            "grix_guest_peak_usage_ratio",
            "histogram",
            "The most of each resource a run had in use at once, as a fraction of its limit, when it ended.",
        );
        for r in Resource::ALL {
            m.guest_peak_ratio[r as usize].render(&mut out, "grix_guest_peak_usage_ratio", &[("resource", r.name())]);
        }
        out.0
    }
}

/// A denied capability as a label: grix's own names, or `other`.
fn capability_label(cap: &str) -> &'static str {
    if let Some(c) = Capability::ALL.iter().find(|c| c.name() == cap) {
        return c.name();
    }
    match cap {
        "privileged" => "privileged",
        crate::event::NET_POLICY => crate::event::NET_POLICY,
        _ => "other",
    }
}

fn ns_to_secs(ns: u64) -> f64 {
    ns as f64 / 1e9
}

/// One run's part in the metrics: the guest's last report (so later ones
/// add only what's new) and what it adds to the gauges, taken back when it's
/// dropped. A run dropped without `finish` failed to run (`error`).
pub(crate) struct Recorder {
    m: Metrics,
    last: GuestStats,
    ended: bool,
}

impl Recorder {
    pub fn output(&self, stream: Stream, bytes: usize) {
        self.m.0.output[(stream == Stream::Stderr) as usize].fetch_add(bytes as u64, Relaxed);
    }

    /// A report from the guest's kernel. Its counters only grow (anything
    /// else is ignored), and its gauges replace this run's last ones.
    pub fn guest(&mut self, s: &GuestStats) {
        let m = &self.m.0;
        let last = &self.last;
        let grew = |now: u64, then: u64| now.saturating_sub(then);
        m.guest_cpu_ns.fetch_add(grew(s.cpu_ns, last.cpu_ns), Relaxed);
        m.guest_syscalls.fetch_add(grew(s.syscalls, last.syscalls), Relaxed);
        m.guest_faults.fetch_add(grew(s.page_faults, last.page_faults), Relaxed);
        m.guest_switches.fetch_add(grew(s.context_switches, last.context_switches), Relaxed);
        m.guest_forks.fetch_add(grew(s.processes_started, last.processes_started), Relaxed);
        for l in Limit::ALL {
            m.guest_hits[l as usize].fetch_add(grew(s.hits(l), last.hits(l)), Relaxed);
        }
        for r in Resource::ALL {
            let (now, then) = (s.usage(r), last.usage(r));
            m.guest_used[r as usize].fetch_add(gauge(now.now) - gauge(then.now), Relaxed);
            m.guest_limit[r as usize].fetch_add(gauge(now.limit) - gauge(then.limit), Relaxed);
        }
        // Counters stay where they got to, if a report says less.
        let mut next = s.clone();
        next.cpu_ns = s.cpu_ns.max(last.cpu_ns);
        next.syscalls = s.syscalls.max(last.syscalls);
        next.page_faults = s.page_faults.max(last.page_faults);
        next.context_switches = s.context_switches.max(last.context_switches);
        next.processes_started = s.processes_started.max(last.processes_started);
        for l in Limit::ALL {
            next.limits_hit[l as usize] = s.hits(l).max(last.hits(l));
        }
        self.last = next;
    }

    /// The run ended: count how, and what it cost.
    pub fn finish(mut self, out: &RunOutput) {
        let m = &self.m.0;
        let status = match &out.status {
            ExitStatus::Exited(0) => "ok",
            ExitStatus::Exited(_) => "exit_nonzero",
            ExitStatus::Signaled(_) => "signaled",
            ExitStatus::Timeout => "timeout",
            ExitStatus::Stopped => "stopped",
            ExitStatus::KernelPanic => "kernel_panic",
            ExitStatus::VmFailed(_) => "vm_failed",
        };
        self.count(status);
        m.duration.observe(out.duration.as_secs_f64());
        if let Some(HostUsage { cpu_user, cpu_system, peak_memory_bytes }) = out.host_usage {
            m.vmm_cpu_ns[0].fetch_add(cpu_user.as_nanos() as u64, Relaxed);
            m.vmm_cpu_ns[1].fetch_add(cpu_system.as_nanos() as u64, Relaxed);
            m.vmm_memory.observe(peak_memory_bytes as f64);
        }
        if let Some(s) = &out.guest_stats {
            for r in Resource::ALL {
                let u = s.usage(r);
                if u.limit > 0 {
                    m.guest_peak_ratio[r as usize].observe((u.peak as f64 / u.limit as f64).min(1.0));
                }
            }
        }
        self.ended = true;
    }

    fn count(&self, status: &str) {
        let i = STATUSES.iter().position(|s| *s == status).expect("a known status");
        self.m.0.ended[i].fetch_add(1, Relaxed);
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        if !self.ended {
            self.count("error");
        }
        let m = &self.m.0;
        m.active.fetch_sub(1, Relaxed);
        for r in Resource::ALL {
            let u = self.last.usage(r);
            m.guest_used[r as usize].fetch_sub(gauge(u.now), Relaxed);
            m.guest_limit[r as usize].fetch_sub(gauge(u.limit), Relaxed);
        }
    }
}

/// A guest's number as a gauge's part: no more than any can be.
fn gauge(v: u64) -> i64 {
    v.min(1 << 52) as i64
}

/// Buckets' counts (cumulative when rendered), their sum and count.
struct Histogram {
    bounds: &'static [f64],
    state: Mutex<(Vec<u64>, f64, u64)>,
}

impl Histogram {
    fn new(bounds: &'static [f64]) -> Histogram {
        Histogram { bounds, state: Mutex::new((vec![0; bounds.len()], 0.0, 0)) }
    }

    fn observe(&self, v: f64) {
        let mut st = self.state.lock().unwrap();
        if let Some(i) = self.bounds.iter().position(|&b| v <= b) {
            st.0[i] += 1;
        }
        st.1 += v;
        st.2 += 1;
    }

    fn render(&self, out: &mut Out, name: &str, labels: &[(&str, &str)]) {
        let st = self.state.lock().unwrap();
        let bucket = format!("{name}_bucket");
        let mut seen = 0;
        for (i, b) in self.bounds.iter().enumerate() {
            seen += st.0[i];
            let le = b.to_string();
            out.sample(&bucket, &[labels, &[("le", &le)]].concat(), seen as f64);
        }
        out.sample(&bucket, &[labels, &[("le", "+Inf")]].concat(), st.2 as f64);
        out.sample(&format!("{name}_sum"), labels, st.1);
        out.sample(&format!("{name}_count"), labels, st.2 as f64);
    }
}

/// Prometheus's text format, as it's written.
struct Out(String);

impl Out {
    fn family(&mut self, name: &str, kind: &str, help: &str) {
        let _ = writeln!(self.0, "# HELP {name} {help}\n# TYPE {name} {kind}");
    }

    /// Label values are grix's own (fixed sets), never escaped.
    fn sample(&mut self, name: &str, labels: &[(&str, &str)], v: f64) {
        self.0.push_str(name);
        if !labels.is_empty() {
            let inner: Vec<String> = labels.iter().map(|(k, v)| format!("{k}=\"{v}\"")).collect();
            let _ = write!(self.0, "{{{}}}", inner.join(","));
        }
        let _ = writeln!(self.0, " {v}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_stay_in_fixed_sets() {
        let m = Metrics::new();
        for cap in ["net", "fs_write", "privileged", "allow_host", "a\"quote", "anything else"] {
            m.event(&GuestEvent::Denied { syscall: "x".into(), capability: cap.into(), detail: String::new() });
        }
        m.event(&GuestEvent::MissingPath { path: "/etc/passwd".into() });
        let text = m.render();
        assert!(text.contains("grix_events_total{kind=\"denied\",capability=\"net\"} 1\n"), "{text}");
        assert!(text.contains("grix_events_total{kind=\"denied\",capability=\"other\"} 2\n"), "{text}");
        assert!(text.contains("grix_events_total{kind=\"missing_path\"} 1\n"), "{text}");
        assert!(!text.contains("quote") && !text.contains("passwd"), "{text}");
    }

    #[test]
    fn a_runs_gauges_go_when_it_ends() {
        let m = Metrics::new();
        let mut run = m.start();
        let mut s = GuestStats { syscalls: 10, ..GuestStats::default() };
        s.usage[Resource::Memory as usize] = grix_abi::stats::Usage { now: 100, peak: 200, limit: 400 };
        s.limits_hit[Limit::Threads as usize] = 1;
        run.guest(&s);
        // Counters add what's new; a report that says less adds nothing.
        s.syscalls = 25;
        run.guest(&s);
        s.syscalls = 3;
        run.guest(&s);
        let text = m.render();
        assert!(text.contains("grix_runs_active 1\n"), "{text}");
        assert!(text.contains("grix_guest_syscalls_total 25\n"), "{text}");
        assert!(text.contains("grix_guest_resource_used{resource=\"memory\"} 100\n"), "{text}");
        assert!(text.contains("grix_guest_limit_hits_total{limit=\"threads\"} 1\n"), "{text}");
        let out = RunOutput {
            status: ExitStatus::Exited(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            events: Vec::new(),
            exports: Vec::new(),
            mount_changes: Vec::new(),
            kernel_log: String::new(),
            duration: Duration::from_millis(300),
            guest_stats: Some(s),
            host_usage: Some(HostUsage {
                cpu_user: Duration::from_millis(1500),
                cpu_system: Duration::ZERO,
                peak_memory_bytes: 100 << 20,
            }),
        };
        run.finish(&out);
        // And one that never got to run.
        drop(m.start());
        let text = m.render();
        assert!(text.contains("grix_runs_active 0\n"), "{text}");
        assert!(text.contains("grix_runs_started_total 2\n"), "{text}");
        assert!(text.contains("grix_runs_total{status=\"ok\"} 1\n"), "{text}");
        assert!(text.contains("grix_runs_total{status=\"error\"} 1\n"), "{text}");
        assert!(text.contains("grix_guest_resource_used{resource=\"memory\"} 0\n"), "{text}");
        assert!(text.contains("grix_run_duration_seconds_bucket{le=\"0.5\"} 1\n"), "{text}");
        assert!(text.contains("grix_run_duration_seconds_bucket{le=\"0.25\"} 0\n"), "{text}");
        assert!(text.contains("grix_guest_peak_usage_ratio_bucket{resource=\"memory\",le=\"0.5\"} 1\n"), "{text}");
        assert!(text.contains("grix_vmm_cpu_seconds_total{mode=\"user\"} 1.5\n"), "{text}");
        assert!(text.contains("grix_vmm_peak_memory_bytes_bucket{le=\"134217728\"} 1\n"), "{text}");
    }

    #[test]
    fn served_over_http() {
        let m = Metrics::new();
        let addr = m.serve("127.0.0.1:0").unwrap();
        let get = |req: &str| {
            let mut c = TcpStream::connect(addr).unwrap();
            c.write_all(req.as_bytes()).unwrap();
            let mut s = String::new();
            c.read_to_string(&mut s).unwrap();
            s
        };
        let ok = get("GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(ok.starts_with("HTTP/1.1 200 OK\r\n") && ok.contains("text/plain; version=0.0.4"), "{ok}");
        assert!(ok.contains("\r\n\r\n# HELP grix_runs_started_total"), "{ok}");
        assert!(get("GET / HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 404"));
        assert!(get("POST /metrics HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 405"));
        let head = get("HEAD /metrics HTTP/1.1\r\n\r\n");
        assert!(head.starts_with("HTTP/1.1 200") && head.ends_with("\r\n\r\n"), "{head}");
    }

    #[test]
    fn a_slow_client_doesnt_hold_the_server() {
        let m = Metrics::new();
        let addr = m.serve("127.0.0.1:0").unwrap();
        // A byte now and then, never a whole request.
        let mut slow = TcpStream::connect(addr).unwrap();
        let trickle = std::thread::spawn(move || {
            for _ in 0..20 {
                if slow.write_all(b"G").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        });
        std::thread::sleep(Duration::from_millis(100));
        let started = Instant::now();
        let mut c = TcpStream::connect(addr).unwrap();
        c.write_all(b"GET /metrics HTTP/1.1\r\n\r\n").unwrap();
        let mut s = String::new();
        c.read_to_string(&mut s).unwrap();
        assert!(s.starts_with("HTTP/1.1 200"), "{s}");
        assert!(started.elapsed() < ANSWER_TIME * 3, "{:?}", started.elapsed());
        trickle.join().unwrap();
    }
}
