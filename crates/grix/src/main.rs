use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use grix::{Capability, DenyAction, GuestEvent, Manifest, Metrics, MountMode, RunControl, RunOutput, Sandbox, Stream};

#[derive(Parser)]
#[command(name = "grix", version, about = "Run Linux programs in a capability-scoped unikernel")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a program in a fresh sandbox.
    Run(Box<RunArgs>),
    /// Start a program and save the whole machine when it first waits for
    /// input; `grix run --snapshot FILE` then starts each run from there.
    /// Takes `run`'s options.
    Snapshot(Box<SnapshotArgs>),
    /// Build a grix image (the files, settings and kernel to run) from a Grixfile.
    Build(Box<BuildArgs>),
    /// Pull a Docker/OCI image (linux/arm64 or linux/amd64) into an OCI image layout directory.
    Pull {
        /// e.g. alpine:3.21, python:3.12-alpine, ghcr.io/owner/repo:tag
        reference: String,
        /// The layout directory to write.
        #[arg(long, value_name = "DIR")]
        oci: PathBuf,
        /// The image's architecture: aarch64 (linux/arm64) or x86_64
        /// (linux/amd64). Default: the host's, or GRIX_ARCH.
        #[arg(long, value_name = "ARCH")]
        arch: Option<String>,
    },
    /// Show a grix image's settings and size.
    Inspect { image: PathBuf },
    /// Save a login for a registry (for pulling private images), in
    /// ~/.config/grix/auth.json. Docker's and Podman's logins work too.
    Login {
        /// The registry: docker.io (the default), ghcr.io, localhost:5000, ...
        #[arg(default_value = "docker.io")]
        registry: String,
        #[arg(short, long)]
        username: String,
        /// Read the password (or token) from stdin, as it must be.
        #[arg(long, required = true)]
        password_stdin: bool,
    },
    /// Forget grix's login for a registry.
    Logout {
        #[arg(default_value = "docker.io")]
        registry: String,
    },
    /// Serve AI agents over MCP (stdio): a `run` tool for sandboxed programs, and `build_image`.
    Mcp(McpArgs),
    /// List the capabilities a sandbox can be granted.
    Caps,
}

#[derive(Parser)]
struct McpArgs {
    /// A host directory agents may import, mount, and read images and
    /// Grixfiles from. Repeatable. Default: the current directory.
    #[arg(long = "root", value_name = "DIR")]
    roots: Vec<PathBuf>,
    /// A capability agents may grant (default: fs_write, threads, process). Repeatable.
    #[arg(short = 'a', long = "allow", value_name = "CAP")]
    allow: Vec<String>,
    /// With `-a net`: the only hosts runs may reach. Repeatable.
    #[arg(long = "allow-host", value_name = "RULE")]
    allow_hosts: Vec<String>,
    /// The longest a run may take, in seconds (default 300).
    #[arg(long, value_name = "SECS")]
    max_timeout: Option<u64>,
    /// The most memory a run may have, in MiB (default 2048).
    #[arg(long, value_name = "MIB")]
    max_mem: Option<u64>,
    /// The most CPUs a run may have (default 4).
    #[arg(long, value_name = "N")]
    max_cpus: Option<u32>,
    /// Let agents change files under the roots: writable mounts (rw,
    /// on_exit) and build_image's output. Without it they only read.
    #[arg(long)]
    writable: bool,
    /// Let build_image pull with your registry logins (`grix login`,
    /// Docker's, Podman's). Without it, agents' pulls are anonymous.
    #[arg(long)]
    registry_credentials: bool,
    /// How many tool calls run at once (default 2); more wait their turn.
    #[arg(long, value_name = "N")]
    max_parallel: Option<usize>,
    /// Serve Prometheus metrics of the runs at http://ADDR/metrics
    /// (HOST:PORT, e.g. 127.0.0.1:9090).
    #[arg(long, value_name = "ADDR")]
    metrics: Option<String>,
}

/// The flags add to the Grixfile, or make the whole image without one:
/// `grix build -o hello.grix --copy ./hello:/bin/hello -- /bin/hello`
/// makes an image of just the grix kernel and one program.
#[derive(Parser)]
struct BuildArgs {
    /// The Grixfile (default: ./Grixfile, if there is one).
    #[arg(short, long)]
    file: Option<PathBuf>,
    /// The Docker/OCI image to start from (alpine:3.21, oci:DIR,
    /// docker-archive:FILE, docker:NAME, dir:DIR). Default: nothing.
    #[arg(long)]
    from: Option<String>,
    /// Put host file or directory HOST at GUEST. Repeatable.
    #[arg(long = "copy", value_name = "HOST:GUEST")]
    copies: Vec<String>,
    /// Set KEY=VALUE in the image's environment. Repeatable.
    #[arg(short, long = "env", value_name = "KEY=VALUE")]
    env: Vec<String>,
    /// The image's working directory.
    #[arg(long)]
    cwd: Option<String>,
    /// A capability the image's program needs. Repeatable.
    #[arg(short = 'a', long = "allow", value_name = "CAP")]
    allow: Vec<String>,
    /// A build step: a shell command (needs /bin/sh in the image). Repeatable.
    #[arg(long = "run", value_name = "COMMAND")]
    runs: Vec<String>,
    /// A build step: a program and its arguments, split at spaces (no
    /// shell needed). Repeatable; steps run in the order given.
    #[arg(long = "exec", value_name = "PROGRAM ARGS")]
    execs: Vec<String>,
    /// Guest memory in MiB for running the image.
    #[arg(long)]
    mem: Option<u64>,
    /// The image's command.
    #[arg(last = true)]
    command: Vec<String>,
    /// The image to write.
    #[arg(short, long, default_value = "image.grix")]
    output: PathBuf,
    /// The architecture to build for: aarch64 or x86_64 (default: the
    /// host's, or GRIX_ARCH). A Docker/OCI image's linux/arm64 or
    /// linux/amd64 variant is pulled, and the kernel is that one's.
    #[arg(long, value_name = "ARCH")]
    arch: Option<String>,
    /// The grix kernel to put in the image (default: grix's, for the
    /// architecture).
    #[arg(long)]
    kernel: Option<PathBuf>,
    /// Don't show build steps' output.
    #[arg(short, long)]
    quiet: bool,
    /// Run every build step, even those whose inputs haven't changed since
    /// they last ran.
    #[arg(long)]
    no_cache: bool,
}

#[derive(Parser)]
struct RunArgs {
    /// Run from a snapshot (`grix snapshot`): the program goes on from where
    /// it waited for input, with this run's stdin. Of the other options,
    /// only --timeout, --json, -v, -q, -t, --no-stdin, --export (to say
    /// where the snapshot's exports go) and --mount (the host directories
    /// for its live mounts; `:ro` makes one read-only) apply.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["image", "manifest", "imports", "command"])]
    snapshot: Option<PathBuf>,
    /// Run a grix image (`grix build`): its files, settings, command and kernel.
    #[arg(long, value_name = "IMAGE")]
    image: Option<PathBuf>,
    /// TOML manifest describing the sandbox.
    #[arg(short, long)]
    manifest: Option<PathBuf>,
    /// Import HOST[:GUEST] (GUEST defaults to /<file name>). Repeatable.
    #[arg(short, long = "import", value_name = "HOST[:GUEST]")]
    imports: Vec<String>,
    /// When the program ends, copy guest directory GUEST to HOST (which must
    /// not exist yet, or be empty). Repeatable.
    #[arg(short = 'x', long = "export", value_name = "GUEST:HOST")]
    exports: Vec<String>,
    /// Mount host directory HOST at GUEST: live and read-write (rw, the
    /// default, grants fs_write), live and read-only (ro), with the
    /// changes applied when the program ends (on-exit, grants fs_write), or
    /// as a lazy import (lazy: read from the host as it's used, never
    /// written there; changes, with fs_write, stay in the sandbox).
    /// Repeatable.
    #[arg(long = "mount", value_name = "HOST:GUEST[:rw|ro|on-exit|lazy]")]
    mounts: Vec<String>,
    /// With `net`, only connect to hosts these rules allow (example.com,
    /// *.example.com, 1.2.3.4, 10.0.0.0/8, each optionally :port).
    /// host.grix.internal is the host's own localhost. Repeatable.
    #[arg(long = "allow-host", value_name = "RULE")]
    allow_hosts: Vec<String>,
    /// Forward [ADDR:]HOSTPORT on the host (127.0.0.1 by default) to
    /// GUESTPORT in the sandbox: TCP, or UDP with /udp after it.
    /// Repeatable.
    #[arg(short = 'p', long = "publish", value_name = "[ADDR:]HOSTPORT:GUESTPORT[/udp]")]
    publish: Vec<String>,
    /// Grant a capability (fs_write, threads, process, net). Repeatable.
    #[arg(short, long = "allow", value_name = "CAP")]
    allow: Vec<String>,
    /// Set an environment variable KEY=VALUE. Repeatable.
    #[arg(short, long = "env", value_name = "KEY=VALUE")]
    env: Vec<String>,
    /// Working directory inside the sandbox.
    #[arg(long)]
    cwd: Option<String>,
    /// Guest memory in MiB.
    #[arg(long)]
    mem: Option<u64>,
    /// CPUs for the program's threads (default 1).
    #[arg(long)]
    cpus: Option<u32>,
    /// The guest's architecture: aarch64 or x86_64 (default: an image's
    /// own, otherwise the host's or GRIX_ARCH). Programs must be built for
    /// it; another than the host's is emulated.
    #[arg(long, value_name = "ARCH")]
    arch: Option<String>,
    /// Run x86_64 programs with this translator (an arm64 Linux program:
    /// qemu-x86_64 in user mode, which needs `-a threads`;
    /// box64 untested).
    #[arg(long = "x86-64", value_name = "TRANSLATOR")]
    x86_64: Option<PathBuf>,
    /// After the time limit, how many seconds the program has to end after
    /// SIGTERM before it's stopped (default 5).
    #[arg(long, value_name = "SECS")]
    grace: Option<u64>,
    /// Time limit in seconds (default 60). 0: none, for a server that runs
    /// until it's stopped.
    #[arg(long, value_name = "SECS")]
    timeout: Option<u64>,
    /// Show at most this many MiB of each of stdout and stderr (default:
    /// all of it), or with --json, keep that much (default 64).
    #[arg(long, value_name = "MIB")]
    max_output: Option<usize>,
    /// Serve Prometheus metrics of the run at http://ADDR/metrics while it
    /// goes on (HOST:PORT, e.g. 0.0.0.0:9090 in a container): how it's
    /// doing, what it was denied, and what its kernel reports of its
    /// memory, processes and limits.
    #[arg(long, value_name = "ADDR")]
    metrics: Option<String>,
    /// Export at most this many MiB in all (default 256).
    #[arg(long, value_name = "MIB")]
    max_export: Option<usize>,
    /// Don't pass our stdin to the program (it's passed when it isn't a terminal).
    #[arg(long)]
    no_stdin: bool,
    /// TTY mode, as `docker run -t`: the program gets a terminal
    /// (/dev/pts/0) the size of this one. It shows what the program writes
    /// and takes what you type, Ctrl-C and Ctrl-Z included: they reach the
    /// program through its terminal. If the program itself stops (Ctrl-Z
    /// with nothing to catch it), grix stops too, until `fg`.
    #[arg(short = 't', long, conflicts_with_all = ["json"])]
    tty: bool,
    /// Kill the program (SIGSYS) instead of returning EPERM when it uses a capability it lacks.
    #[arg(long)]
    kill_on_deny: bool,
    /// Print a JSON result instead of streaming output.
    #[arg(long)]
    json: bool,
    /// Also print the machine it runs in, and the guest kernel log.
    #[arg(short, long)]
    verbose: bool,
    /// Don't report denied/missing operations.
    #[arg(short, long)]
    quiet: bool,
    /// Program (path inside the sandbox) and arguments.
    #[arg(last = true)]
    command: Vec<String>,
}

#[derive(Parser)]
struct SnapshotArgs {
    /// Where to write the snapshot.
    #[arg(short, long, value_name = "FILE")]
    output: PathBuf,
    #[command(flatten)]
    run: RunArgs,
}

fn main() -> ExitCode {
    let matches = Cli::command().get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    let result = match cli.cmd {
        Cmd::Caps => {
            for c in Capability::ALL {
                println!("{:<10} {}", c.name(), c.description());
            }
            Ok(0)
        }
        Cmd::Run(args) => run(*args),
        Cmd::Snapshot(args) => snapshot(*args),
        Cmd::Build(args) => build(*args, matches.subcommand_matches("build")),
        Cmd::Mcp(args) => mcp(args),
        Cmd::Pull { reference, oci, arch } => parse_arch(arch.as_deref())
            .and_then(|arch| {
                let arch = arch.unwrap_or_else(grix::Arch::from_env);
                grix::pull(&reference, &oci, arch).map(|digest| (arch, digest))
            })
            .map(|(arch, digest)| {
                eprintln!("grix: pulled {reference} for {arch} ({digest}) into {}", oci.display());
                0
            }),
        Cmd::Login { registry, username, password_stdin: _ } => login(&registry, &username),
        Cmd::Logout { registry } => grix::auth::logout(&registry).map(|had| {
            if had {
                eprintln!("grix: logged out of {registry}");
                0
            } else {
                eprintln!("grix: there was no login for {registry} (Docker's and Podman's are theirs to remove)");
                1
            }
        }),
        Cmd::Inspect { image } => grix::Image::open(&image).map(|img| {
            let (n, bytes) = img.size();
            let arch = img.arch().ok().map(grix::Arch::name);
            let info = serde_json::json!({ "arch": arch, "config": img.config, "entries": n, "bytes": bytes });
            println!("{}", serde_json::to_string_pretty(&info).unwrap());
            0
        }),
    };
    match result {
        Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
        Err(e) => {
            eprintln!("grix: {e:#}");
            ExitCode::from(125)
        }
    }
}

/// A sandbox from `run`'s options, the command to run in it, and where its
/// exports go.
struct Prepared {
    sandbox: Sandbox,
    command: Vec<String>,
    exports: grix::results::Destinations,
    control: RunControl,
}

fn snapshot(args: SnapshotArgs) -> Result<i32> {
    let metrics = serve_metrics(&args.run)?;
    let p = prepare(&args.run, metrics.as_ref(), false)?;
    let started = std::time::Instant::now();
    let snap = p.sandbox.snapshot(&p.command, &args.output)?;
    if !args.run.quiet {
        let size = std::fs::metadata(snap.path()).map_or(0, |m| m.len());
        eprintln!(
            "grix: saved {} ({} MiB) after {} ms; run it with `grix run --snapshot {}`",
            snap.path().display(),
            size >> 20,
            started.elapsed().as_millis(),
            snap.path().display()
        );
    }
    Ok(0)
}

fn run(args: RunArgs) -> Result<i32> {
    let metrics = serve_metrics(&args)?;
    // Shown as it comes, or (--json) kept for the answer.
    let mut shown = Shown::new(&args);
    if let Some(path) = &args.snapshot {
        let control = RunControl::new();
        let mut snap = grix::Snapshot::open(path)?.control(&control);
        match args.timeout {
            Some(0) => snap = snap.no_timeout(),
            Some(s) => snap = snap.timeout(Duration::from_secs(s)),
            None => {}
        }
        if let Some(m) = &metrics {
            snap = snap.metrics(m);
        }
        // The file's network policy is never used (it may be anyone's):
        // net only as for an image, if granted here.
        if args.allow.iter().any(|c| c == "net") {
            snap = snap.allow_net(&args.allow_hosts)?;
        } else if snap.asks_for_net() && !args.quiet {
            eprintln!("grix: the snapshot asks for net; grant it with `-a net` (and limit it with --allow-host)");
        }
        for spec in &args.publish {
            snap = snap.publish(spec)?;
        }
        if !args.json {
            snap = snap.max_output(0);
        } else if let Some(mb) = args.max_output {
            snap = snap.max_output(mb << 20);
        }
        if let Some(mb) = args.max_export {
            snap = snap.max_export(mb << 20);
        }
        if let Some(s) = args.grace {
            snap = snap.grace(Duration::from_secs(s));
        }
        for spec in &args.mounts {
            let (rest, read_only) = match spec.rsplit_once(':') {
                Some((rest, "ro")) => (rest, true),
                Some((rest, "rw" | "lazy")) => (rest, false),
                _ => (spec.as_str(), false),
            };
            let (host, guest) =
                rest.rsplit_once(':').with_context(|| format!("--mount {spec:?} must be HOST:GUEST[:ro]"))?;
            snap = if read_only { snap.mount_read_only(host, guest)? } else { snap.mount(host, guest)? };
        }
        forward_signals(control.clone(), args.quiet);
        let exports: Vec<(String, PathBuf)> = args
            .exports
            .iter()
            .map(|spec| {
                let (g, h) = spec.split_once(':').with_context(|| format!("--export {spec:?} must be GUEST:HOST"))?;
                Ok((g.to_string(), PathBuf::from(h)))
            })
            .collect::<Result<_>>()?;
        for (guest, _) in &exports {
            if !snap.exports().contains(guest) {
                bail!("the snapshot doesn't export {guest} (it exports {:?})", snap.exports());
            }
        }
        let exports = grix::results::check_destinations(&exports, &[])?;
        // A snapshot taken in TTY mode is a terminal's (`-t` is then ours).
        let tty = snap.tty();
        if args.tty && !tty {
            bail!("the snapshot wasn't taken in TTY mode (grix snapshot -t)");
        }
        let stdin = !args.no_stdin && (tty || !std::io::stdin().is_terminal());
        let live = print_events(&args, &control);
        let raw = terminal(args.tty && stdin, &control, true);
        let input: Box<dyn std::io::Read + Send> =
            if stdin { Box::new(std::io::stdin()) } else { Box::new(std::io::empty()) };
        let out = snap.run_streaming(input, |s, d| shown.write(s, d))?;
        drop(raw);
        return report(&args, out, &exports, live, shown.cut);
    }
    let p = prepare(&args, metrics.as_ref(), !args.json)?;
    forward_signals(p.control.clone(), args.quiet);
    // Piped or redirected input goes to the program; a terminal only in
    // TTY mode (otherwise the program sees end-of-file).
    let stdin = !args.no_stdin && (args.tty || !std::io::stdin().is_terminal());
    let live = print_events(&args, &p.control);
    let raw = terminal(args.tty && stdin, &p.control, false);
    let (sandbox, command) = (&p.sandbox, &p.command);
    let on_output = |s, d: &[u8]| shown.write(s, d);
    let out = if stdin {
        sandbox.run_streaming_with_stdin(command, std::io::stdin(), on_output)?
    } else {
        sandbox.run_streaming(command, on_output)?
    };
    drop(raw);
    report(&args, out, &p.exports, live, shown.cut)
}

/// `--metrics ADDR`: metrics served there for as long as grix runs.
fn serve_metrics(args: &RunArgs) -> Result<Option<Metrics>> {
    let Some(addr) = &args.metrics else { return Ok(None) };
    let metrics = Metrics::new();
    let at = metrics.serve(addr)?;
    if !args.quiet {
        eprintln!("grix: metrics at http://{at}/metrics");
    }
    Ok(Some(metrics))
}

/// Events as they happen, outside TTY mode (whose terminal is the
/// program's) and --json: a server's denials show up while it runs.
/// Missing paths only with -v (they're counted at the end). True if so.
fn print_events(args: &RunArgs, control: &RunControl) -> bool {
    if args.json || args.tty || args.quiet {
        return false;
    }
    let verbose = args.verbose;
    control.on_event(move |e| {
        if verbose || !matches!(e, GuestEvent::MissingPath { .. }) {
            eprintln!("grix: {e}");
        }
    });
    true
}

/// The program's output, shown as it comes (up to `--max-output` of each
/// stream), or with --json, not: it's in the answer.
struct Shown {
    json: bool,
    limit: Option<usize>,
    bytes: [usize; 2],
    /// Whether any of stdout, stderr wasn't shown.
    cut: [bool; 2],
}

impl Shown {
    fn new(args: &RunArgs) -> Shown {
        Shown { json: args.json, limit: args.max_output.map(|mb| mb << 20), bytes: [0; 2], cut: [false; 2] }
    }

    fn write(&mut self, stream: Stream, data: &[u8]) {
        if self.json {
            return;
        }
        let i = usize::from(stream == Stream::Stderr);
        let n = self.limit.map_or(data.len(), |l| l.saturating_sub(self.bytes[i]).min(data.len()));
        self.bytes[i] += n;
        self.cut[i] |= n < data.len();
        if n > 0 {
            write_stream(stream, &data[..n]);
        }
    }
}

/// TTY mode with our terminal: raw, so every key goes to the program's,
/// its size followed (`now`: sent at once too, for a restored snapshot,
/// whose terminal was another's), and a stopped program stops us.
fn terminal(wanted: bool, control: &RunControl, now: bool) -> Option<RawTerminal> {
    if !wanted || !std::io::stdin().is_terminal() {
        return None;
    }
    let raw = RawTerminal::enter()?;
    let saved = raw.0;
    if now {
        RESIZED.store(true, Ordering::SeqCst);
    }
    follow_size(control.clone());
    let c = control.clone();
    control.on_event(move |e| {
        if let GuestEvent::Stopped { .. } = e {
            // As a shell does for a stopped job: our terminal back as
            // it was, and grix stopped until `fg`; then the program
            // goes on.
            let _ = std::io::stdout().flush();
            RawTerminal::set(&saved, false);
            // SAFETY: raising a signal; its default action stops us.
            unsafe { libc::raise(libc::SIGTSTP) };
            RawTerminal::set(&saved, true);
            c.signal(18);
        }
    });
    Some(raw)
}

/// Our terminal in raw mode (TTY mode), put back as it was when dropped.
struct RawTerminal(libc::termios);

impl RawTerminal {
    fn enter() -> Option<RawTerminal> {
        // SAFETY: tcgetattr fills the termios it's given.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(0, &mut saved) } != 0 {
            return None;
        }
        RawTerminal::set(&saved, true);
        Some(RawTerminal(saved))
    }

    /// `saved`, or (`raw`) it made raw.
    fn set(saved: &libc::termios, raw: bool) {
        let mut t = *saved;
        // SAFETY: cfmakeraw and tcsetattr on a termios we own.
        unsafe {
            if raw {
                libc::cfmakeraw(&mut t);
            }
            libc::tcsetattr(0, libc::TCSANOW, &t);
        }
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        RawTerminal::set(&self.0, false);
    }
}

/// Our terminal's size (rows, columns); 24 by 80 if it has none.
fn terminal_size() -> (u16, u16) {
    for fd in [1, 0, 2] {
        // SAFETY: TIOCGWINSZ fills the winsize it's given.
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_row > 0 && ws.ws_col > 0 {
            return (ws.ws_row, ws.ws_col);
        }
    }
    (24, 80)
}

static RESIZED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn resized(_: libc::c_int) {
    RESIZED.store(true, Ordering::SeqCst);
}

/// Our terminal's size changes go to the program's.
fn follow_size(control: RunControl) {
    // SAFETY: the handler only sets an atomic, which is async-signal-safe.
    unsafe { libc::signal(libc::SIGWINCH, resized as extern "C" fn(libc::c_int) as libc::sighandler_t) };
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_millis(50));
            // Until the run has started, a size waits.
            if RESIZED.load(Ordering::SeqCst) {
                let (rows, cols) = terminal_size();
                if control.resize(rows, cols) {
                    RESIZED.store(false, Ordering::SeqCst);
                }
            }
        }
    });
}

/// The program's output as it comes, unbuffered: a prompt or an echoed
/// key has no newline to flush it.
fn write_stream(stream: Stream, data: &[u8]) {
    let _ = match stream {
        Stream::Stdout => {
            let mut out = std::io::stdout().lock();
            out.write_all(data).and_then(|_| out.flush())
        }
        Stream::Stderr => std::io::stderr().write_all(data),
    };
}

/// `--arch`'s architecture, if given.
fn parse_arch(name: Option<&str>) -> Result<Option<grix::Arch>> {
    name.map(|a| grix::Arch::parse(a).with_context(|| format!("--arch {a}: aarch64 (arm64) or x86_64 (amd64)")))
        .transpose()
}

/// The sandbox `args` describe: counted in `metrics`, and with `streamed`,
/// keeping none of the output (it's shown as it comes).
fn prepare(args: &RunArgs, metrics: Option<&Metrics>, streamed: bool) -> Result<Prepared> {
    let manifest = match &args.manifest {
        Some(p) => Manifest::load(p)?,
        None => Manifest::default(),
    };
    let mut b = Sandbox::builder();
    if let Some(arch) = parse_arch(args.arch.as_deref())? {
        b = b.arch(arch);
    }
    if let Some(path) = args.image.as_ref().or(manifest.image.as_ref()) {
        let image = grix::Image::open(path)?;
        // net reaches beyond the sandbox: the image may only ask for it.
        let granted = args.allow.iter().any(|c| c == "net") || manifest.capabilities.iter().any(|c| c == "net");
        if image.config.capabilities.iter().any(|c| c == "net") && !granted && !args.quiet {
            eprintln!("grix: the image asks for net; grant it with `-a net` (and limit it with --allow-host)");
        }
        b = b.image(&image)?;
    }
    let mut b = manifest.apply(b)?;
    for spec in &args.imports {
        let (host, guest) = match spec.rsplit_once(':') {
            Some((h, g)) if g.starts_with('/') => (h.to_string(), g.to_string()),
            _ => {
                let name = PathBuf::from(spec);
                let name = name.file_name().context("import needs a file name")?.to_string_lossy().into_owned();
                (spec.clone(), format!("/{name}"))
            }
        };
        b = b.import(&host, &guest)?;
    }
    let mut exports: Vec<(String, PathBuf)> =
        manifest.exports.iter().map(|e| (e.guest.clone(), e.host.clone())).collect();
    for spec in &args.exports {
        let (guest, host) = spec.split_once(':').with_context(|| format!("--export {spec:?} must be GUEST:HOST"))?;
        b = b.export(guest)?;
        exports.push((guest.to_string(), PathBuf::from(host)));
    }
    let mut mounted: Vec<PathBuf> = manifest.mounts.iter().map(|m| m.host.clone()).collect();
    for spec in &args.mounts {
        let (rest, mode) = match spec.rsplit_once(':') {
            Some((rest, "rw")) => (rest, MountMode::ReadWrite),
            Some((rest, "ro")) => (rest, MountMode::ReadOnly),
            Some((rest, "on-exit")) => (rest, MountMode::OnExit),
            Some((rest, "lazy")) => (rest, MountMode::Lazy),
            _ => (spec.as_str(), MountMode::ReadWrite),
        };
        let (host, guest) = rest
            .rsplit_once(':')
            .with_context(|| format!("--mount {spec:?} must be HOST:GUEST[:rw|ro|on-exit|lazy]"))?;
        b = b.mount_with(host, guest, mode)?;
        mounted.push(PathBuf::from(host));
    }
    // Before the run, so its results have somewhere to go.
    let exports = grix::results::check_destinations(&exports, &mounted)?;
    for rule in &args.allow_hosts {
        b = b.allow_host(rule)?;
    }
    for spec in &args.publish {
        let p = grix::Publish::parse(spec)?;
        b = b.publish(spec)?;
        if !args.quiet {
            let udp = if p.udp { "UDP " } else { "" };
            eprintln!("grix: forwarding {udp}{} to port {} in the sandbox", p.host, p.guest);
        }
    }
    for name in &args.allow {
        b = b.allow(Capability::from_name(name).with_context(|| format!("unknown capability {name:?}"))?);
    }
    for kv in &args.env {
        let (k, v) = kv.split_once('=').with_context(|| format!("--env {kv:?} must be KEY=VALUE"))?;
        b = b.env(k, v);
    }
    if let Some(cwd) = &args.cwd {
        b = b.cwd(cwd);
    }
    if let Some(mb) = args.mem {
        b = b.memory_mb(mb);
    }
    if let Some(n) = args.cpus {
        b = b.cpus(n);
    }
    if args.tty {
        let (rows, cols) = terminal_size();
        b = b.tty(rows, cols);
    }
    if let Some(t) = &args.x86_64 {
        b = b.x86_64(t)?;
    }
    if let Some(s) = args.grace {
        b = b.grace(Duration::from_secs(s));
    }
    match args.timeout {
        Some(0) => b = b.no_timeout(),
        Some(s) => b = b.timeout(Duration::from_secs(s)),
        None => {}
    }
    if args.kill_on_deny {
        b = b.on_deny(DenyAction::Kill);
    }
    if streamed {
        b = b.max_output(0);
    } else if let Some(mb) = args.max_output {
        b = b.max_output(mb << 20);
    }
    if let Some(m) = metrics {
        b = b.metrics(m);
    }
    if let Some(mb) = args.max_export {
        b = b.max_export(mb << 20);
    }

    if args.verbose {
        eprintln!("grix: {}", b.machine());
    }
    let control = RunControl::new();
    let sandbox = b.control(&control).build()?;
    let command = [&args.command, &manifest.command, &sandbox.command().to_vec()]
        .into_iter()
        .find(|c| !c.is_empty())
        .cloned()
        .context("no command given (pass it after `--`, or set `command` in the manifest or image)")?;
    Ok(Prepared { sandbox, command, exports, control })
}

/// What a run did, for the user; the exit code. `live`: its events were
/// shown as they happened; `cut`: stdout, stderr weren't all shown.
fn report(
    args: &RunArgs,
    out: RunOutput,
    exports: &grix::results::Destinations,
    live: bool,
    cut: [bool; 2],
) -> Result<i32> {
    let mut notes = Vec::new();
    let say = |notes: &mut Vec<String>| {
        for n in notes.drain(..) {
            eprintln!("grix: {n}");
        }
    };
    if args.json {
        let mut json = serde_json::to_value(&out)?;
        json["missing_capabilities"] = serde_json::json!(out.missing_capabilities());
        println!("{}", serde_json::to_string_pretty(&json)?);
        let wrote = exports.write(&out, args.quiet, &mut notes);
        let applied = grix::results::report_mounts(&out, true, &mut notes);
        say(&mut notes);
        return Ok(if wrote && applied { out.status.code() } else { 125 });
    }
    let _ = std::io::stdout().flush();
    if args.verbose && !out.kernel_log.is_empty() {
        eprint!("{}", out.kernel_log);
    }
    if !args.quiet {
        // Programs probe many paths that legitimately don't exist; list them only with -v.
        let mut missing = 0;
        for e in &out.events {
            match e {
                grix::GuestEvent::MissingPath { .. } if !args.verbose => missing += 1,
                _ if live => {}
                _ => eprintln!("grix: {e}"),
            }
        }
        if missing > 0 {
            eprintln!("grix: {missing} path(s) were looked up but not imported (-v lists them)");
        }
    }
    for (truncated, name) in [(cut[0], "stdout"), (cut[1], "stderr")] {
        if truncated {
            eprintln!("grix: {name} was cut off at the output limit (--max-output)");
        }
    }
    match &out.status {
        grix::ExitStatus::Timeout => eprintln!("grix: timed out"),
        grix::ExitStatus::Stopped => eprintln!("grix: stopped"),
        grix::ExitStatus::KernelPanic => eprintln!("grix: guest kernel panic:\n{}", out.kernel_log),
        grix::ExitStatus::VmFailed(why) => eprintln!("grix: {why}"),
        _ => {}
    }
    let wrote = exports.write(&out, args.quiet, &mut notes);
    let applied = grix::results::report_mounts(&out, args.quiet, &mut notes);
    say(&mut notes);
    Ok(if wrote && applied { out.status.code() } else { 125 })
}

/// Host signals caught and not forwarded yet, as a bit per signal number.
static CAUGHT: AtomicU64 = AtomicU64::new(0);

extern "C" fn caught(sig: libc::c_int) {
    CAUGHT.fetch_or(1 << sig, Ordering::SeqCst);
}

/// Pass Ctrl-C, SIGTERM, SIGHUP and SIGQUIT on to the program, as a
/// terminal would. The third Ctrl-C stops the sandbox, for a program that
/// doesn't end. What arrives before the run has started waits for it.
fn forward_signals(control: RunControl, quiet: bool) {
    // The host's numbers for these, and Linux's.
    let forwarded = [(libc::SIGINT, 2), (libc::SIGTERM, 15), (libc::SIGHUP, 1), (libc::SIGQUIT, 3)];
    for (sig, _) in forwarded {
        // SAFETY: the handler only sets an atomic, which is async-signal-safe.
        unsafe { libc::signal(sig, caught as extern "C" fn(libc::c_int) as libc::sighandler_t) };
    }
    std::thread::spawn(move || {
        let (mut interrupts, mut pending, mut stop) = (0, Vec::new(), false);
        loop {
            std::thread::sleep(Duration::from_millis(20));
            let bits = CAUGHT.swap(0, Ordering::SeqCst);
            for (sig, linux) in forwarded {
                if bits & (1 << sig) == 0 {
                    continue;
                }
                if sig == libc::SIGINT {
                    interrupts += 1;
                    if interrupts >= 3 {
                        if !stop && !quiet {
                            eprintln!("grix: stopping the sandbox");
                        }
                        stop = true;
                        continue;
                    }
                    if interrupts == 2 && !quiet {
                        eprintln!("grix: press Ctrl-C again to stop the sandbox");
                    }
                }
                if !pending.contains(&linux) {
                    pending.push(linux);
                }
            }
            // Until the run starts, they wait.
            if stop && control.stop() {
                stop = false;
            }
            pending.retain(|&sig| !control.signal(sig));
        }
    });
}

fn build(args: BuildArgs, matches: Option<&clap::ArgMatches>) -> Result<i32> {
    let quiet = args.quiet;
    let mut on_output = |stream: Stream, data: &[u8]| {
        if !quiet {
            let _ = match stream {
                Stream::Stdout => std::io::stderr().write_all(data),
                Stream::Stderr => std::io::stderr().write_all(data),
            };
        }
    };
    use grix::build::{Copy, Grixfile, Step};
    let default = Path::new("Grixfile");
    let file = args.file.clone().or_else(|| default.is_file().then(|| default.to_path_buf()));
    if args.file.is_none() && file.is_some() && !args.quiet {
        eprintln!("grix: building from ./Grixfile");
    }
    // Paths given here are from the current directory, wherever the Grixfile is.
    let cwd = std::env::current_dir()?;
    let here = |p: &str| if Path::new(p).is_absolute() { PathBuf::from(p) } else { cwd.join(p) };
    let (mut g, base) = match &file {
        Some(f) => {
            let text = std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?;
            let g = Grixfile::parse(&text).with_context(|| format!("parsing {}", f.display()))?;
            (g, f.parent().unwrap_or(Path::new(".")).to_path_buf())
        }
        None => (Grixfile::default(), PathBuf::from(".")),
    };
    if let Some(from) = &args.from {
        let from = ["dir:", "oci:", "docker-archive:", "image:"]
            .iter()
            .find_map(|p| from.strip_prefix(p).map(|rest| format!("{p}{}", here(rest).display())))
            .unwrap_or_else(|| from.clone());
        g.from = Some(from);
        g.from_outside_context = true;
    }
    for spec in &args.copies {
        let (host, guest) = spec.rsplit_once(':').with_context(|| format!("--copy {spec:?} must be HOST:GUEST"))?;
        g.copies.push(Copy { host: here(host), guest: guest.to_string(), outside_context: true });
    }
    for kv in &args.env {
        let (k, v) = kv.split_once('=').with_context(|| format!("--env {kv:?} must be KEY=VALUE"))?;
        g.env.insert(k.to_string(), v.to_string());
    }
    if args.cwd.is_some() {
        g.cwd = args.cwd.clone();
    }
    g.capabilities.extend(args.allow.iter().cloned());
    if args.mem.is_some() {
        g.memory_mb = args.mem;
    }
    if !args.command.is_empty() {
        g.command = Some(args.command.clone());
    }
    // --run and --exec steps, in the order they were given.
    let at =
        |id: &str| -> Vec<usize> { matches.and_then(|m| m.indices_of(id)).map(|i| i.collect()).unwrap_or_default() };
    let mut steps: Vec<(usize, Step)> =
        at("runs").into_iter().zip(&args.runs).map(|(i, r)| (i, Step::Shell(r.clone()))).collect();
    steps.extend(
        at("execs")
            .into_iter()
            .zip(&args.execs)
            .map(|(i, e)| (i, Step::Exec(e.split_whitespace().map(String::from).collect()))),
    );
    steps.sort_by_key(|(i, _)| *i);
    g.run.extend(steps.into_iter().map(|(_, s)| s));
    let policy = grix::build::BuildPolicy { cache: !args.no_cache, ..Default::default() };
    let opts = grix::build::BuildOptions {
        arch: parse_arch(args.arch.as_deref())?,
        kernel: args.kernel.clone(),
        on_output: &mut on_output,
        policy,
        control: None,
    };
    let image = g.build(&base, opts)?;
    image.write_to(&args.output)?;
    let (n, bytes) = image.size();
    let arch = image.arch()?;
    eprintln!("grix: built {} for {arch} ({n} entries, {} MiB)", args.output.display(), bytes >> 20);
    Ok(0)
}

fn login(registry: &str, username: &str) -> Result<i32> {
    let mut password = String::new();
    std::io::stdin().read_line(&mut password).context("reading the password from stdin")?;
    let password = password.trim_end_matches(['\n', '\r']);
    if password.is_empty() {
        anyhow::bail!("no password on stdin");
    }
    let path = grix::auth::login(registry, username, password)?;
    eprintln!("grix: saved the login for {registry} in {}", path.display());
    Ok(0)
}

fn mcp(args: McpArgs) -> Result<i32> {
    let roots = if args.roots.is_empty() { vec![std::env::current_dir()?] } else { args.roots.clone() };
    let mut config = grix::mcp::McpConfig::new(&roots)?;
    if !args.allow.is_empty() {
        config.capabilities = args
            .allow
            .iter()
            .map(|n| Capability::from_name(n).with_context(|| format!("unknown capability {n:?}")))
            .collect::<Result<_>>()?;
    }
    config.allow_hosts = args.allow_hosts.clone();
    config.registry_credentials = args.registry_credentials;
    if let Some(n) = args.max_parallel {
        config.max_parallel = n.max(1);
    }
    if let Some(s) = args.max_timeout {
        config.max_timeout = Duration::from_secs(s);
    }
    if let Some(mb) = args.max_mem {
        config.max_memory_mb = mb;
    }
    if let Some(n) = args.max_cpus {
        config.max_cpus = n;
    }
    config.writable = args.writable;
    if let Some(addr) = &args.metrics {
        let metrics = Metrics::new();
        eprintln!("grix: metrics at http://{}/metrics", metrics.serve(addr)?);
        config.metrics = Some(metrics);
    }
    grix::mcp::serve(&config, std::io::stdin().lock(), std::io::stdout())?;
    Ok(0)
}
