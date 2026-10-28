use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use grix::{
    Capability, DenyAction, Export, ExportState, GuestEvent, Manifest, MountMode, MountState, RunControl, RunOutput,
    Sandbox, Stream,
};

#[derive(Parser)]
#[command(name = "grix", about = "Run Linux programs in a capability-scoped unikernel")]
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
    /// Pull a Docker/OCI image (linux/arm64) into an OCI image layout directory.
    Pull {
        /// e.g. alpine:3.21, python:3.12-alpine, ghcr.io/owner/repo:tag
        reference: String,
        /// The layout directory to write.
        #[arg(long, value_name = "DIR")]
        oci: PathBuf,
    },
    /// Show a grix image's settings and size.
    Inspect { image: PathBuf },
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
    /// The grix kernel to put in the image (default: the one grix runs).
    #[arg(long)]
    kernel: Option<PathBuf>,
    /// Don't show build steps' output.
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Parser)]
struct RunArgs {
    /// Run from a snapshot (`grix snapshot`): the program goes on from where
    /// it waited for input, with this run's stdin. Of the other options,
    /// only --timeout, --json, -v, -q, --no-stdin and --export apply (to say
    /// where the snapshot's exports go).
    #[arg(long, value_name = "FILE", conflicts_with_all = ["image", "manifest", "imports", "mounts", "command"])]
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
    /// GUESTPORT in the sandbox. Repeatable.
    #[arg(short = 'p', long = "publish", value_name = "[ADDR:]HOSTPORT:GUESTPORT")]
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
    /// Run x86_64 programs with this translator (an arm64 Linux program:
    /// qemu-x86_64 in user mode, which needs `-a threads`;
    /// box64 untested).
    #[arg(long = "x86-64", value_name = "TRANSLATOR")]
    x86_64: Option<PathBuf>,
    /// After the time limit, how many seconds the program has to end after
    /// SIGTERM before it's stopped (default 5).
    #[arg(long, value_name = "SECS")]
    grace: Option<u64>,
    /// Time limit in seconds.
    #[arg(long)]
    timeout: Option<u64>,
    /// Keep at most this many MiB of each of stdout and stderr.
    #[arg(long, value_name = "MIB")]
    max_output: Option<usize>,
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
    #[arg(short = 't', long, conflicts_with_all = ["snapshot", "json"])]
    tty: bool,
    /// Kill the program (SIGSYS) instead of returning EPERM when it uses a capability it lacks.
    #[arg(long)]
    kill_on_deny: bool,
    /// Print a JSON result instead of streaming output.
    #[arg(long)]
    json: bool,
    /// Also print the guest kernel log.
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
        Cmd::Pull { reference, oci } => grix::pull(&reference, &oci).map(|digest| {
            eprintln!("grix: pulled {reference} ({digest}) into {}", oci.display());
            0
        }),
        Cmd::Inspect { image } => grix::Image::open(&image).map(|img| {
            let (n, bytes) = img.size();
            let info = serde_json::json!({ "config": img.config, "entries": n, "bytes": bytes });
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
    exports: Vec<(String, PathBuf)>,
    control: RunControl,
}

fn snapshot(args: SnapshotArgs) -> Result<i32> {
    let p = prepare(&args.run)?;
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
    if let Some(path) = &args.snapshot {
        let control = RunControl::new();
        let mut snap = grix::Snapshot::open(path)?.control(&control);
        if let Some(s) = args.timeout {
            snap = snap.timeout(Duration::from_secs(s));
        }
        forward_signals(control, args.quiet);
        let exports: Vec<(String, PathBuf)> = args
            .exports
            .iter()
            .map(|spec| {
                let (g, h) = spec.split_once(':').with_context(|| format!("--export {spec:?} must be GUEST:HOST"))?;
                Ok((g.to_string(), PathBuf::from(h)))
            })
            .collect::<Result<_>>()?;
        for (guest, host) in &exports {
            if !snap.exports().contains(guest) {
                bail!("the snapshot doesn't export {guest} (it exports {:?})", snap.exports());
            }
            Export::check_destination(host).context("export destination")?;
        }
        let stdin = !args.no_stdin && !std::io::stdin().is_terminal();
        let input: Box<dyn std::io::Read + Send> =
            if stdin { Box::new(std::io::stdin()) } else { Box::new(std::io::empty()) };
        let out =
            if args.json { snap.run_streaming(input, |_, _| {})? } else { snap.run_streaming(input, write_stream)? };
        return report(&args, out, &exports);
    }
    let p = prepare(&args)?;
    forward_signals(p.control.clone(), args.quiet);
    // Piped or redirected input goes to the program; a terminal only in
    // TTY mode (otherwise the program sees end-of-file).
    let stdin = !args.no_stdin && (args.tty || !std::io::stdin().is_terminal());
    // TTY mode with our terminal: raw, so every key goes to the program's.
    let raw = if args.tty && stdin && std::io::stdin().is_terminal() { RawTerminal::enter() } else { None };
    if let Some(saved) = raw.as_ref().map(|r| r.0) {
        follow_size(p.control.clone());
        let c = p.control.clone();
        p.control.on_event(move |e| {
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
    }
    let (sandbox, command) = (&p.sandbox, &p.command);
    let run = |on_output: &mut dyn FnMut(Stream, &[u8])| {
        if stdin {
            sandbox.run_streaming_with_stdin(command, std::io::stdin(), on_output)
        } else {
            sandbox.run_streaming(command, on_output)
        }
    };
    let out = if args.json { run(&mut |_, _| {})? } else { run(&mut write_stream)? };
    drop(raw);
    report(&args, out, &p.exports)
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
            if RESIZED.swap(false, Ordering::SeqCst) {
                let (rows, cols) = terminal_size();
                control.resize(rows, cols);
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

fn prepare(args: &RunArgs) -> Result<Prepared> {
    let manifest = match &args.manifest {
        Some(p) => Manifest::load(p)?,
        None => Manifest::default(),
    };
    let mut b = Sandbox::builder();
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
    // Before the run, so its results have somewhere to go.
    for (i, (_, host)) in exports.iter().enumerate() {
        Export::check_destination(host).context("export destination")?;
        if exports[..i].iter().any(|(_, h)| h == host) {
            bail!("{} is the destination of two exports", host.display());
        }
    }
    let mut mounted: Vec<PathBuf> = manifest.mounts.iter().filter_map(|m| m.host.canonicalize().ok()).collect();
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
        mounted.extend(Path::new(host).canonicalize().ok());
    }
    // Mounts are applied first: one's changes mustn't decide where an
    // export goes.
    for (_, dest) in &exports {
        let parent = dest.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        if let Ok(parent) = parent.canonicalize()
            && let Some(m) = mounted.iter().find(|m| parent.starts_with(m))
        {
            bail!("export destination {} is inside mounted {}", dest.display(), m.display());
        }
    }
    for rule in &args.allow_hosts {
        b = b.allow_host(rule)?;
    }
    for spec in &args.publish {
        let (host, guest) =
            spec.rsplit_once(':').with_context(|| format!("--publish {spec:?} must be HOSTPORT:GUESTPORT"))?;
        let guest: u16 = guest.parse().with_context(|| format!("--publish {spec:?}: bad guest port"))?;
        let host = if host.contains(':') { host.to_string() } else { format!("127.0.0.1:{host}") };
        b = b.forward(&host, guest)?;
        if !args.quiet {
            eprintln!("grix: forwarding {host} to port {guest} in the sandbox");
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
    if let Some(s) = args.timeout {
        b = b.timeout(Duration::from_secs(s));
    }
    if args.kill_on_deny {
        b = b.on_deny(DenyAction::Kill);
    }
    if let Some(mb) = args.max_output {
        b = b.max_output(mb << 20);
    }
    if let Some(mb) = args.max_export {
        b = b.max_export(mb << 20);
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

/// What a run did, for the user; the exit code.
fn report(args: &RunArgs, out: RunOutput, exports: &[(String, PathBuf)]) -> Result<i32> {
    if args.json {
        let mut json = serde_json::to_value(&out)?;
        json["missing_capabilities"] = serde_json::json!(out.missing_capabilities());
        println!("{}", serde_json::to_string_pretty(&json)?);
        let wrote = write_exports(&out, exports, args.quiet);
        let applied = report_mounts(&out, true);
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
                _ => eprintln!("grix: {e}"),
            }
        }
        if missing > 0 {
            eprintln!("grix: {missing} path(s) were looked up but not imported (-v lists them)");
        }
    }
    for (truncated, name) in [(out.stdout_truncated, "stdout"), (out.stderr_truncated, "stderr")] {
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
    let wrote = write_exports(&out, exports, args.quiet);
    let applied = report_mounts(&out, args.quiet);
    Ok(if wrote && applied { out.status.code() } else { 125 })
}

/// Say what happened to each mount. False if a program that ended
/// normally didn't get its changes applied.
fn report_mounts(out: &RunOutput, quiet: bool) -> bool {
    let ended = matches!(out.status, grix::ExitStatus::Exited(_) | grix::ExitStatus::Signaled(_));
    let mut ok = true;
    for m in &out.mount_changes {
        let host = m.host.display();
        let (w, r) = (m.written.len(), m.removed.len());
        match &m.state {
            MountState::Applied if quiet || w + r == 0 => {}
            MountState::Applied => eprintln!("grix: applied the changes to {host}: {w} written, {r} removed"),
            MountState::NotApplied if ended => {
                eprintln!(
                    "grix: the changes to {host} weren't applied: they didn't all arrive \
                     (over --max-export, or paths nested deeper than 4096 bytes)"
                );
                ok = false;
            }
            MountState::NotApplied => eprintln!("grix: the changes to {host} weren't applied"),
            MountState::Failed(why) => {
                eprintln!("grix: applying the changes to {host} failed after {w} written, {r} removed: {why}");
                ok = false;
            }
        }
        if !m.conflicts.is_empty() {
            let n = m.conflicts.len();
            let shown: Vec<&str> = m.conflicts.iter().take(10).map(String::as_str).collect();
            let more = if n > 10 { format!(" and {} more", n - 10) } else { String::new() };
            eprintln!(
                "grix: {n} path(s) in {host} changed on the host during the run too and were left as they are: {}{more}",
                shown.join(", ")
            );
        }
    }
    ok
}

/// Write each exported directory to its host path, saying what happened.
/// Partial exports are written too, with a warning. False if any couldn't
/// be written.
fn write_exports(out: &RunOutput, exports: &[(String, PathBuf)], quiet: bool) -> bool {
    let mut ok = true;
    for (guest, host) in exports {
        let Some(export) = out.export(guest) else { continue };
        let note = match export.state {
            ExportState::Complete => "",
            ExportState::Missing => {
                eprintln!("grix: {guest} didn't exist when the program ended; nothing exported");
                continue;
            }
            ExportState::Truncated => " (cut off at the export limit)",
            ExportState::Incomplete => " (incomplete: the run ended before all of it arrived)",
        };
        if export.entries.is_empty() && !note.is_empty() {
            eprintln!("grix: nothing of {guest} was exported{note}");
            continue;
        }
        match export.write_to(host) {
            Ok(()) if quiet && note.is_empty() => {}
            Ok(()) => {
                let n = export.entries.len();
                let s = if n == 1 { "entry" } else { "entries" };
                eprintln!("grix: exported {guest} to {} ({n} {s}){note}", host.display())
            }
            Err(e) => {
                eprintln!("grix: exporting {guest} to {}: {e:#}", host.display());
                ok = false;
            }
        }
    }
    ok
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
        let from = ["dir:", "oci:", "docker-archive:"]
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
    let opts = grix::build::BuildOptions {
        kernel: args.kernel.clone(),
        on_output: &mut on_output,
        policy: Default::default(),
    };
    let image = g.build(&base, opts)?;
    image.write_to(&args.output)?;
    let (n, bytes) = image.size();
    eprintln!("grix: built {} ({n} entries, {} MiB)", args.output.display(), bytes >> 20);
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
    grix::mcp::serve(&config, std::io::stdin().lock(), std::io::stdout().lock())?;
    Ok(0)
}
