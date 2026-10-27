use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use grix::{Capability, DenyAction, Export, ExportState, Manifest, RunOutput, Sandbox, Stream};

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
    /// List the capabilities a sandbox can be granted.
    Caps,
}

#[derive(Parser)]
struct RunArgs {
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

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.cmd {
        Cmd::Caps => {
            for c in Capability::ALL {
                println!("{:<10} {}", c.name(), c.description());
            }
            Ok(0)
        }
        Cmd::Run(args) => run(*args),
    };
    match result {
        Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
        Err(e) => {
            eprintln!("grix: {e:#}");
            ExitCode::from(125)
        }
    }
}

fn run(args: RunArgs) -> Result<i32> {
    let manifest = match &args.manifest {
        Some(p) => Manifest::load(p)?,
        None => Manifest::default(),
    };
    let mut b = manifest.apply(Sandbox::builder())?;
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
    let command = if args.command.is_empty() { manifest.command.clone() } else { args.command.clone() };
    if command.is_empty() {
        bail!("no command given (pass it after `--` or set `command` in the manifest)");
    }

    let sandbox = b.build()?;
    // Piped or redirected input goes to the program; a terminal doesn't
    // (there's no interactive mode yet), so the program sees end-of-file.
    let stdin = !args.no_stdin && !std::io::stdin().is_terminal();
    let run = |on_output: &mut dyn FnMut(Stream, &[u8])| {
        if stdin {
            sandbox.run_streaming_with_stdin(&command, std::io::stdin(), on_output)
        } else {
            sandbox.run_streaming(&command, on_output)
        }
    };
    if args.json {
        let out = run(&mut |_, _| {})?;
        println!("{}", serde_json::to_string_pretty(&out)?);
        let wrote = write_exports(&out, &exports, args.quiet);
        return Ok(if wrote { out.status.code() } else { 125 });
    }

    let out = run(&mut |stream, data| {
        let _ = match stream {
            Stream::Stdout => std::io::stdout().write_all(data),
            Stream::Stderr => std::io::stderr().write_all(data),
        };
    })?;
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
        grix::ExitStatus::KernelPanic => eprintln!("grix: guest kernel panic:\n{}", out.kernel_log),
        grix::ExitStatus::VmFailed(why) => eprintln!("grix: {why}"),
        _ => {}
    }
    let wrote = write_exports(&out, &exports, args.quiet);
    Ok(if wrote { out.status.code() } else { 125 })
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
