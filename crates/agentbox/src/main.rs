use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use agentbox::{Capability, DenyAction, Manifest, Sandbox, Stream};
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "agentbox", about = "Run Linux programs in a capability-scoped unikernel")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a program in a fresh sandbox.
    Run(RunArgs),
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
        Cmd::Run(args) => run(args),
    };
    match result {
        Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
        Err(e) => {
            eprintln!("agentbox: {e:#}");
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
    let command = if args.command.is_empty() { manifest.command.clone() } else { args.command.clone() };
    if command.is_empty() {
        bail!("no command given (pass it after `--` or set `command` in the manifest)");
    }

    let sandbox = b.build()?;
    if args.json {
        let out = sandbox.run(&command)?;
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(out.status.code());
    }

    let out = sandbox.run_streaming(&command, |stream, data| {
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
        for e in &out.events {
            eprintln!("agentbox: {e}");
        }
    }
    match &out.status {
        agentbox::ExitStatus::Timeout => eprintln!("agentbox: timed out"),
        agentbox::ExitStatus::KernelPanic => eprintln!("agentbox: guest kernel panic:\n{}", out.kernel_log),
        agentbox::ExitStatus::VmFailed(why) => eprintln!("agentbox: {why}"),
        _ => {}
    }
    Ok(out.status.code())
}
