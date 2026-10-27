//! VM backend: QEMU `virt` machine.
//!
//! The VM gets exactly: RAM, one serial port (the framed channel back to us,
//! and stdin to it), the kernel, and the boot image. No network card, no
//! disks, no semihosting (which would expose the host filesystem) and no
//! QEMU monitor.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use grix_abi::image::IMAGE_BASE;
use grix_abi::wire::{self, Channel, ExitKind, FrameDecoder, Input};

pub(crate) struct VmConfig {
    pub qemu: PathBuf,
    pub kernel: PathBuf,
    pub memory_mb: u64,
    pub accel: String,
}

pub(crate) enum VmEnd {
    Exited {
        kind: ExitKind,
        code: i32,
    },
    Timeout,
    /// QEMU exited without the guest reporting a status.
    Lost {
        qemu_status: Option<i32>,
        qemu_stderr: String,
    },
}

/// Kills QEMU if we bail out early (error, timeout, caller panic).
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct TempFile(PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn write_temp(image: &[u8]) -> Result<TempFile> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("grix-{}-{n}.img", std::process::id()));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| format!("creating {}", path.display()))?;
    let guard = TempFile(path);
    f.write_all(image)?;
    Ok(guard)
}

/// Feed `input` to the guest's stdin as frames, then end it, once the guest
/// says it's ready. The guest stops draining the console when its stdin
/// buffer is full, so writes here block: that's the backpressure. They fail
/// once QEMU is gone.
fn feed_stdin(mut qemu_in: impl Write, mut input: Box<dyn Read + Send>, ready: mpsc::Receiver<()>) {
    if ready.recv().is_err() {
        return; // the VM ended first
    }
    let mut buf = vec![0u8; wire::MAX_FRAME];
    loop {
        let n = match input.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            // An unreadable input ends stdin, like a closed pipe.
            Err(_) => break,
        };
        if qemu_in.write_all(&wire::input_header(Input::Stdin, n)).and_then(|_| qemu_in.write_all(&buf[..n])).is_err() {
            return;
        }
    }
    let _ = qemu_in.write_all(&wire::input_header(Input::StdinEof, 0));
    let _ = qemu_in.flush();
}

pub(crate) fn run(
    cfg: &VmConfig,
    image: &[u8],
    timeout: Duration,
    stdin: Option<Box<dyn Read + Send>>,
    mut on_frame: impl FnMut(Channel, &[u8]),
) -> Result<VmEnd> {
    if !cfg.kernel.exists() {
        anyhow::bail!(
            "grix kernel not found at {} (build it with `make kernel` or set GRIX_KERNEL)",
            cfg.kernel.display()
        );
    }
    let img = write_temp(image)?;
    // Under emulation use QEMU's richest CPU model; with hardware virtualization, the host CPU.
    let cpu = if cfg.accel == "tcg" { "max,pauth-impdef=on" } else { "host" };
    let mut cmd = Command::new(&cfg.qemu);
    cmd.args(["-machine", "virt,gic-version=3", "-cpu", cpu, "-smp", "1"])
        .args(["-m", &format!("{}M", cfg.memory_mb)])
        .args(["-accel", &cfg.accel])
        .args(["-nodefaults", "-no-user-config", "-display", "none", "-no-reboot"])
        .args(["-chardev", "stdio,id=con,signal=off", "-serial", "chardev:con"])
        .arg("-kernel")
        .arg(&cfg.kernel)
        .arg("-device")
        .arg(format!("loader,file={},addr={IMAGE_BASE:#x},force-raw=on", img.0.display()))
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd.spawn().with_context(|| format!("starting {}", cfg.qemu.display()))?;
    let mut child = ChildGuard(child);
    let (ready_tx, ready_rx) = mpsc::channel();
    if let (Some(input), Some(qemu_in)) = (stdin, child.0.stdin.take()) {
        // Detached: it may be blocked reading `input` when the VM ends.
        thread::spawn(move || feed_stdin(qemu_in, input, ready_rx));
    }

    let mut stdout = child.0.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    thread::spawn(move || {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match stdout.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let mut stderr = child.0.stderr.take().unwrap();
    let stderr_thread = thread::spawn(move || {
        let mut s = Vec::new();
        let _ = (&mut stderr).take(64 * 1024).read_to_end(&mut s);
        String::from_utf8_lossy(&s).into_owned()
    });

    let deadline = Instant::now() + timeout;
    let mut decoder = FrameDecoder::new();
    let mut exit = None;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(VmEnd::Timeout);
        }
        match rx.recv_timeout(left) {
            Ok(chunk) => decoder.push(&chunk, |ch, payload| match ch {
                Channel::Exit => exit = exit.or(wire::decode_exit(payload)),
                Channel::Ready => {
                    let _ = ready_tx.send(());
                }
                _ => on_frame(ch, payload),
            }),
            Err(mpsc::RecvTimeoutError::Timeout) => return Ok(VmEnd::Timeout),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let status = child.0.wait()?;
    let qemu_stderr = stderr_thread.join().unwrap_or_default();
    Ok(match exit {
        Some((kind, code)) => VmEnd::Exited { kind, code },
        None => VmEnd::Lost { qemu_status: status.code(), qemu_stderr },
    })
}
