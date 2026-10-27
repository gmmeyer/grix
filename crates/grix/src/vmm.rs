//! VM backend: QEMU `virt` machine.
//!
//! The VM gets exactly: RAM, a virtio console (the framed channel back to
//! us, and stdin to it, on QEMU's stdio), a PL011 serial port on a Unix
//! socket (early boot and panic messages), the kernel, and the boot image. No
//! network card, no disks, no semihosting (which would expose the host
//! filesystem) and no QEMU monitor.

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
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

fn temp_path(ext: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("grix-{}-{n}.{ext}", std::process::id()))
}

fn write_temp(ext: &str, contents: &[u8]) -> Result<TempFile> {
    let path = temp_path(ext);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| format!("creating {}", path.display()))?;
    let guard = TempFile(path);
    f.write_all(contents)?;
    Ok(guard)
}

/// How long the guest gets, after the program ends, to send its exports
/// (on top of what's left of the timeout).
const EXPORT_GRACE: Duration = Duration::from_secs(30);

/// The most of the serial port's output we keep: the kernel only writes
/// there before the virtio console is up and when it panics.
const MAX_UART: usize = 1 << 20;

/// Wait for QEMU to connect to the serial port's socket, which it does
/// while starting up, before the guest runs. `None` if QEMU exits first.
fn accept_uart(listener: &UnixListener, child: &mut Child) -> Result<Option<UnixStream>> {
    listener.set_nonblocking(true)?;
    let started = Instant::now();
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                return Ok(Some(stream));
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) => return Err(e).context("accepting QEMU's serial connection"),
        }
        if child.try_wait()?.is_some() {
            return Ok(None);
        }
        if started.elapsed() > Duration::from_secs(30) {
            anyhow::bail!("QEMU didn't connect its serial port");
        }
        thread::sleep(Duration::from_millis(1));
    }
}

/// Read the serial port until QEMU closes it, keeping at most `MAX_UART`
/// bytes. Reading on past that keeps QEMU from blocking on it.
fn read_uart(mut stream: UnixStream) -> Vec<u8> {
    let mut kept = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let room = (MAX_UART - kept.len()).min(n);
                kept.extend_from_slice(&buf[..room]);
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    kept
}

/// Feed `input` to the guest's stdin as frames, then end it. QEMU reads
/// only as much as the guest has buffers for, so writes here block: that's
/// the backpressure. They fail once QEMU is gone.
fn feed_stdin(mut qemu_in: &ChildStdin, mut input: Box<dyn Read + Send>) {
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
    let img = write_temp("img", image)?;
    let uart_path = temp_path("uart");
    let listener =
        UnixListener::bind(&uart_path).with_context(|| format!("creating socket {}", uart_path.display()))?;
    let _uart_path = TempFile(uart_path.clone());
    // Under emulation use QEMU's richest CPU model; with hardware virtualization, the host CPU.
    let cpu = if cfg.accel == "tcg" { "max,pauth-impdef=on" } else { "host" };
    let mut cmd = Command::new(&cfg.qemu);
    cmd.args(["-machine", "virt,gic-version=3", "-cpu", cpu, "-smp", "1"])
        .args(["-m", &format!("{}M", cfg.memory_mb)])
        .args(["-accel", &cfg.accel])
        .args(["-nodefaults", "-no-user-config", "-display", "none", "-no-reboot"])
        .args(["-global", "virtio-mmio.force-legacy=false"])
        // A serial port, not a `virtconsole`: QEMU drops console output the
        // host doesn't read fast enough, but holds a port's back. Port 0 is
        // reserved for consoles, so it's port 1.
        .args(["-chardev", "stdio,id=con,signal=off", "-device", "virtio-serial-device,max_ports=2"])
        .args(["-device", "virtserialport,chardev=con,nr=1"])
        .arg("-chardev")
        .arg(format!("socket,id=uart,path={}", uart_path.display()))
        .args(["-serial", "chardev:uart"])
        .arg("-kernel")
        .arg(&cfg.kernel)
        .arg("-device")
        .arg(format!("loader,file={},addr={IMAGE_BASE:#x},force-raw=on", img.0.display()))
        // Piped even without input: QEMU disconnects the port when its
        // stdin ends, and then discards what the guest writes.
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd.spawn().with_context(|| format!("starting {}", cfg.qemu.display()))?;
    let mut child = ChildGuard(child);
    let uart = accept_uart(&listener, &mut child.0)?;
    drop(listener);
    let uart_thread = thread::spawn(move || uart.map(read_uart).unwrap_or_default());
    // Kept open until QEMU is gone, after stdin's end frame too.
    let qemu_in = Arc::new(child.0.stdin.take().unwrap());
    if let Some(input) = stdin {
        let qemu_in = qemu_in.clone();
        // Detached: it may be blocked reading `input` when the VM ends.
        thread::spawn(move || feed_stdin(&qemu_in, input));
    }

    let mut stdout = child.0.stdout.take().unwrap();
    // Bounded, so a slow `on_frame` holds QEMU back (and through it the
    // guest) instead of piling output up here.
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(16);
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

    let mut deadline = Instant::now() + timeout;
    let mut decoder = FrameDecoder::new();
    let mut exit = None;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let chunk = match rx.recv_timeout(left) {
            Ok(chunk) => chunk,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            // Out of time. If the program had ended, that's its status (and
            // the exports are incomplete); otherwise it timed out.
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Ok(match exit {
                    Some((kind, code)) => VmEnd::Exited { kind, code },
                    None => VmEnd::Timeout,
                });
            }
        };
        decoder.push(&chunk, |ch, payload| match ch {
            Channel::Exit if exit.is_none() => {
                exit = wire::decode_exit(payload);
                if exit.is_some() {
                    deadline = deadline.max(Instant::now() + EXPORT_GRACE);
                }
            }
            Channel::Exit => {}
            _ => on_frame(ch, payload),
        });
    }
    let status = child.0.wait()?;
    drop(qemu_in);
    // A panic's message and status come on the serial port.
    let early = uart_thread.join().unwrap_or_default();
    FrameDecoder::new().push(&early, |ch, payload| match ch {
        Channel::Exit => exit = exit.or(wire::decode_exit(payload)),
        _ => on_frame(ch, payload),
    });
    let qemu_stderr = stderr_thread.join().unwrap_or_default();
    Ok(match exit {
        Some((kind, code)) => VmEnd::Exited { kind, code },
        None => VmEnd::Lost { qemu_status: status.code(), qemu_stderr },
    })
}
