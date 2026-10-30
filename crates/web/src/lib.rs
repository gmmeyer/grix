//! grix's host side for a web page: the boot image the kernel starts from,
//! and the frames it talks in, built with `grix_abi` itself so the page
//! can't drift from the kernel. The machine is QEMU compiled to wasm; this
//! is what `crates/grix` does around it (`image.rs`, `vmm.rs`), minus
//! everything a browser can't have (host files, networking, live mounts).
//!
//! The page calls the `extern "C"` functions at the bottom (wasm32, no
//! bindings generator): it copies its bytes in through [`grix_alloc`], and
//! each call leaves its result in one output buffer ([`grix_out_ptr`],
//! [`grix_out_len`]) until the next.

use std::cell::RefCell;
use std::collections::BTreeMap;

use grix_abi::image::{Entry, EntryKind, Image};
use grix_abi::link::{STDIN_WINDOW, ToHost};
use grix_abi::machine;
use grix_abi::policy::{Capability, DenyAction, Policy};
use grix_abi::wire::{self, Channel, Event, ExitKind, FrameDecoder, Input};
use serde::Deserialize;

// The CLI's words for events, so the page says what `grix run` would.
#[path = "../../grix/src/event.rs"]
#[allow(dead_code)]
mod event;

use event::GuestEvent;

/// Paths the guest kernel provides itself (as `crates/grix/src/image.rs`).
const RESERVED: &[&str] = &["/dev", "/proc", "/sys"];

/// What runs, and with what: the page's half of `SandboxBuilder`.
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Spec {
    pub argv: Vec<String>,
    /// `NAME=value` strings.
    pub env: Vec<String>,
    /// Capability names (`Capability::name`).
    pub allow: Vec<String>,
    /// Kill with SIGSYS instead of failing with EPERM.
    pub kill_on_deny: bool,
    pub cwd: String,
    pub memory_mb: u64,
    pub uid: u32,
    pub gid: u32,
    pub cpus: u32,
    /// The page sends stdin (`Session::stdin`); otherwise reads see its end at once.
    pub stdin: bool,
    /// TTY mode: rows and columns.
    pub tty: Option<(u16, u16)>,
    /// The page's clock, in ms since the Unix epoch.
    pub now_ms: f64,
    /// Entropy for the guest's CSPRNG (`crypto.getRandomValues`).
    pub seed: Vec<u8>,
}

impl Default for Spec {
    fn default() -> Self {
        Spec {
            argv: Vec::new(),
            env: Vec::new(),
            allow: Vec::new(),
            kill_on_deny: false,
            cwd: "/".into(),
            memory_mb: 256,
            uid: 1000,
            gid: 1000,
            cpus: 1,
            stdin: false,
            tty: None,
            now_ms: 0.0,
            seed: Vec::new(),
        }
    }
}

enum Node {
    File { data: Vec<u8>, mode: u32 },
    Dir { mode: u32 },
    Symlink { target: String },
}

/// The imports, then the image.
#[derive(Default)]
pub struct Builder {
    files: BTreeMap<String, Node>,
}

/// Check and normalize an absolute guest path, as `image::guest_path` does.
fn guest_path(p: &str) -> Result<String, String> {
    if !p.starts_with('/') {
        return Err(format!("guest path {p:?} must be absolute"));
    }
    let parts: Vec<&str> = p.split('/').filter(|c| !c.is_empty() && *c != ".").collect();
    if parts.contains(&"..") {
        return Err(format!("guest path {p:?} must not contain `..`"));
    }
    let norm = format!("/{}", parts.join("/"));
    if RESERVED.iter().any(|r| norm == *r || norm.starts_with(&format!("{r}/"))) {
        return Err(format!("guest path {p:?} is reserved by the sandbox"));
    }
    Ok(norm)
}

/// Not setuid or setgid: nothing in the sandbox honours them (as for an
/// OCI image's layers).
const MODE_BITS: u32 = 0o1777;

impl Builder {
    pub fn file(&mut self, path: &str, data: Vec<u8>, mode: u32) -> Result<(), String> {
        self.files.insert(guest_path(path)?, Node::File { data, mode: mode & MODE_BITS });
        Ok(())
    }

    pub fn dir(&mut self, path: &str, mode: u32) -> Result<(), String> {
        let path = guest_path(path)?;
        if path != "/" {
            self.files.insert(path, Node::Dir { mode: mode & MODE_BITS });
        }
        Ok(())
    }

    pub fn symlink(&mut self, path: &str, target: &str) -> Result<(), String> {
        self.files.insert(guest_path(path)?, Node::Symlink { target: target.into() });
        Ok(())
    }

    /// The boot image for QEMU `virt` (where its redistributors are), at
    /// `image::IMAGE_BASE`.
    pub fn image(&self, spec: &Spec) -> Result<Vec<u8>, String> {
        let exe = spec.argv.first().ok_or("empty command")?;
        let mut policy =
            Policy { caps: 0, on_deny: if spec.kill_on_deny { DenyAction::Kill } else { DenyAction::Errno } };
        for name in &spec.allow {
            policy.grant(Capability::from_name(name).ok_or_else(|| format!("no capability {name:?}"))?);
        }
        if !(1..=machine::MAX_CPUS).contains(&spec.cpus) {
            return Err(format!("cpus must be 1 to {}", machine::MAX_CPUS));
        }
        let mut seed = [0u8; 32];
        if spec.seed.len() != seed.len() {
            return Err("seed must be 32 bytes".into());
        }
        seed.copy_from_slice(&spec.seed);
        let entries = self
            .files
            .iter()
            .map(|(path, node)| match node {
                Node::File { data, mode } => Entry { path, kind: EntryKind::File, mode: *mode, mtime_ns: 0, data },
                Node::Dir { mode } => Entry { path, kind: EntryKind::Dir, mode: *mode, mtime_ns: 0, data: &[] },
                Node::Symlink { target } => {
                    Entry { path, kind: EntryKind::Symlink, mode: 0o777, mtime_ns: 0, data: target.as_bytes() }
                }
            })
            .collect();
        Ok(Image {
            ram_size: spec.memory_mb << 20,
            gicr: machine::GICR_QEMU,
            boot_time_ns: (spec.now_ms.max(0.0) as u64).saturating_mul(1_000_000),
            seed,
            policy,
            uid: spec.uid,
            gid: spec.gid,
            cwd: &spec.cwd,
            stdin: spec.stdin || spec.tty.is_some(),
            exe,
            argv: spec.argv.iter().map(String::as_str).collect(),
            envp: spec.env.iter().map(String::as_str).collect(),
            entries,
            exports: Vec::new(),
            export_budget: 0,
            mounts: Vec::new(),
            live_mounts: Vec::new(),
            forwards: Vec::new(),
            udp_forwards: Vec::new(),
            snapshot: false,
            cpus: spec.cpus,
            x86_64: "",
            tty: spec.tty,
            hostname: grix_abi::HOSTNAME,
        }
        .encode())
    }
}

/// QEMU's command line for the machine, as `crates/grix/src/vmm.rs` makes
/// it, for QEMU in the page: the console is its stdio, which the page
/// connects to a [`Session`], and the serial port (output before the
/// console is up, and panics) goes to the file `uart`.
pub fn qemu_args(spec: &Spec, kernel: &str, image: &str, uart: &str) -> Vec<String> {
    let args = [
        "-machine",
        "virt,gic-version=3",
        // Pointer authentication with QEMU's own cheap algorithm: the
        // architected one is most of the emulator's time.
        "-cpu",
        "max,pauth-impdef=on",
        "-smp",
        &spec.cpus.to_string(),
        "-m",
        &format!("{}M", spec.memory_mb),
        "-accel",
        "tcg",
        "-nodefaults",
        "-no-user-config",
        "-display",
        "none",
        "-no-reboot",
        "-global",
        "virtio-mmio.force-legacy=false",
        // A queue kick then reaches the device at once, from the vCPU,
        // instead of as an eventfd for the main loop, whose poll() in the
        // browser wakes only for the console.
        "-global",
        "virtio-mmio.ioeventfd=off",
        "-chardev",
        "stdio,id=con,signal=off",
        "-device",
        "virtio-serial-device,max_ports=2",
        "-device",
        "virtserialport,chardev=con,nr=1",
        "-chardev",
        &format!("file,id=uart,path={uart}"),
        "-serial",
        "chardev:uart",
        "-kernel",
        kernel,
        "-device",
        &format!("loader,file={image},addr={:#x},force-raw=on", grix_abi::image::IMAGE_BASE),
    ];
    args.iter().map(|s| s.to_string()).collect()
}

/// What the page shows of the guest's frames, as records:
/// `[kind u8, len u32 LE, bytes]`.
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Record {
    Stdout = 1,
    Stderr = 2,
    /// The kernel's log (with `-v`).
    Log = 3,
    /// An event, in the CLI's words.
    Event = 4,
    /// How the program ended, in the CLI's words; the last record.
    Exit = 5,
    /// A path the program looked for that wasn't imported, which the CLI
    /// only counts unless asked (programs probe many).
    Missing = 6,
}

/// One run's console: frames out of the guest, stdin into it within the
/// credit the guest gives (`link::STDIN_WINDOW`, as `StdinGate`).
pub struct Session {
    decoder: FrameDecoder,
    credit: u64,
    stdin: Vec<u8>,
    stdin_end: bool,
    end_sent: bool,
    exited: bool,
}

impl Default for Session {
    fn default() -> Self {
        Session {
            decoder: FrameDecoder::new(),
            credit: STDIN_WINDOW as u64,
            stdin: Vec::new(),
            stdin_end: false,
            end_sent: false,
            exited: false,
        }
    }
}

fn record(out: &mut Vec<u8>, kind: Record, bytes: &[u8]) {
    out.push(kind as u8);
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

impl Session {
    /// Bytes the machine wrote (its virtio console or its serial port),
    /// as records for the page.
    pub fn output(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let (credit, exited) = (&mut self.credit, &mut self.exited);
        self.decoder.push(data, |ch, payload| match ch {
            Channel::Stdout => record(&mut out, Record::Stdout, payload),
            Channel::Stderr => record(&mut out, Record::Stderr, payload),
            Channel::Log => record(&mut out, Record::Log, payload),
            Channel::Event => match Event::decode(payload) {
                Ok(e @ Event::MissingPath { .. }) => {
                    record(&mut out, Record::Missing, GuestEvent::from(e).to_string().as_bytes())
                }
                Ok(e) => record(&mut out, Record::Event, GuestEvent::from(e).to_string().as_bytes()),
                Err(_) => record(&mut out, Record::Log, b"undecodable event"),
            },
            Channel::Exit if !*exited => {
                if let Some((kind, code)) = wire::decode_exit(payload) {
                    *exited = true;
                    let how = match kind {
                        ExitKind::Exited => format!("exited with status {code}"),
                        ExitKind::Signaled => format!("killed by signal {code}"),
                        ExitKind::Panic => "the grix kernel panicked".into(),
                    };
                    record(&mut out, Record::Exit, how.as_bytes());
                }
            }
            Channel::Link => {
                if let Ok(ToHost::StdinCredit { bytes }) = ToHost::decode(payload) {
                    *credit = credit.saturating_add(bytes as u64);
                }
                // Nothing else comes without `net`, which the page never grants.
            }
            // Exports and live mounts: the page has neither. Nor metrics.
            Channel::Exit | Channel::Export | Channel::Fs | Channel::Stats => {}
        });
        out
    }

    /// stdin from the page, and maybe its end.
    pub fn stdin(&mut self, data: &[u8], end: bool) {
        self.stdin.extend_from_slice(data);
        self.stdin_end |= end;
    }

    /// Frames for the machine's console now: as much stdin as the guest
    /// has credit for, then its end once all of it went.
    pub fn input(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        while !self.stdin.is_empty() && self.credit > 0 {
            // credit's low 32 bits are all that fit in wasm32's usize: cap
            // it, so a full counter never truncates to zero here (the
            // loop above would spin forever on a frame of nothing).
            let n = self.stdin.len().min(wire::MAX_FRAME).min(self.credit.min(u32::MAX as u64) as usize);
            out.extend_from_slice(&wire::input_header(Input::Stdin, n));
            out.extend(self.stdin.drain(..n));
            self.credit -= n as u64;
        }
        if self.stdin.is_empty() && self.stdin_end && !self.end_sent {
            self.end_sent = true;
            out.extend_from_slice(&wire::input_header(Input::StdinEof, 0));
        }
        out
    }

    pub fn exited(&self) -> bool {
        self.exited
    }
}

/// A signal for the program's process group, as `RunControl::signal`.
pub fn signal_frame(signal: u8) -> Vec<u8> {
    let mut f = wire::input_header(Input::Signal, 1).to_vec();
    f.push(signal);
    f
}

/// TTY mode: the terminal's new size.
pub fn resize_frame(rows: u16, cols: u16) -> Vec<u8> {
    let mut f = wire::input_header(Input::Resize, 4).to_vec();
    f.extend_from_slice(&rows.to_le_bytes());
    f.extend_from_slice(&cols.to_le_bytes());
    f
}

// The page's interface.

thread_local! {
    static BUILDER: RefCell<Builder> = RefCell::default();
    static SESSION: RefCell<Session> = RefCell::default();
    static OUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn set_out(bytes: Vec<u8>) -> usize {
    OUT.with(|o| *o.borrow_mut() = bytes);
    OUT.with(|o| o.borrow().len())
}

/// The bytes at `ptr`, which the page filled after [`grix_alloc`].
///
/// # Safety
/// `ptr..ptr + len` must be memory from `grix_alloc(len)` (or empty).
unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        return &[];
    }
    // SAFETY: the caller's promise.
    unsafe { std::slice::from_raw_parts(ptr, len) }
}

/// The result of a call that can fail: 0, or -1 with the message as output.
fn status(r: Result<(), String>) -> i32 {
    match r {
        Ok(()) => 0,
        Err(e) => {
            set_out(e.into_bytes());
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn grix_alloc(len: usize) -> *mut u8 {
    let mut v = Vec::<u8>::with_capacity(len.max(1));
    let ptr = v.as_mut_ptr();
    std::mem::forget(v);
    ptr
}

/// # Safety
/// `ptr` and `len` must come from one `grix_alloc`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grix_free(ptr: *mut u8, len: usize) {
    // SAFETY: the caller's promise: this is grix_alloc's allocation.
    drop(unsafe { Vec::from_raw_parts(ptr, 0, len.max(1)) });
}

#[unsafe(no_mangle)]
pub extern "C" fn grix_out_ptr() -> *const u8 {
    OUT.with(|o| o.borrow().as_ptr())
}

#[unsafe(no_mangle)]
pub extern "C" fn grix_out_len() -> usize {
    OUT.with(|o| o.borrow().len())
}

/// Start over: no imports, a new console.
#[unsafe(no_mangle)]
pub extern "C" fn grix_reset() {
    BUILDER.with(|b| *b.borrow_mut() = Builder::default());
    SESSION.with(|s| *s.borrow_mut() = Session::default());
}

/// Import an entry: `kind` 0 a file (`data` its bytes), 1 a directory, 2 a
/// symlink (`data` its target).
///
/// # Safety
/// The pointers must be `grix_alloc`'s, filled by the page.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grix_import(
    kind: u32,
    mode: u32,
    path: *const u8,
    path_len: usize,
    data: *const u8,
    data_len: usize,
) -> i32 {
    // SAFETY: the caller's promise.
    let (path, data) = unsafe { (bytes(path, path_len), bytes(data, data_len)) };
    let Ok(path) = std::str::from_utf8(path) else { return status(Err("path isn't UTF-8".into())) };
    status(BUILDER.with(|b| {
        let mut b = b.borrow_mut();
        match kind {
            0 => b.file(path, data.to_vec(), mode),
            1 => b.dir(path, mode),
            2 => b.symlink(path, std::str::from_utf8(data).map_err(|_| "link target isn't UTF-8")?),
            _ => Err(format!("no entry kind {kind}")),
        }
    }))
}

/// Encode the boot image for `spec` (JSON, see [`Spec`]) as output.
///
/// # Safety
/// The pointer must be `grix_alloc`'s, filled by the page.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grix_image(spec: *const u8, spec_len: usize) -> i32 {
    // SAFETY: the caller's promise.
    let spec = unsafe { bytes(spec, spec_len) };
    let built = serde_json::from_slice::<Spec>(spec)
        .map_err(|e| format!("bad spec: {e}"))
        .and_then(|spec| BUILDER.with(|b| b.borrow().image(&spec)));
    match built {
        Ok(image) => {
            set_out(image);
            0
        }
        Err(e) => status(Err(e)),
    }
}

/// Output: QEMU's arguments for `spec` (JSON), as a JSON array (see [`qemu_args`]).
///
/// # Safety
/// The pointers must be `grix_alloc`'s, filled by the page.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grix_qemu_args(spec: *const u8, spec_len: usize) -> i32 {
    // SAFETY: the caller's promise.
    let spec = unsafe { bytes(spec, spec_len) };
    match serde_json::from_slice::<Spec>(spec) {
        Ok(spec) => {
            let args = qemu_args(&spec, "/grix-kernel", "/grix-image", "/uart");
            set_out(serde_json::to_vec(&args).expect("strings"));
            0
        }
        Err(e) => status(Err(format!("bad spec: {e}"))),
    }
}

/// Bytes from the machine; output: records (see [`Record`]).
///
/// # Safety
/// The pointer must be `grix_alloc`'s, filled by the page.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grix_output(data: *const u8, len: usize) -> usize {
    // SAFETY: the caller's promise.
    let data = unsafe { bytes(data, len) };
    set_out(SESSION.with(|s| s.borrow_mut().output(data)))
}

/// Queue stdin (and its end, if `end`).
///
/// # Safety
/// The pointer must be `grix_alloc`'s, filled by the page.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grix_stdin(data: *const u8, len: usize, end: bool) {
    // SAFETY: the caller's promise.
    let data = unsafe { bytes(data, len) };
    SESSION.with(|s| s.borrow_mut().stdin(data, end));
}

/// Output: the frames for the machine's console now.
#[unsafe(no_mangle)]
pub extern "C" fn grix_input() -> usize {
    set_out(SESSION.with(|s| s.borrow_mut().input()))
}

/// Output: a frame sending `signal` to the program's process group.
#[unsafe(no_mangle)]
pub extern "C" fn grix_signal(signal: u8) -> usize {
    set_out(signal_frame(signal))
}

/// Output: a frame telling a TTY-mode program its terminal's new size.
#[unsafe(no_mangle)]
pub extern "C" fn grix_resize(rows: u16, cols: u16) -> usize {
    set_out(resize_frame(rows, cols))
}

#[unsafe(no_mangle)]
pub extern "C" fn grix_exited() -> bool {
    SESSION.with(|s| s.borrow().exited())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(argv: &[&str]) -> Spec {
        Spec { argv: argv.iter().map(|s| s.to_string()).collect(), seed: vec![7; 32], ..Spec::default() }
    }

    #[test]
    fn image_round_trips() {
        let mut b = Builder::default();
        b.file("/bin//hello", b"ELF".to_vec(), 0o100755).unwrap();
        b.dir("/data", 0o755).unwrap();
        b.symlink("/bin/hi", "hello").unwrap();
        let mut s = spec(&["/bin/hello", "world"]);
        s.allow = vec!["threads".into()];
        s.tty = Some((24, 80));
        let bytes = b.image(&s).unwrap();
        let img = Image::decode(&bytes).unwrap();
        assert_eq!(img.argv, ["/bin/hello", "world"]);
        assert_eq!(img.gicr, machine::GICR_QEMU);
        assert!(img.policy.allows(Capability::Threads) && !img.policy.allows(Capability::Net));
        assert!(img.stdin);
        let paths: Vec<_> = img.entries.iter().map(|e| (e.path, e.mode)).collect();
        assert_eq!(paths, [("/bin/hello", 0o755), ("/bin/hi", 0o777), ("/data", 0o755)]);
    }

    #[test]
    fn modes_lose_setuid_and_setgid() {
        let mut b = Builder::default();
        b.file("/bin/su", b"ELF".to_vec(), 0o106755).unwrap();
        b.dir("/tmp", 0o41777).unwrap();
        let bytes = b.image(&spec(&["/bin/su"])).unwrap();
        let img = Image::decode(&bytes).unwrap();
        let modes: Vec<_> = img.entries.iter().map(|e| (e.path, e.mode)).collect();
        assert_eq!(modes, [("/bin/su", 0o755), ("/tmp", 0o1777)]);
    }

    #[test]
    fn bad_specs_are_errors() {
        let b = Builder::default();
        assert!(b.image(&spec(&[])).is_err());
        let mut s = spec(&["/x"]);
        s.allow = vec!["root".into()];
        assert!(b.image(&s).is_err());
        assert!(Builder::default().file("/proc/x", vec![], 0).is_err());
        assert!(Builder::default().file("/a/../b", vec![], 0).is_err());
    }

    fn frame(ch: Channel, payload: &[u8]) -> Vec<u8> {
        let mut f = wire::frame_header(ch, payload.len()).to_vec();
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn output_becomes_records() {
        let mut s = Session::default();
        let mut bytes = frame(Channel::Stdout, b"hi\n");
        bytes.extend(b"garbage");
        let ev = Event::Denied { nr: 198, syscall: "socket", capability: "net", detail: "" }.encode();
        bytes.extend(frame(Channel::Event, &ev));
        bytes.extend(frame(Channel::Exit, &wire::encode_exit(ExitKind::Exited, 3)));
        // Split mid-frame: the decoder waits for the rest.
        let mut out = s.output(&bytes[..5]);
        out.extend(s.output(&bytes[5..]));
        let mut want = Vec::new();
        record(&mut want, Record::Stdout, b"hi\n");
        record(&mut want, Record::Event, b"denied socket: needs capability `net`");
        record(&mut want, Record::Exit, b"exited with status 3");
        assert_eq!(out, want);
        assert!(s.exited());
    }

    #[test]
    fn stdin_waits_for_credit() {
        let mut s = Session::default();
        s.stdin(&vec![b'x'; STDIN_WINDOW as usize + 10], true);
        let first = s.input();
        let frames = (STDIN_WINDOW as usize).div_ceil(wire::MAX_FRAME);
        assert_eq!(first.len(), STDIN_WINDOW as usize + frames * wire::FRAME_HEADER);
        assert!(s.input().is_empty());
        let credit = ToHost::StdinCredit { bytes: 4 }.encode();
        s.output(&frame(Channel::Link, &credit));
        assert_eq!(s.input(), [&wire::input_header(Input::Stdin, 4)[..], b"xxxx"].concat());
        s.output(&frame(Channel::Link, &ToHost::StdinCredit { bytes: 100 }.encode()));
        let end = s.input();
        assert_eq!(
            end,
            [&wire::input_header(Input::Stdin, 6)[..], b"xxxxxx", &wire::input_header(Input::StdinEof, 0)].concat()
        );
    }

    /// A guest that gave more credit than a wasm32 usize holds: 2^32 read
    /// 0 there, and `input` spun on empty frames.
    #[test]
    fn credit_past_u32_still_sends() {
        let mut s = Session { credit: 1 << 32, ..Session::default() };
        s.stdin(b"abc", true);
        assert_eq!(
            s.input(),
            [&wire::input_header(Input::Stdin, 3)[..], b"abc", &wire::input_header(Input::StdinEof, 0)].concat()
        );
        assert_eq!(s.credit, (1 << 32) - 3);
    }
}
