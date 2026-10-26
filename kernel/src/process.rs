//! The single process this kernel runs: exec, faults, termination, and
//! reporting of denied/unimplemented operations.

use agentbox_abi::image::Image;
use agentbox_abi::policy::{DenyAction, Policy};
use agentbox_abi::wire::{Event, ExitKind};
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

use crate::arch::{self, TrapFrame};
use crate::console::{self, klog};
use crate::elf;
use crate::errno::*;
use crate::fd::FdTable;
use crate::fs::{self, Ino, Kind, ROOT};
pub use crate::mm::aspace::Access;
use crate::mm::aspace::{AddressSpace, FaultError, STACK_SIZE, STACK_TOP, Vma};
use crate::mm::paging::Prot;
use crate::rng;
use crate::uaccess::copy_out;

pub const PID: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Signal {
    Sigill = 4,
    Sigtrap = 5,
    Sigbus = 7,
    Sigfpe = 8,
    Sigkill = 9,
    Sigsegv = 11,
    Sigsys = 31,
}

#[derive(Clone, Copy, Default)]
pub struct SigAction {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: u64,
}

pub struct Process {
    pub aspace: AddressSpace,
    pub fds: FdTable,
    pub cwd: Ino,
    pub policy: Policy,
    pub uid: u32,
    pub gid: u32,
    pub umask: u32,
    pub sigactions: [SigAction; 65],
    pub sigmask: u64,
    pub sigpending: u64,
    pub altstack: [u64; 3],
    pub rlimits: [(u64, u64); 16],
    pub name: [u8; 16],
    reported: BTreeSet<(u8, u32, String)>,
}

pub static PROCESS: Mutex<Option<Process>> = Mutex::new(None);

const MAX_REPORTS: usize = 512;
const RLIM_INFINITY: u64 = u64::MAX;

impl Process {
    fn new(policy: Policy, uid: u32, gid: u32) -> Self {
        let mut rlimits = [(RLIM_INFINITY, RLIM_INFINITY); 16];
        rlimits[3] = (STACK_SIZE, RLIM_INFINITY); // RLIMIT_STACK
        rlimits[4] = (0, 0); // RLIMIT_CORE
        rlimits[7] = (crate::fd::MAX_FDS as u64, crate::fd::MAX_FDS as u64); // RLIMIT_NOFILE
        Process {
            aspace: AddressSpace::new().expect("out of memory"),
            fds: FdTable::with_stdio(),
            cwd: ROOT,
            policy,
            uid,
            gid,
            umask: 0o022,
            sigactions: [SigAction::default(); 65],
            sigmask: 0,
            sigpending: 0,
            altstack: [0, 2, 0], // SS_DISABLE
            rlimits,
            name: [0; 16],
            reported: BTreeSet::new(),
        }
    }

    fn first_report(&mut self, kind: u8, nr: u32, detail: &str) -> bool {
        self.reported.len() < MAX_REPORTS && self.reported.insert((kind, nr, detail.into()))
    }

    /// A syscall needed a capability the policy does not grant.
    pub fn deny(&mut self, nr: u32, syscall: &str, capability: &str, detail: &str) -> SysResult {
        if self.first_report(0, nr, detail) {
            console::event(&Event::Denied { nr, syscall, capability, detail });
        }
        match self.policy.on_deny {
            DenyAction::Errno => Err(EPERM),
            DenyAction::Kill => {
                let msg = alloc::format!("{syscall} denied (needs capability `{capability}`)");
                exit_signaled(Signal::Sigsys as u32, 0, 0, &msg)
            }
        }
    }

    /// The program needs something this kernel does not implement yet.
    pub fn unimplemented(&mut self, nr: u32, syscall: &str, detail: &str, err: Errno) -> SysResult {
        if self.first_report(1, nr, detail) {
            console::event(&Event::Unimplemented { nr, syscall, detail });
        }
        Err(err)
    }

    /// The program looked for a path that was not imported.
    pub fn missing_path(&mut self, base: Ino, path: &str) {
        let abs = if path.starts_with('/') {
            String::from(path)
        } else {
            let mut s = fs::get().path_of(base);
            if !s.ends_with('/') {
                s.push('/');
            }
            s.push_str(path);
            s
        };
        if self.first_report(2, 0, &abs) {
            console::event(&Event::MissingPath { path: &abs });
        }
    }
}

/// Exit the program normally.
pub fn exit(code: i32) -> ! {
    console::exit(ExitKind::Exited, code)
}

/// Terminate the program with a signal and report why.
pub fn exit_signaled(signal: u32, addr: u64, pc: u64, detail: &str) -> ! {
    console::event(&Event::Fault { signal, addr, pc, detail });
    console::exit(ExitKind::Signaled, signal as i32)
}

pub fn terminate(sig: Signal, addr: u64, pc: u64, detail: &str) -> ! {
    exit_signaled(sig as u32, addr, pc, detail)
}

/// Demand paging for a user translation fault.
pub fn user_fault(tf: &TrapFrame, far: u64, access: Access) {
    let result = {
        let mut guard = PROCESS.lock();
        let p = guard.as_mut().expect("fault without a process");
        p.aspace.fault(far, access)
    };
    match result {
        Ok(()) => {}
        Err(FaultError::Segv) => terminate(Signal::Sigsegv, far, tf.elr, access.describe_violation()),
        Err(FaultError::OutOfMemory) => terminate(Signal::Sigkill, far, tf.elr, "out of memory"),
    }
}

/// Load the image's program and jump to it.
pub fn start(img: Image<'static>) -> ! {
    fs::init(&img.entries, img.exe);
    let mut p = Process::new(img.policy, img.uid, img.gid);
    p.aspace.activate();
    match exec(&mut p, &img) {
        Ok((entry, sp)) => {
            *PROCESS.lock() = Some(p);
            arch::enter_user(entry, sp)
        }
        Err((code, reason)) => {
            console::event(&Event::ExecFailed { path: img.exe, reason: &reason });
            klog!("exec {}: {}\n", img.exe, reason);
            exit(code)
        }
    }
}

fn exec(p: &mut Process, img: &Image<'static>) -> Result<(u64, u64), (i32, String)> {
    let fs = fs::get();
    p.cwd = match fs.lookup(ROOT, img.cwd, true) {
        Ok(ino) if fs.is_dir(ino) => ino,
        _ => return Err((127, alloc::format!("working directory {} does not exist", img.cwd))),
    };
    let file = |path: &str, what: &str| -> Result<&'static [u8], (i32, String)> {
        let ino = fs
            .lookup(p.cwd, path, true)
            .map_err(|_| (127, alloc::format!("{what} {path} not found (was it imported?)")))?;
        let node = fs.node(ino);
        match node.kind {
            Kind::File(data) if node.perm & 0o111 != 0 || what == "interpreter" => Ok(data),
            Kind::File(_) => Err((126, alloc::format!("{what} {path} is not executable"))),
            _ => Err((126, alloc::format!("{what} {path} is not a regular file"))),
        }
    };

    let data = file(img.exe, "program")?;
    let exe = elf::load(&mut p.aspace, data, Some(elf::DYN_BASE)).map_err(|e| (126, e.into()))?;
    let (entry, interp_base) = match exe.interp {
        Some(path) => {
            let idata = file(path, "interpreter")?;
            let interp = elf::load(&mut p.aspace, idata, None).map_err(|e| (126, alloc::format!("{path}: {e}")))?;
            if interp.interp.is_some() {
                return Err((126, "interpreter requests its own interpreter".into()));
            }
            (interp.entry, interp.base)
        }
        None => (exe.entry, 0),
    };

    p.aspace.brk_start = exe.end;
    p.aspace.brk = exe.end;
    p.aspace.map(Vma::anon(STACK_TOP - STACK_SIZE, STACK_TOP, Prot::RW));

    let auxv = [
        (3, exe.phdr),    // AT_PHDR
        (4, 56),          // AT_PHENT
        (5, exe.phnum),   // AT_PHNUM
        (6, 4096),        // AT_PAGESZ
        (7, interp_base), // AT_BASE
        (8, 0),           // AT_FLAGS
        (9, exe.entry),   // AT_ENTRY
        (11, p.uid as u64),
        (12, p.uid as u64),
        (13, p.gid as u64),
        (14, p.gid as u64),
        (16, arch::hwcap()), // AT_HWCAP
        (17, 100),           // AT_CLKTCK
        (23, 0),             // AT_SECURE
        (26, 0),             // AT_HWCAP2
    ];
    let sp = build_stack(&mut p.aspace, &img.argv, &img.envp, img.exe, &auxv)
        .map_err(|e| (126, alloc::format!("could not build initial stack (errno {})", e.0)))?;
    Ok((entry, sp))
}

/// Lay out argc/argv/envp/auxv at the top of the stack as Linux does.
fn build_stack(
    a: &mut AddressSpace,
    argv: &[&str],
    envp: &[&str],
    execfn: &str,
    aux: &[(u64, u64)],
) -> Result<u64, Errno> {
    let total: usize = argv.iter().chain(envp).map(|s| s.len() + 1).sum::<usize>() + execfn.len() + 1;
    if total > 1 << 20 {
        return Err(E2BIG);
    }
    let mut sp = STACK_TOP;
    let mut push = |a: &mut AddressSpace, bytes: &[u8]| -> Result<u64, Errno> {
        sp -= bytes.len() as u64;
        copy_out(a, sp, bytes)?;
        Ok(sp)
    };
    let mut cstr = |a: &mut AddressSpace, s: &str| -> Result<u64, Errno> {
        let mut v = Vec::with_capacity(s.len() + 1);
        v.extend_from_slice(s.as_bytes());
        v.push(0);
        push(a, &v)
    };
    let execfn_ptr = cstr(a, execfn)?;
    let env_ptrs = envp.iter().map(|s| cstr(a, s)).collect::<Result<Vec<_>, _>>()?;
    let arg_ptrs = argv.iter().map(|s| cstr(a, s)).collect::<Result<Vec<_>, _>>()?;
    let platform_ptr = cstr(a, "aarch64")?;
    let mut random = [0u8; 16];
    rng::fill(&mut random);
    let random_ptr = push(a, &random)?;

    let mut words: Vec<u64> = Vec::new();
    words.push(argv.len() as u64);
    words.extend(&arg_ptrs);
    words.push(0);
    words.extend(&env_ptrs);
    words.push(0);
    for &(k, v) in aux.iter().chain(&[(15, platform_ptr), (25, random_ptr), (31, execfn_ptr), (0, 0)]) {
        words.push(k);
        words.push(v);
    }
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let sp = (random_ptr - bytes.len() as u64) & !15;
    copy_out(a, sp, &bytes)?;
    Ok(sp)
}
