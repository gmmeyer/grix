//! Synthetic /proc and /sys files. Contents are generated from live kernel
//! state each time a file is opened, like Linux's procfs.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use crate::arch;
use crate::fd::FileKind;
use crate::fs;
use crate::mm::aspace::{Backing, STACK_TOP};
use crate::mm::frame;
use crate::process::{PID, Process};
use crate::time;

pub const HOSTNAME: &str = "grix";
pub const RELEASE: &str = "6.1.0-grix";
pub const VERSION: &str = "#1 SMP grix";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcFile {
    /// Fixed contents.
    Text(&'static str),
    // /proc/<pid>/...
    Maps,
    Status,
    Stat,
    Statm,
    Cmdline,
    Environ,
    Comm,
    Limits,
    Mountinfo,
    Mounts,
    // /proc/...
    Cpuinfo,
    ProcStat,
    Meminfo,
    Uptime,
    Loadavg,
    Version,
    RandomUuid,
    BootId,
    // /sys/fs/cgroup/...
    CgroupMemoryMax,
}

/// The files to create, by path. `/proc/self` is a symlink to `/proc/1`.
pub const FILES: &[(&str, ProcFile)] = &[
    ("/proc/1/maps", ProcFile::Maps),
    ("/proc/1/status", ProcFile::Status),
    ("/proc/1/stat", ProcFile::Stat),
    ("/proc/1/statm", ProcFile::Statm),
    ("/proc/1/cmdline", ProcFile::Cmdline),
    ("/proc/1/environ", ProcFile::Environ),
    ("/proc/1/comm", ProcFile::Comm),
    ("/proc/1/limits", ProcFile::Limits),
    ("/proc/1/mountinfo", ProcFile::Mountinfo),
    ("/proc/1/mounts", ProcFile::Mounts),
    ("/proc/1/cgroup", ProcFile::Text("0::/\n")),
    ("/proc/1/oom_score_adj", ProcFile::Text("0\n")),
    ("/proc/cpuinfo", ProcFile::Cpuinfo),
    ("/proc/stat", ProcFile::ProcStat),
    ("/proc/meminfo", ProcFile::Meminfo),
    ("/proc/uptime", ProcFile::Uptime),
    ("/proc/loadavg", ProcFile::Loadavg),
    ("/proc/version", ProcFile::Version),
    ("/proc/filesystems", ProcFile::Text("nodev\ttmpfs\nnodev\tproc\n")),
    ("/proc/sys/kernel/hostname", ProcFile::Text("grix\n")),
    ("/proc/sys/kernel/osrelease", ProcFile::Text("6.1.0-grix\n")),
    ("/proc/sys/kernel/ostype", ProcFile::Text("Linux\n")),
    ("/proc/sys/kernel/pid_max", ProcFile::Text("4194304\n")),
    ("/proc/sys/kernel/threads-max", ProcFile::Text("1024\n")),
    ("/proc/sys/kernel/ngroups_max", ProcFile::Text("65536\n")),
    ("/proc/sys/kernel/random/uuid", ProcFile::RandomUuid),
    ("/proc/sys/kernel/random/boot_id", ProcFile::BootId),
    ("/proc/sys/vm/overcommit_memory", ProcFile::Text("0\n")),
    ("/proc/sys/vm/max_map_count", ProcFile::Text("65530\n")),
    ("/proc/sys/fs/file-max", ProcFile::Text("1024\n")),
    ("/proc/sys/fs/nr_open", ProcFile::Text("1024\n")),
    ("/proc/sys/net/core/somaxconn", ProcFile::Text("4096\n")),
    ("/sys/devices/system/cpu/online", ProcFile::Text("0\n")),
    ("/sys/devices/system/cpu/possible", ProcFile::Text("0\n")),
    ("/sys/devices/system/cpu/present", ProcFile::Text("0\n")),
    ("/sys/kernel/mm/transparent_hugepage/enabled", ProcFile::Text("always madvise [never]\n")),
    ("/sys/kernel/mm/transparent_hugepage/hpage_pmd_size", ProcFile::Text("2097152\n")),
    ("/sys/fs/cgroup/cgroup.controllers", ProcFile::Text("cpu memory pids\n")),
    ("/sys/fs/cgroup/cpu.max", ProcFile::Text("100000 100000\n")),
    ("/sys/fs/cgroup/memory.max", ProcFile::CgroupMemoryMax),
    ("/sys/fs/cgroup/pids.max", ProcFile::Text("1024\n")),
];

pub fn generate(p: &Process, f: ProcFile) -> Vec<u8> {
    let mut s = String::new();
    match f {
        ProcFile::Text(t) => s.push_str(t),
        ProcFile::Maps => maps(p, &mut s),
        ProcFile::Status => status(p, &mut s),
        ProcFile::Stat => stat(p, &mut s),
        ProcFile::Statm => {
            let (size, rss) = mem_pages(p);
            let _ = writeln!(s, "{size} {rss} 0 0 0 {size} 0");
        }
        ProcFile::Cmdline | ProcFile::Environ => {
            let list = if f == ProcFile::Cmdline { &p.argv } else { &p.envp };
            let mut v = Vec::new();
            for a in list {
                v.extend_from_slice(a.as_bytes());
                v.push(0);
            }
            return v;
        }
        ProcFile::Comm => {
            let _ = writeln!(s, "{}", comm(p));
        }
        ProcFile::Limits => limits(p, &mut s),
        // The root is read-only without fs_write.
        ProcFile::Mountinfo => {
            let m = root_mode(p);
            let _ = write!(
                s,
                "1 0 0:1 / / {m},relatime - tmpfs grix {m}\n2 1 0:2 / /proc rw,relatime - proc proc rw\n\
                 3 1 0:3 / /dev rw,relatime - devtmpfs dev rw\n"
            );
        }
        ProcFile::Mounts => {
            let m = root_mode(p);
            let _ = write!(s, "grix / tmpfs {m} 0 0\nproc /proc proc rw 0 0\ndev /dev devtmpfs rw 0 0\n");
        }
        ProcFile::Cpuinfo => cpuinfo(&mut s),
        ProcFile::ProcStat => {
            let ticks = time::monotonic_ns() / 10_000_000;
            let _ = write!(
                s,
                "cpu  {ticks} 0 0 0 0 0 0 0 0 0\ncpu0 {ticks} 0 0 0 0 0 0 0 0 0\nintr 0\nctxt 0\nbtime {}\n\
                 processes 1\nprocs_running 1\nprocs_blocked 0\n",
                time::realtime_to_boot_secs()
            );
        }
        ProcFile::Meminfo => {
            let (total, used) = frame::stats();
            let (total, free) = (total * 4, (total - used) * 4);
            let _ = write!(
                s,
                "MemTotal:       {total:8} kB\nMemFree:        {free:8} kB\nMemAvailable:   {free:8} kB\n\
                 Buffers:               0 kB\nCached:                0 kB\nSwapCached:            0 kB\n\
                 SwapTotal:             0 kB\nSwapFree:              0 kB\nShmem:                 0 kB\n"
            );
        }
        ProcFile::Uptime => {
            let ms = time::monotonic_ns() / 1_000_000;
            let _ = writeln!(s, "{}.{:02} {}.{:02}", ms / 1000, ms % 1000 / 10, ms / 1000, ms % 1000 / 10);
        }
        ProcFile::Loadavg => {
            let _ = writeln!(s, "0.00 0.00 0.00 1/{} {}", p.threads.len(), p.next_tid - 1);
        }
        ProcFile::Version => {
            let _ = writeln!(s, "Linux version {RELEASE} (grix) {VERSION}");
        }
        ProcFile::RandomUuid => uuid(&mut s, None),
        ProcFile::BootId => uuid(&mut s, Some(time::boot_id())),
        ProcFile::CgroupMemoryMax => {
            let (total, _) = frame::stats();
            let _ = writeln!(s, "{}", total * 4096);
        }
    }
    s.into_bytes()
}

fn comm(p: &Process) -> String {
    let n = p.name.iter().position(|&b| b == 0).unwrap_or(p.name.len());
    if n > 0 {
        return String::from_utf8_lossy(&p.name[..n]).into_owned();
    }
    let base = p.exe.rsplit('/').next().unwrap_or("");
    base.chars().take(15).collect()
}

/// (virtual size, resident) in pages.
fn mem_pages(p: &Process) -> (u64, u64) {
    let size: u64 = p.aspace.vmas().map(|v| (v.end - v.start) / 4096).sum();
    let (_, used) = frame::stats();
    (size, used)
}

fn root_mode(p: &Process) -> &'static str {
    if p.policy.allows(grix_abi::policy::Capability::FsWrite) { "rw" } else { "ro" }
}

fn maps(p: &Process, s: &mut String) {
    let fs = fs::lock();
    for v in p.aspace.vmas() {
        let perms = [(v.prot.read || v.prot.write || v.prot.exec, 'r'), (v.prot.write, 'w'), (v.prot.exec, 'x')];
        let mut flags = String::new();
        for (on, c) in perms {
            flags.push(if on { c } else { '-' });
        }
        flags.push('p');
        let (offset, inode, name) = match v.backing {
            Backing::File { offset, ino, .. } | Backing::Data { offset, ino, .. } => {
                (offset, ino as u64 + 1, fs.path_of(ino))
            }
            Backing::Anon if v.start == p.aspace.brk_start && v.start < p.aspace.brk => (0, 0, "[heap]".into()),
            Backing::Anon if v.end == STACK_TOP => (0, 0, "[stack]".into()),
            // What Linux calls the page holding the signal-return code on arm32.
            Backing::Sigpage => (0, 0, "[sigpage]".into()),
            Backing::Anon => (0, 0, String::new()),
        };
        let dev = if inode == 0 { "00:00" } else { "00:01" };
        let _ = writeln!(s, "{:08x}-{:08x} {flags} {offset:08x} {dev} {inode:<10} {name}", v.start, v.end);
    }
}

fn status(p: &Process, s: &mut String) {
    let (size, rss) = mem_pages(p);
    let (blocked, pending) = p.threads.get(&p.current).map_or((0, 0), |t| (t.sigmask, t.pending.mask));
    let ignored: u64 = (1..=64).filter(|&i| p.sigactions[i].handler == 1).map(|i| 1u64 << (i - 1)).sum();
    let caught: u64 = (1..=64).filter(|&i| p.sigactions[i].handler > 1).map(|i| 1u64 << (i - 1)).sum();
    let (u, g) = (p.uid, p.gid);
    let _ = write!(
        s,
        "Name:\t{}\nUmask:\t{:04o}\nState:\tR (running)\nTgid:\t{PID}\nNgid:\t0\nPid:\t{PID}\nPPid:\t0\n\
         TracerPid:\t0\nUid:\t{u}\t{u}\t{u}\t{u}\nGid:\t{g}\t{g}\t{g}\t{g}\nFDSize:\t{}\nGroups:\t{g}\n\
         VmPeak:\t{:8} kB\nVmSize:\t{:8} kB\nVmRSS:\t{:8} kB\nThreads:\t{}\nSigQ:\t0/0\n\
         SigPnd:\t{pending:016x}\nShdPnd:\t{:016x}\nSigBlk:\t{blocked:016x}\nSigIgn:\t{ignored:016x}\n\
         SigCgt:\t{caught:016x}\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n\
         CapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\n\
         NoNewPrivs:\t1\nSeccomp:\t0\nCpus_allowed:\t1\nCpus_allowed_list:\t0\n",
        comm(p),
        p.umask,
        p.fds.len(),
        size * 4,
        size * 4,
        rss * 4,
        p.threads.len(),
        p.shared_pending.mask,
    );
}

fn stat(p: &Process, s: &mut String) {
    let (size, rss) = mem_pages(p);
    let ticks = time::monotonic_ns() / 10_000_000;
    let _ = writeln!(
        s,
        "{PID} ({}) R 0 {PID} {PID} 0 -1 4194560 0 0 0 0 {ticks} 0 0 0 20 0 {} 0 0 {} {rss} \
         18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
        comm(p),
        p.threads.len(),
        size * 4096,
    );
}

fn limits(p: &Process, s: &mut String) {
    const NAMES: [(&str, &str); 16] = [
        ("Max cpu time", "seconds"),
        ("Max file size", "bytes"),
        ("Max data size", "bytes"),
        ("Max stack size", "bytes"),
        ("Max core file size", "bytes"),
        ("Max resident set", "bytes"),
        ("Max processes", "processes"),
        ("Max open files", "files"),
        ("Max locked memory", "bytes"),
        ("Max address space", "bytes"),
        ("Max file locks", "locks"),
        ("Max pending signals", "signals"),
        ("Max msgqueue size", "bytes"),
        ("Max nice priority", ""),
        ("Max realtime priority", ""),
        ("Max realtime timeout", "us"),
    ];
    let _ = writeln!(s, "{:<26}{:<21}{:<21}{:<10}", "Limit", "Soft Limit", "Hard Limit", "Units");
    let fmt = |v: u64| if v == u64::MAX { String::from("unlimited") } else { format!("{v}") };
    for (i, (name, unit)) in NAMES.iter().enumerate() {
        let (cur, max) = p.rlimits[i];
        let _ = writeln!(s, "{name:<26}{:<21}{:<21}{unit:<10}", fmt(cur), fmt(max));
    }
}

fn cpuinfo(s: &mut String) {
    const NAMES: [&str; 22] = [
        "fp", "asimd", "evtstrm", "aes", "pmull", "sha1", "sha2", "crc32", "atomics", "fphp", "asimdhp", "cpuid",
        "asimdrdm", "jscvt", "fcma", "lrcpc", "dcpop", "sha3", "sm3", "sm4", "asimddp", "sha512",
    ];
    let hw = arch::hwcap();
    let features: Vec<&str> = NAMES.iter().enumerate().filter(|(i, _)| hw & (1 << i) != 0).map(|(_, n)| *n).collect();
    let midr = arch::midr();
    let bogomips = arch::counter_freq() * 2 / 10_000;
    let _ = write!(
        s,
        "processor\t: 0\nBogoMIPS\t: {}.{:02}\nFeatures\t: {}\nCPU implementer\t: {:#04x}\n\
         CPU architecture: 8\nCPU variant\t: {:#x}\nCPU part\t: {:#05x}\nCPU revision\t: {}\n\n",
        bogomips / 100,
        bogomips % 100,
        features.join(" "),
        (midr >> 24) & 0xff,
        (midr >> 20) & 0xf,
        (midr >> 4) & 0xfff,
        midr & 0xf,
    );
}

/// A version-4 UUID: fresh random, or derived from `seed`.
fn uuid(s: &mut String, seed: Option<[u8; 16]>) {
    let mut b = seed.unwrap_or_else(|| {
        let mut b = [0u8; 16];
        crate::rng::fill(&mut b);
        b
    });
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    for (i, x) in b.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        let _ = write!(s, "{x:02x}");
    }
    s.push('\n');
}

/// `readlink("/proc/self/fd/N")`: what the descriptor refers to.
pub fn fd_link(kind: &FileKind, fd: u64) -> String {
    match kind {
        FileKind::Stdin | FileKind::Stdout | FileKind::Stderr => format!("pipe:[{}]", 0x1000_0000 + fd),
        FileKind::Node(ino) | FileKind::Dev(_, ino) => fs::lock().path_of(*ino),
        FileKind::Generated(_) => String::from("/proc/self/generated"),
        FileKind::Pipe(end) => format!("pipe:[{}]", alloc::sync::Arc::as_ptr(&end.pipe) as u64 & 0xffff_ffff),
        FileKind::Socket(_) => format!("socket:[{}]", 0x3000_0000 + fd),
        FileKind::EventFd(_) => String::from("anon_inode:[eventfd]"),
        FileKind::Epoll(_) => String::from("anon_inode:[eventpoll]"),
        FileKind::Inotify(_) => String::from("anon_inode:inotify"),
    }
}

/// Which descriptor a path names, if it is `/proc/self/fd/N` or an alias of it.
pub fn fd_path(path: &str) -> Option<u64> {
    let rest = ["/proc/self/fd/", "/proc/1/fd/", "/proc/thread-self/fd/", "/dev/fd/"]
        .iter()
        .find_map(|prefix| path.strip_prefix(prefix))
        .or(match path {
            "/dev/stdin" => Some("0"),
            "/dev/stdout" => Some("1"),
            "/dev/stderr" => Some("2"),
            _ => None,
        })?;
    rest.trim_end_matches('/').parse().ok()
}
