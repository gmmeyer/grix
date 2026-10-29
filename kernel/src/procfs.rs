//! Synthetic /proc and /sys files. Contents are generated from live kernel
//! state each time a file is opened, like Linux's procfs.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use crate::arch;
use crate::errno::{EINVAL, ENOENT, Errno};
use crate::fd::FileKind;
use crate::fs;
use crate::mm::aspace::{Backing, STACK_TOP, VVAR};
use crate::mm::frame;
use crate::process::{Ids, Process};
use crate::procs::Zombie;
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
    Auxv,
    Comm,
    Limits,
    Mountinfo,
    Mounts,
    // /proc/...
    Cpuinfo,
    /// 0-(n-1), the CPUs.
    CpuList,
    CgroupCpuMax,
    ProcStat,
    Meminfo,
    Vmstat,
    /// /proc/sys/fs/file-nr and file-max.
    FileNr,
    FileMax,
    InodeNr,
    /// /sys/devices/system/cpu/cpuN/topology/core_id.
    CoreId(u32),
    Uptime,
    Loadavg,
    Version,
    RandomUuid,
    BootId,
    // /sys/fs/cgroup/...
    CgroupMemoryMax,
}

/// Each process's directory, /proc/<pid> (made at fork, gone once it has
/// ended and been reaped; `/proc/self` is the caller's): these files,
/// `fd/`, and the `exe`, `cwd` and `root` links.
pub const PID_FILES: &[(&str, ProcFile)] = &[
    ("maps", ProcFile::Maps),
    ("status", ProcFile::Status),
    ("stat", ProcFile::Stat),
    ("statm", ProcFile::Statm),
    ("cmdline", ProcFile::Cmdline),
    ("environ", ProcFile::Environ),
    ("auxv", ProcFile::Auxv),
    ("comm", ProcFile::Comm),
    ("limits", ProcFile::Limits),
    ("mountinfo", ProcFile::Mountinfo),
    ("mounts", ProcFile::Mounts),
    ("cgroup", ProcFile::Text("0::/\n")),
    ("oom_score_adj", ProcFile::Text("0\n")),
];

/// The other files to create, by path.
pub const FILES: &[(&str, ProcFile)] = &[
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
    ("/proc/sys/vm/mmap_min_addr", ProcFile::Text("65536\n")), // syscall::mem::MMAP_MIN_ADDR
    ("/proc/sys/fs/file-max", ProcFile::FileMax),
    ("/proc/sys/fs/file-nr", ProcFile::FileNr),
    ("/proc/sys/fs/inode-nr", ProcFile::InodeNr),
    ("/proc/sys/fs/nr_open", ProcFile::Text("1024\n")),
    // Linux 6.1's last capability, CAP_CHECKPOINT_RESTORE (libcap and Go's
    // capability packages read it).
    ("/proc/sys/kernel/cap_last_cap", ProcFile::Text("40\n")),
    ("/proc/vmstat", ProcFile::Vmstat),
    // No block devices.
    ("/proc/diskstats", ProcFile::Text("")),
    ("/proc/partitions", ProcFile::Text("major minor  #blocks  name\n\n")),
    ("/proc/sys/net/core/somaxconn", ProcFile::Text("4096\n")),
    // The only interface is lo (see netlink.rs).
    (
        "/proc/net/dev",
        ProcFile::Text(
            "Inter-|   Receive                                                |  Transmit\n \
             face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    \
             lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n",
        ),
    ),
    ("/proc/net/if_inet6", ProcFile::Text("00000000000000000000000000000001 01 80 10 80       lo\n")),
    // lo as sysfs shows it (as netlink.rs describes it).
    ("/sys/class/net/lo/address", ProcFile::Text("00:00:00:00:00:00\n")),
    ("/sys/class/net/lo/addr_len", ProcFile::Text("6\n")),
    ("/sys/class/net/lo/carrier", ProcFile::Text("1\n")),
    ("/sys/class/net/lo/flags", ProcFile::Text("0x9\n")),
    ("/sys/class/net/lo/ifindex", ProcFile::Text("1\n")),
    ("/sys/class/net/lo/mtu", ProcFile::Text("65536\n")),
    ("/sys/class/net/lo/operstate", ProcFile::Text("unknown\n")),
    ("/sys/class/net/lo/type", ProcFile::Text("772\n")),
    ("/sys/devices/system/cpu/online", ProcFile::CpuList),
    ("/sys/devices/system/cpu/possible", ProcFile::CpuList),
    ("/sys/devices/system/cpu/present", ProcFile::CpuList),
    ("/sys/kernel/mm/transparent_hugepage/enabled", ProcFile::Text("always madvise [never]\n")),
    ("/sys/kernel/mm/transparent_hugepage/hpage_pmd_size", ProcFile::Text("2097152\n")),
    ("/sys/fs/cgroup/cgroup.controllers", ProcFile::Text("cpu memory pids\n")),
    ("/sys/fs/cgroup/cpu.max", ProcFile::CgroupCpuMax),
    ("/sys/fs/cgroup/memory.max", ProcFile::CgroupMemoryMax),
    ("/sys/fs/cgroup/pids.max", ProcFile::Text("1024\n")),
];

pub fn generate(p: &Process, f: ProcFile) -> Vec<u8> {
    let mut s = String::new();
    match f {
        ProcFile::Text(t) => s.push_str(t),
        ProcFile::Maps => maps(p, &mut s),
        ProcFile::Status => status(&shown(p), &mut s),
        ProcFile::Stat => stat(&shown(p), &mut s),
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
        // Go's golang.org/x/sys/cpu reads this when it can't get the
        // vector from its runtime, and otherwise reads the ID registers.
        ProcFile::Auxv => return p.auxv.iter().flat_map(|w| w.to_le_bytes()).collect(),
        ProcFile::Comm => {
            let _ = writeln!(s, "{}", comm(p));
        }
        ProcFile::Limits => limits(&p.rlimits, &mut s),
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
        ProcFile::Cpuinfo => arch::cpuinfo(&mut s, crate::smp::count()),
        ProcFile::CpuList => {
            let n = crate::smp::count();
            let _ = if n == 1 { writeln!(s, "0") } else { writeln!(s, "0-{}", n - 1) };
        }
        // As many CPUs' worth of time per period as there are.
        ProcFile::CgroupCpuMax => {
            let _ = writeln!(s, "{} 100000", crate::smp::count() * 100_000);
        }
        ProcFile::ProcStat => {
            let ticks = time::monotonic_ns() / 10_000_000;
            let n = crate::smp::count();
            let _ = writeln!(s, "cpu  {} 0 0 0 0 0 0 0 0 0", ticks * n as u64);
            for i in 0..n {
                let _ = writeln!(s, "cpu{i} {ticks} 0 0 0 0 0 0 0 0 0");
            }
            let _ = write!(
                s,
                "intr 0\nctxt 0\nbtime {}\nprocesses 1\nprocs_running 1\nprocs_blocked 0\n",
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
                 Active:         {used:8} kB\nInactive:              0 kB\n\
                 SwapTotal:             0 kB\nSwapFree:              0 kB\nShmem:                 0 kB\n",
                used = total - free
            );
        }
        // No swap and no block devices: their counters stay at 0.
        ProcFile::Vmstat => {
            let (total, used) = frame::stats();
            let _ = write!(
                s,
                "nr_free_pages {}\nnr_dirty 0\nnr_writeback 0\npgpgin 0\npgpgout 0\npswpin 0\npswpout 0\n\
                 oom_kill 0\n",
                total - used
            );
        }
        // Allocated, unused (always 0 since 2.6), most.
        ProcFile::FileNr => {
            let _ = writeln!(s, "{}\t0\t{}", crate::fd::open_files(), crate::fd::MAX_OPEN_FILES);
        }
        ProcFile::FileMax => {
            let _ = writeln!(s, "{}", crate::fd::MAX_OPEN_FILES);
        }
        ProcFile::InodeNr => {
            let _ = writeln!(s, "{}\t0", fs::lock().node_count());
        }
        ProcFile::CoreId(cpu) => {
            let _ = writeln!(s, "{cpu}");
        }
        ProcFile::Uptime => {
            let ms = time::monotonic_ns() / 1_000_000;
            let _ = writeln!(s, "{}.{:02} {}.{:02}", ms / 1000, ms % 1000 / 10, ms / 1000, ms % 1000 / 10);
        }
        ProcFile::Loadavg => {
            let _ = writeln!(s, "0.00 0.00 0.00 1/{} {}", p.threads.len(), crate::process::new_tid() - 1);
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

/// What /proc/<pid> still shows of a process that has ended, until it's
/// reaped (`procs::Zombie`): what Linux keeps of a zombie, its name,
/// credentials, signal state, limits and times. Its memory, descriptors,
/// filesystem context and mount namespace went when it exited (Linux's
/// `exit_mm`, `exit_files`, `exit_fs`, `exit_task_namespaces`).
pub struct Remains {
    comm: String,
    uid: u32,
    gid: u32,
    ids: Ids,
    blocked: u64,
    ignored: u64,
    caught: u64,
    rlimits: [(u64, u64); 16],
    /// CPU time of the children it reaped (`Zombie::cpu_ns` has its own too).
    children_ns: u64,
}

impl Remains {
    pub fn of(p: &Process) -> Remains {
        let (ignored, caught) = dispositions(p);
        Remains {
            comm: comm(p),
            uid: p.uid,
            gid: p.gid,
            ids: p.ids.clone(),
            blocked: p.threads.get(&p.current).map_or(0, |t| t.sigmask),
            ignored,
            caught,
            rlimits: p.rlimits,
            children_ns: p.children_cpu_ns,
        }
    }
}

/// A zombie's /proc/<pid> file, as `reader` sees it: what Linux's procfs
/// gives for a task without memory, files or namespaces.
pub fn generate_zombie(reader: &Process, pid: u32, z: &Zombie, f: ProcFile) -> Result<Vec<u8>, Errno> {
    let r = &z.remains;
    let mut s = String::new();
    match f {
        ProcFile::Text(t) => s.push_str(t),
        ProcFile::Status | ProcFile::Stat => {
            // Its exit code is for those ptrace would let look (do_task_stat).
            let permitted = crate::procs::may_inspect_creds(reader, r.uid, r.gid, &r.ids, false);
            let sh = Shown {
                pid,
                ppid: z.ppid,
                pgid: z.pgid,
                sid: z.sid,
                comm: r.comm.clone(),
                state: "Z (zombie)",
                umask: None,
                uid: r.uid,
                gid: r.gid,
                ids: &r.ids,
                fds: 0,
                mem: None,
                // The thread group's leader, until it's reaped.
                threads: 1,
                pending: 0,
                shared_pending: 0,
                blocked: r.blocked,
                ignored: r.ignored,
                caught: r.caught,
                cpu_ns: z.cpu_ns - r.children_ns,
                children_ns: r.children_ns,
                flags: PF_DEFAULT | PF_EXITING,
                exit_code: if permitted { z.status } else { 0 },
            };
            if f == ProcFile::Status { status(&sh, &mut s) } else { stat(&sh, &mut s) }
        }
        // No memory: no mappings, arguments or environment (they read empty).
        ProcFile::Maps | ProcFile::Cmdline | ProcFile::Environ => {}
        ProcFile::Statm => s.push_str("0 0 0 0 0 0 0\n"),
        ProcFile::Comm => {
            let _ = writeln!(s, "{}", r.comm);
        }
        ProcFile::Limits => limits(&r.rlimits, &mut s),
        // No mount namespace: Linux's mounts_open_common fails.
        ProcFile::Mountinfo | ProcFile::Mounts => return Err(EINVAL),
        // Not a /proc/<pid> file.
        _ => return Err(ENOENT),
    }
    Ok(s.into_bytes())
}

/// Signals ignored and caught, as /proc shows them (bit n-1 for signal n).
fn dispositions(p: &Process) -> (u64, u64) {
    let acts = p.sigactions.get();
    let ignored: u64 = (1..=64).filter(|&i| acts[i].handler == 1).map(|i| 1u64 << (i - 1)).sum();
    let caught: u64 = (1..=64).filter(|&i| acts[i].handler > 1).map(|i| 1u64 << (i - 1)).sum();
    (ignored, caught)
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
        let shared = matches!(v.backing, Backing::Shared { .. } | Backing::SharedFile { .. }) || v.is_shared_file();
        flags.push(if shared { 's' } else { 'p' });
        let (offset, inode, name) = match v.backing {
            Backing::File { offset, ino, .. }
            | Backing::Data { offset, ino, .. }
            | Backing::SharedFile { offset, ino, .. } => (offset, fs.ino_number(ino), fs.path_of(ino)),
            Backing::Anon if v.start == p.aspace.brk_start && v.start < p.aspace.brk => (0, 0, "[heap]".into()),
            Backing::Anon if v.end == STACK_TOP => (0, 0, "[stack]".into()),
            // What Linux calls the page holding the signal-return code on arm32.
            Backing::Sigpage => (0, 0, "[sigpage]".into()),
            Backing::KernelPage(_) if v.start == VVAR => (0, 0, "[vvar]".into()),
            Backing::KernelPage(_) => (0, 0, "[vdso]".into()),
            Backing::Anon => (0, 0, String::new()),
            Backing::Shared { index, .. } => (index * 4096, 0, "/dev/zero (deleted)".into()),
        };
        let dev = if inode == 0 { "00:00" } else { "00:01" };
        let _ = writeln!(s, "{:08x}-{:08x} {flags} {offset:08x} {dev} {inode:<10} {name}", v.start, v.end);
    }
}

/// What status and stat show of a process, live or a zombie.
struct Shown<'a> {
    pid: u32,
    ppid: u32,
    pgid: u32,
    sid: u32,
    comm: String,
    state: &'static str,
    /// None without a filesystem context (a zombie).
    umask: Option<u32>,
    uid: u32,
    gid: u32,
    ids: &'a Ids,
    fds: usize,
    /// (virtual size, resident) in pages; None without memory (a zombie).
    mem: Option<(u64, u64)>,
    threads: usize,
    pending: u64,
    shared_pending: u64,
    blocked: u64,
    ignored: u64,
    caught: u64,
    cpu_ns: u64,
    children_ns: u64,
    flags: u64,
    exit_code: i32,
}

/// The task flags stat shows (PF_RANDOMIZE | PF_SUPERPRIV), and the one
/// an exiting task gets.
const PF_DEFAULT: u64 = 0x40_0100;
const PF_EXITING: u64 = 0x4;

fn shown(p: &Process) -> Shown<'_> {
    let (blocked, pending) = p.threads.get(&p.current).map_or((0, 0), |t| (t.sigmask, t.pending.mask));
    let (ignored, caught) = dispositions(p);
    Shown {
        pid: p.pid,
        ppid: p.ppid,
        pgid: p.pgid,
        sid: p.sid,
        comm: comm(p),
        state: state(p),
        umask: Some(p.umask()),
        uid: p.uid,
        gid: p.gid,
        ids: &p.ids,
        fds: p.fds.len(),
        mem: Some(mem_pages(p)),
        threads: p.threads.len(),
        pending,
        shared_pending: p.shared_pending.mask,
        blocked,
        ignored,
        caught,
        cpu_ns: p.process_cpu_ns(),
        children_ns: p.children_cpu_ns,
        flags: PF_DEFAULT,
        exit_code: 0,
    }
}

/// As Linux's proc_pid_status lays it out: without a filesystem context
/// there's no Umask line, and without memory no Vm lines.
fn status(sh: &Shown, s: &mut String) {
    let ids = sh.ids;
    let (ru, u, su) = (ids.ruid, sh.uid, ids.suid);
    let (rg, g, sg) = (ids.rgid, sh.gid, ids.sgid);
    let groups = ids.groups.iter().map(|g| alloc::format!("{g}")).collect::<alloc::vec::Vec<_>>().join(" ");
    let (pid, ppid) = (sh.pid, sh.ppid);
    let _ = writeln!(s, "Name:\t{}", sh.comm);
    if let Some(umask) = sh.umask {
        let _ = writeln!(s, "Umask:\t{umask:04o}");
    }
    let _ = write!(
        s,
        "State:\t{}\nTgid:\t{pid}\nNgid:\t0\nPid:\t{pid}\nPPid:\t{ppid}\n\
         TracerPid:\t0\nUid:\t{ru}\t{u}\t{su}\t{u}\nGid:\t{rg}\t{g}\t{sg}\t{g}\nFDSize:\t{}\nGroups:\t{groups}\n",
        sh.state, sh.fds,
    );
    if let Some((size, rss)) = sh.mem {
        let _ = write!(s, "VmPeak:\t{:8} kB\nVmSize:\t{:8} kB\nVmRSS:\t{:8} kB\n", size * 4, size * 4, rss * 4);
    }
    let _ = write!(
        s,
        "Threads:\t{}\nSigQ:\t0/0\n\
         SigPnd:\t{:016x}\nShdPnd:\t{:016x}\nSigBlk:\t{:016x}\nSigIgn:\t{:016x}\n\
         SigCgt:\t{:016x}\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n\
         CapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\n\
         NoNewPrivs:\t1\nSeccomp:\t0\nCpus_allowed:\t1\nCpus_allowed_list:\t0\n",
        sh.threads, sh.pending, sh.shared_pending, sh.blocked, sh.ignored, sh.caught,
    );
}

/// Stopped, running (the caller), or waiting for its turn or for something.
fn state(p: &Process) -> &'static str {
    if p.stopped {
        "T (stopped)"
    } else if p.pid == crate::process::current_pid() {
        "R (running)"
    } else {
        "S (sleeping)"
    }
}

fn stat(sh: &Shown, s: &mut String) {
    let (size, rss) = sh.mem.unwrap_or((0, 0));
    // utime and cutime, in clock ticks (all CPU time counts as user time).
    let (ticks, cticks) = (sh.cpu_ns / 10_000_000, sh.children_ns / 10_000_000);
    let (pid, ppid, pgrp, sid, flags) = (sh.pid, sh.ppid, sh.pgid, sh.sid, sh.flags);
    let _ = writeln!(
        s,
        "{pid} ({}) {} {ppid} {pgrp} {sid} 0 -1 {flags} 0 0 0 0 {ticks} 0 {cticks} 0 20 0 {} 0 0 {} {rss} \
         18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 {}",
        sh.comm,
        &sh.state[..1],
        sh.threads,
        size * 4096,
        sh.exit_code,
    );
}

fn limits(rlimits: &[(u64, u64); 16], s: &mut String) {
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
        let (cur, max) = rlimits[i];
        let _ = writeln!(s, "{name:<26}{:<21}{:<21}{unit:<10}", fmt(cur), fmt(max));
    }
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
        FileKind::Pty(end) => fs::lock().path_of(end.ino),
        FileKind::Generated(_) => String::from("/proc/self/generated"),
        FileKind::Pipe(end) => format!("pipe:[{}]", alloc::sync::Arc::as_ptr(&end.pipe) as u64 & 0xffff_ffff),
        FileKind::Socket(_) => format!("socket:[{}]", 0x3000_0000 + fd),
        FileKind::EventFd(_) => String::from("anon_inode:[eventfd]"),
        FileKind::Epoll(_) => String::from("anon_inode:[eventpoll]"),
        FileKind::Inotify(_) => String::from("anon_inode:inotify"),
        FileKind::TimerFd(_) => String::from("anon_inode:[timerfd]"),
        FileKind::SignalFd(_) => String::from("anon_inode:[signalfd]"),
        FileKind::PidFd(_) => String::from("anon_inode:[pidfd]"),
        FileKind::Netlink(_) | FileKind::UnixUnbound(_) | FileKind::Inet(_) | FileKind::Unix(_) => {
            alloc::format!("socket:[{}]", 0x3000_0000 + fd)
        }
    }
}

/// Another process's descriptor, `/proc/<pid>/fd/N`.
pub fn other_fd_path(path: &str) -> Option<(u32, u64)> {
    let (pid, fd) = path.strip_prefix("/proc/")?.split_once("/fd/")?;
    let pid: u32 = pid.parse().ok()?;
    let fd = fd.trim_end_matches('/').parse().ok()?;
    (pid != crate::process::current_pid()).then_some((pid, fd))
}

/// Which descriptor a path names, if it is `/proc/self/fd/N` or an alias of it.
pub fn fd_path(path: &str) -> Option<u64> {
    let mine = alloc::format!("/proc/{}/fd/", crate::process::current_pid());
    let rest = ["/proc/self/fd/", mine.as_str(), "/proc/thread-self/fd/", "/dev/fd/"]
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
