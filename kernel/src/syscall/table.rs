//! Linux AArch64 syscall numbers, names, and the capability each one needs.

use grix_abi::policy::Capability;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    /// Always available.
    Core,
    /// Needs a capability.
    Cap(Capability),
    /// Never available inside the sandbox (mount, ptrace, module loading, ...).
    Privileged,
}

use Capability::*;
use Gate::*;

macro_rules! syscalls {
    ($($nr:literal $name:ident $gate:expr;)*) => {
        #[allow(non_upper_case_globals, dead_code)]
        pub mod nr {
            $(pub const $name: u32 = $nr;)*
        }

        pub fn info(n: u32) -> (&'static str, Gate) {
            match n {
                $($nr => (stringify!($name), $gate),)*
                _ => ("unknown", Core),
            }
        }
    };
}

syscalls! {
    5 setxattr Cap(FsWrite);
    6 lsetxattr Cap(FsWrite);
    7 fsetxattr Cap(FsWrite);
    8 getxattr Core;
    9 lgetxattr Core;
    10 fgetxattr Core;
    11 listxattr Core;
    12 llistxattr Core;
    13 flistxattr Core;
    14 removexattr Cap(FsWrite);
    15 lremovexattr Cap(FsWrite);
    16 fremovexattr Cap(FsWrite);
    17 getcwd Core;
    19 eventfd2 Core;
    20 epoll_create1 Core;
    21 epoll_ctl Core;
    22 epoll_pwait Core;
    23 dup Core;
    24 dup3 Core;
    25 fcntl Core;
    26 inotify_init1 Core;
    27 inotify_add_watch Core;
    28 inotify_rm_watch Core;
    29 ioctl Core;
    32 flock Core;
    33 mknodat Cap(FsWrite);
    34 mkdirat Cap(FsWrite);
    35 unlinkat Cap(FsWrite);
    36 symlinkat Cap(FsWrite);
    37 linkat Cap(FsWrite);
    38 renameat Cap(FsWrite);
    39 umount2 Privileged;
    40 mount Privileged;
    41 pivot_root Privileged;
    43 statfs Core;
    44 fstatfs Core;
    45 truncate Cap(FsWrite);
    46 ftruncate Core; // acts on an fd already opened for writing (which needed fs_write, or is a memfd)
    47 fallocate Core; // like ftruncate
    48 faccessat Core;
    49 chdir Core;
    50 fchdir Core;
    51 chroot Privileged;
    52 fchmod Cap(FsWrite);
    53 fchmodat Cap(FsWrite);
    54 fchownat Cap(FsWrite);
    55 fchown Cap(FsWrite);
    56 openat Core;
    57 close Core;
    59 pipe2 Core;
    60 quotactl Privileged;
    61 getdents64 Core;
    62 lseek Core;
    63 read Core;
    64 write Core;
    65 readv Core;
    66 writev Core;
    67 pread64 Core;
    68 pwrite64 Core;
    69 preadv Core;
    70 pwritev Core;
    71 sendfile Core;
    72 pselect6 Core;
    73 ppoll Core;
    78 readlinkat Core;
    79 newfstatat Core;
    80 fstat Core;
    81 sync Core;
    82 fsync Core;
    83 fdatasync Core;
    88 utimensat Cap(FsWrite);
    89 acct Privileged;
    90 capget Core;
    91 capset Privileged;
    92 personality Core;
    93 exit Core;
    94 exit_group Core;
    95 waitid Cap(Process);
    96 set_tid_address Core;
    97 unshare Privileged;
    98 futex Core;
    99 set_robust_list Core;
    100 get_robust_list Core;
    101 nanosleep Core;
    74 signalfd4 Core;
    85 timerfd_create Core;
    86 timerfd_settime Core;
    87 timerfd_gettime Core;
    102 getitimer Core;
    103 setitimer Core;
    104 kexec_load Privileged;
    105 init_module Privileged;
    106 delete_module Privileged;
    107 timer_create Core;
    108 timer_gettime Core;
    109 timer_getoverrun Core;
    110 timer_settime Core;
    111 timer_delete Core;
    112 clock_settime Privileged;
    113 clock_gettime Core;
    114 clock_getres Core;
    115 clock_nanosleep Core;
    116 syslog Privileged;
    117 ptrace Privileged;
    118 sched_setparam Core;
    119 sched_setscheduler Core;
    120 sched_getscheduler Core;
    121 sched_getparam Core;
    122 sched_setaffinity Core;
    123 sched_getaffinity Core;
    124 sched_yield Core;
    129 kill Core;
    130 tkill Core;
    131 tgkill Core;
    132 sigaltstack Core;
    133 rt_sigsuspend Core;
    134 rt_sigaction Core;
    135 rt_sigprocmask Core;
    136 rt_sigpending Core;
    137 rt_sigtimedwait Core;
    138 rt_sigqueueinfo Core;
    139 rt_sigreturn Core;
    140 setpriority Core;
    141 getpriority Core;
    142 reboot Privileged;
    143 setregid Core; // no-op to the current id, else EPERM
    144 setgid Core; // no-op to the current id, else EPERM
    145 setreuid Core; // no-op to the current id, else EPERM
    146 setuid Core; // no-op to the current id, else EPERM
    147 setresuid Core; // no-op to the current id, else EPERM
    148 getresuid Core;
    149 setresgid Core; // no-op to the current id, else EPERM
    150 getresgid Core;
    153 times Core;
    154 setpgid Cap(Process);
    155 getpgid Core;
    156 getsid Core;
    157 setsid Cap(Process);
    158 getgroups Core;
    159 setgroups Privileged;
    160 uname Core;
    161 sethostname Privileged;
    162 setdomainname Privileged;
    163 getrlimit Core;
    164 setrlimit Core;
    165 getrusage Core;
    166 umask Core;
    167 prctl Core;
    168 getcpu Core;
    169 gettimeofday Core;
    170 settimeofday Privileged;
    172 getpid Core;
    173 getppid Core;
    174 getuid Core;
    175 geteuid Core;
    176 getgid Core;
    177 getegid Core;
    178 gettid Core;
    179 sysinfo Core;
    198 socket Core; // gated by family: netlink route sockets only know `lo`; see net.rs
    199 socketpair Core; // AF_UNIX pairs are local IPC; others need `net`
    200 bind Core; // acts on existing sockets (netlink port ids); see net.rs
    201 listen Core; // acts on existing sockets; see net.rs
    202 accept Core; // acts on existing sockets; see net.rs
    203 connect Core; // acts on existing sockets; see net.rs
    204 getsockname Core; // acts on existing sockets; see net.rs
    205 getpeername Core; // acts on existing sockets; see net.rs
    206 sendto Core; // acts on existing sockets; see net.rs
    207 recvfrom Core; // acts on existing sockets; see net.rs
    208 setsockopt Core; // acts on existing sockets; see net.rs
    209 getsockopt Core; // acts on existing sockets; see net.rs
    210 shutdown Core; // acts on existing sockets; see net.rs
    211 sendmsg Core; // acts on existing sockets; see net.rs
    212 recvmsg Core; // acts on existing sockets; see net.rs
    214 brk Core;
    215 munmap Core;
    216 mremap Core;
    217 add_key Privileged;
    218 request_key Privileged;
    219 keyctl Privileged;
    220 clone Core; // gated by flags: threads vs process
    221 execve Cap(Process);
    222 mmap Core;
    223 fadvise64 Core;
    224 swapon Privileged;
    225 swapoff Privileged;
    226 mprotect Core;
    227 msync Core;
    228 mlock Core;
    229 munlock Core;
    230 mlockall Core;
    231 munlockall Core;
    232 mincore Core;
    233 madvise Core;
    240 rt_tgsigqueueinfo Core;
    241 perf_event_open Privileged;
    242 accept4 Core; // acts on existing sockets; see net.rs
    243 recvmmsg Cap(Net);
    260 wait4 Cap(Process);
    261 prlimit64 Core;
    268 setns Privileged;
    269 sendmmsg Cap(Net);
    270 process_vm_readv Privileged;
    271 process_vm_writev Privileged;
    272 kcmp Privileged;
    273 finit_module Privileged;
    276 renameat2 Cap(FsWrite);
    277 seccomp Core;
    278 getrandom Core;
    279 memfd_create Core;
    280 bpf Privileged;
    281 execveat Cap(Process);
    282 userfaultfd Privileged;
    283 membarrier Core;
    284 mlock2 Core;
    285 copy_file_range Core;
    291 statx Core;
    293 rseq Core;
    424 pidfd_send_signal Cap(Process);
    425 io_uring_setup Core;
    434 pidfd_open Cap(Process);
    435 clone3 Core; // gated by flags: threads vs process
    436 close_range Core;
    437 openat2 Core;
    439 faccessat2 Core;
    441 epoll_pwait2 Core;
}
