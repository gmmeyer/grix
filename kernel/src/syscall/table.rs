//! Linux syscall numbers (the architecture's), names, and the capability
//! each one needs.

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

#[cfg(target_arch = "aarch64")]
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
    143 setregid Core; // Linux's rules; ids mean nothing outside the sandbox
    144 setgid Core;
    145 setreuid Core;
    146 setuid Core;
    147 setresuid Core;
    148 getresuid Core;
    149 setresgid Core;
    150 getresgid Core;
    151 setfsuid Core;
    152 setfsgid Core;
    153 times Core;
    154 setpgid Cap(Process);
    155 getpgid Core;
    156 getsid Core;
    157 setsid Cap(Process);
    158 getgroups Core;
    159 setgroups Core; // uid 0 only, as on Linux
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
    243 recvmmsg Core; // acts on existing sockets, like recvmsg
    260 wait4 Cap(Process);
    261 prlimit64 Core;
    268 setns Privileged;
    269 sendmmsg Core; // acts on existing sockets, like sendmsg
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
    438 pidfd_getfd Cap(Process);
    436 close_range Core;
    437 openat2 Core;
    439 faccessat2 Core;
    441 epoll_pwait2 Core;
}

// Linux x86_64 (arch/x86/entry/syscalls/syscall_64.tbl): the same calls, and
// the older ones arm64 never had, each gated like what replaced it.
#[cfg(target_arch = "x86_64")]
syscalls! {
    0 read Core;
    1 write Core;
    2 open Core;
    3 close Core;
    4 stat Core;
    5 fstat Core;
    6 lstat Core;
    7 poll Core;
    8 lseek Core;
    9 mmap Core;
    10 mprotect Core;
    11 munmap Core;
    12 brk Core;
    13 rt_sigaction Core;
    14 rt_sigprocmask Core;
    15 rt_sigreturn Core;
    16 ioctl Core;
    17 pread64 Core;
    18 pwrite64 Core;
    19 readv Core;
    20 writev Core;
    21 access Core;
    22 pipe Core;
    23 select Core;
    24 sched_yield Core;
    25 mremap Core;
    26 msync Core;
    27 mincore Core;
    28 madvise Core;
    32 dup Core;
    33 dup2 Core;
    34 pause Core;
    35 nanosleep Core;
    36 getitimer Core;
    37 alarm Core;
    38 setitimer Core;
    39 getpid Core;
    40 sendfile Core;
    41 socket Core; // gated by family: netlink route sockets only know `lo`; see net.rs
    42 connect Core; // acts on existing sockets; see net.rs
    43 accept Core; // acts on existing sockets; see net.rs
    44 sendto Core; // acts on existing sockets; see net.rs
    45 recvfrom Core; // acts on existing sockets; see net.rs
    46 sendmsg Core; // acts on existing sockets; see net.rs
    47 recvmsg Core; // acts on existing sockets; see net.rs
    48 shutdown Core; // acts on existing sockets; see net.rs
    49 bind Core; // acts on existing sockets (netlink port ids); see net.rs
    50 listen Core; // acts on existing sockets; see net.rs
    51 getsockname Core; // acts on existing sockets; see net.rs
    52 getpeername Core; // acts on existing sockets; see net.rs
    53 socketpair Core; // AF_UNIX pairs are local IPC; others need `net`
    54 setsockopt Core; // acts on existing sockets; see net.rs
    55 getsockopt Core; // acts on existing sockets; see net.rs
    56 clone Core; // gated by flags: threads vs process
    57 fork Cap(Process);
    58 vfork Cap(Process);
    59 execve Cap(Process);
    60 exit Core;
    61 wait4 Cap(Process);
    62 kill Core;
    63 uname Core;
    72 fcntl Core;
    73 flock Core;
    74 fsync Core;
    75 fdatasync Core;
    76 truncate Cap(FsWrite);
    77 ftruncate Core; // acts on an fd already opened for writing (which needed fs_write, or is a memfd)
    78 getdents Core;
    79 getcwd Core;
    80 chdir Core;
    81 fchdir Core;
    82 rename Cap(FsWrite);
    83 mkdir Cap(FsWrite);
    84 rmdir Cap(FsWrite);
    85 creat Core;
    86 link Cap(FsWrite);
    87 unlink Cap(FsWrite);
    88 symlink Cap(FsWrite);
    89 readlink Core;
    90 chmod Cap(FsWrite);
    91 fchmod Cap(FsWrite);
    92 chown Cap(FsWrite);
    93 fchown Cap(FsWrite);
    94 lchown Cap(FsWrite);
    95 umask Core;
    96 gettimeofday Core;
    97 getrlimit Core;
    98 getrusage Core;
    99 sysinfo Core;
    100 times Core;
    101 ptrace Privileged;
    102 getuid Core;
    103 syslog Privileged;
    104 getgid Core;
    105 setuid Core;
    106 setgid Core;
    107 geteuid Core;
    108 getegid Core;
    109 setpgid Cap(Process);
    110 getppid Core;
    111 getpgrp Core;
    112 setsid Cap(Process);
    113 setreuid Core;
    114 setregid Core; // Linux's rules; ids mean nothing outside the sandbox
    115 getgroups Core;
    116 setgroups Core; // uid 0 only, as on Linux
    117 setresuid Core;
    118 getresuid Core;
    119 setresgid Core;
    120 getresgid Core;
    121 getpgid Core;
    122 setfsuid Core;
    123 setfsgid Core;
    124 getsid Core;
    125 capget Core;
    126 capset Privileged;
    127 rt_sigpending Core;
    128 rt_sigtimedwait Core;
    129 rt_sigqueueinfo Core;
    130 rt_sigsuspend Core;
    131 sigaltstack Core;
    132 utime Cap(FsWrite);
    133 mknod Cap(FsWrite);
    134 uselib Privileged;
    135 personality Core;
    137 statfs Core;
    138 fstatfs Core;
    140 getpriority Core;
    141 setpriority Core;
    142 sched_setparam Core;
    143 sched_getparam Core;
    144 sched_setscheduler Core;
    145 sched_getscheduler Core;
    149 mlock Core;
    150 munlock Core;
    151 mlockall Core;
    152 munlockall Core;
    153 vhangup Privileged;
    154 modify_ldt Privileged;
    155 pivot_root Privileged;
    156 _sysctl Privileged;
    157 prctl Core;
    158 arch_prctl Core;
    160 setrlimit Core;
    161 chroot Privileged;
    162 sync Core;
    163 acct Privileged;
    164 settimeofday Privileged;
    165 mount Privileged;
    166 umount2 Privileged;
    167 swapon Privileged;
    168 swapoff Privileged;
    169 reboot Privileged;
    170 sethostname Privileged;
    171 setdomainname Privileged;
    172 iopl Privileged;
    173 ioperm Privileged;
    174 create_module Privileged;
    175 init_module Privileged;
    176 delete_module Privileged;
    177 get_kernel_syms Privileged;
    178 query_module Privileged;
    179 quotactl Privileged;
    180 nfsservctl Privileged;
    186 gettid Core;
    188 setxattr Cap(FsWrite);
    189 lsetxattr Cap(FsWrite);
    190 fsetxattr Cap(FsWrite);
    191 getxattr Core;
    192 lgetxattr Core;
    193 fgetxattr Core;
    194 listxattr Core;
    195 llistxattr Core;
    196 flistxattr Core;
    197 removexattr Cap(FsWrite);
    198 lremovexattr Cap(FsWrite);
    199 fremovexattr Cap(FsWrite);
    200 tkill Core;
    201 time Core;
    202 futex Core;
    203 sched_setaffinity Core;
    204 sched_getaffinity Core;
    213 epoll_create Core;
    217 getdents64 Core;
    218 set_tid_address Core;
    221 fadvise64 Core;
    222 timer_create Core;
    223 timer_settime Core;
    224 timer_gettime Core;
    225 timer_getoverrun Core;
    226 timer_delete Core;
    227 clock_settime Privileged;
    228 clock_gettime Core;
    229 clock_getres Core;
    230 clock_nanosleep Core;
    231 exit_group Core;
    232 epoll_wait Core;
    233 epoll_ctl Core;
    234 tgkill Core;
    235 utimes Cap(FsWrite);
    246 kexec_load Privileged;
    247 waitid Cap(Process);
    248 add_key Privileged;
    249 request_key Privileged;
    250 keyctl Privileged;
    253 inotify_init Core;
    254 inotify_add_watch Core;
    255 inotify_rm_watch Core;
    257 openat Core;
    258 mkdirat Cap(FsWrite);
    259 mknodat Cap(FsWrite);
    260 fchownat Cap(FsWrite);
    261 futimesat Cap(FsWrite);
    262 newfstatat Core;
    263 unlinkat Cap(FsWrite);
    264 renameat Cap(FsWrite);
    265 linkat Cap(FsWrite);
    266 symlinkat Cap(FsWrite);
    267 readlinkat Core;
    268 fchmodat Cap(FsWrite);
    269 faccessat Core;
    270 pselect6 Core;
    271 ppoll Core;
    272 unshare Privileged;
    273 set_robust_list Core;
    274 get_robust_list Core;
    280 utimensat Cap(FsWrite);
    281 epoll_pwait Core;
    282 signalfd Core;
    283 timerfd_create Core;
    284 eventfd Core;
    285 fallocate Core; // like ftruncate
    286 timerfd_settime Core;
    287 timerfd_gettime Core;
    288 accept4 Core; // acts on existing sockets; see net.rs
    289 signalfd4 Core;
    290 eventfd2 Core;
    291 epoll_create1 Core;
    292 dup3 Core;
    293 pipe2 Core;
    294 inotify_init1 Core;
    295 preadv Core;
    296 pwritev Core;
    297 rt_tgsigqueueinfo Core;
    298 perf_event_open Privileged;
    299 recvmmsg Core; // acts on existing sockets, like recvmsg
    302 prlimit64 Core;
    307 sendmmsg Core; // acts on existing sockets, like sendmsg
    308 setns Privileged;
    309 getcpu Core;
    310 process_vm_readv Privileged;
    311 process_vm_writev Privileged;
    312 kcmp Privileged;
    313 finit_module Privileged;
    316 renameat2 Cap(FsWrite);
    317 seccomp Core;
    318 getrandom Core;
    319 memfd_create Core;
    321 bpf Privileged;
    322 execveat Cap(Process);
    323 userfaultfd Privileged;
    324 membarrier Core;
    325 mlock2 Core;
    326 copy_file_range Core;
    332 statx Core;
    334 rseq Core;
    424 pidfd_send_signal Cap(Process);
    425 io_uring_setup Core;
    434 pidfd_open Cap(Process);
    435 clone3 Core; // gated by flags: threads vs process
    436 close_range Core;
    437 openat2 Core;
    438 pidfd_getfd Cap(Process);
    439 faccessat2 Core;
    441 epoll_pwait2 Core;
}
