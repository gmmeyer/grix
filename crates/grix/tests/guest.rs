//! End-to-end tests: boot the real kernel in QEMU and run the C fixtures.
//! Needs `make kernel fixtures` (or just `make test`).

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use grix::{Capability, DenyAction, ExitStatus, GuestEvent, RunOutput, Sandbox, SandboxBuilder};

fn fixture(name: &str) -> PathBuf {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/build").join(name);
    assert!(p.exists(), "missing fixture {} — run `make fixtures`", p.display());
    p
}

fn with(name: &str) -> SandboxBuilder {
    Sandbox::builder().timeout(Duration::from_secs(60)).import(fixture(name), &format!("/bin/{name}")).unwrap()
}

fn run(b: SandboxBuilder, argv: &[&str]) -> RunOutput {
    let out = b.build().unwrap().run(argv).unwrap();
    assert!(
        !matches!(out.status, ExitStatus::KernelPanic | ExitStatus::VmFailed(_)),
        "sandbox failure: {:?}\n{}",
        out.status,
        out.kernel_log
    );
    out
}

#[test]
fn args_env_output_and_exit_status() {
    let out = run(with("hello").env("GREETING", "hi"), &["/bin/hello", "world"]);
    assert_eq!(out.status, ExitStatus::Exited(7));
    assert_eq!(out.stdout_str(), "hello from grix! argc=2\nargv[0]=/bin/hello\nargv[1]=world\nGREETING=hi\n");
    assert_eq!(out.stderr_str(), "this goes to stderr\n");
    assert!(out.events.is_empty(), "{:?}", out.events);
}

#[test]
fn environment_is_empty_unless_given() {
    let out = run(with("hello"), &["/bin/hello"]);
    assert!(out.stdout_str().contains("GREETING=(unset)"));
}

#[test]
fn static_pie_executable() {
    let b = Sandbox::builder().import(fixture("hello-pie"), "/bin/hello").unwrap();
    let out = run(b, &["/bin/hello", "pie"]);
    assert_eq!(out.status, ExitStatus::Exited(7));
    assert!(out.stdout_str().contains("argv[1]=pie"));
}

#[test]
fn reads_imported_files_only() {
    let b = with("cat").file("/data/in.txt", "secret data\n", 0o644).unwrap();
    let out = run(b, &["/bin/cat", "/data/in.txt", "/etc/shadow"]);
    assert_eq!(out.status, ExitStatus::Exited(1));
    assert_eq!(out.stdout_str(), "secret data\n");
    assert_eq!(out.stderr_str(), "cat: /etc/shadow: No such file or directory\n");
    assert_eq!(out.events, [GuestEvent::MissingPath { path: "/etc/shadow".into() }]);
}

#[test]
fn imported_directory_tree_and_symlinks() {
    let dir = std::env::temp_dir().join(format!("grix-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("a.txt"), "aaaa").unwrap();
    std::fs::write(dir.join("sub/b.txt"), "b").unwrap();
    std::os::unix::fs::symlink("a.txt", dir.join("link")).unwrap();
    let out = run(with("ls").import(&dir, "/work").unwrap(), &["/bin/ls", "/work"]);
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(out.status, ExitStatus::Exited(0), "{}", out.stderr_str());
    let listing = out.stdout_str();
    assert!(listing.starts_with("cwd=/work\n"), "{listing}");
    assert!(listing.contains("- a.txt 4 "), "{listing}");
    assert!(listing.contains("l link -> a.txt"), "{listing}");
    assert!(listing.contains("d sub 4096 755"), "{listing}");
}

#[test]
fn root_contains_only_imports_and_synthetic_dirs() {
    let out = run(with("ls"), &["/bin/ls", "/"]);
    let listing = out.stdout_str();
    let names: Vec<&str> = listing.lines().skip(1).filter_map(|l| l.split(' ').nth(1)).collect();
    // /etc/passwd + /etc/group and /home/grix describe the sandbox user.
    assert_eq!(names, ["bin", "dev", "etc", "home", "proc", "sys", "tmp"]);
}

#[test]
fn network_is_denied_by_default() {
    let out = run(with("net"), &["/bin/net"]);
    assert_eq!(out.status, ExitStatus::Exited(0), "{}", out.stdout_str());
    assert_eq!(out.stdout_str(), "socket: Operation not permitted\n");
    assert_eq!(out.missing_capabilities(), ["net"]);
}

#[test]
fn kill_on_deny() {
    let out = run(with("net").on_deny(DenyAction::Kill), &["/bin/net"]);
    assert_eq!(out.status, ExitStatus::Signaled(31));
    assert_eq!(out.stdout_str(), "");
}

#[test]
fn granted_but_unimplemented_is_reported_as_such() {
    let out = run(with("net").allow(Capability::Net), &["/bin/net"]);
    assert_eq!(out.status, ExitStatus::Exited(1));
    assert!(out.missing_capabilities().is_empty());
    assert!(out.events.iter().any(|e| matches!(e, GuestEvent::Unimplemented { syscall, .. } if syscall == "socket")));
}

#[test]
fn file_writes_need_fs_write() {
    let out = run(with("write"), &["/bin/write", "/tmp/out.txt"]);
    assert_eq!(out.status, ExitStatus::Exited(0), "{}", out.stdout_str());
    assert_eq!(out.stdout_str(), "fopen /tmp/out.txt: Operation not permitted\n");
    assert_eq!(
        out.events,
        [GuestEvent::Denied { syscall: "openat".into(), capability: "fs_write".into(), detail: "/tmp/out.txt".into() }]
    );
}

#[test]
fn memory_management() {
    let out = run(with("mem"), &["/bin/mem"]);
    assert_eq!(out.stdout_str(), "mem ok\n");
    assert_eq!(out.status, ExitStatus::Exited(0));
}

#[test]
fn faults_become_signals() {
    for (arg, sig) in [("segv", 11), ("abort", 6), ("ill", 5)] {
        let out = run(with("fault"), &["/bin/fault", arg]);
        assert_eq!(out.status, ExitStatus::Signaled(sig), "{arg}");
        assert!(matches!(out.events.last(), Some(GuestEvent::Fault { signal, .. }) if *signal == sig as u32));
    }
    // A signal frame asking to return to a privileged mode is rejected.
    let out = run(with("fault"), &["/bin/fault", "sigreturn"]);
    assert_eq!(out.status, ExitStatus::Signaled(11));
    assert!(
        matches!(&out.events[..], [GuestEvent::Fault { signal: 11, detail, .. }] if detail.contains("rt_sigreturn")),
        "{:?}",
        out.events
    );
}

#[test]
fn clocks_sleep_and_randomness() {
    let out = run(with("clock"), &["/bin/clock"]);
    assert_eq!(out.status, ExitStatus::Exited(0), "{}", out.stdout_str());
    let s = out.stdout_str();
    let now: u64 = s.split("now=").nth(1).unwrap().split(' ').next().unwrap().parse().unwrap();
    let host = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    assert!(host.abs_diff(now) < 120, "guest time {now} vs host {host}");
    assert!(s.contains("random=32/1"), "{s}");
}

#[test]
fn missing_program() {
    let out = run(with("hello"), &["/bin/nope"]);
    assert_eq!(out.status, ExitStatus::Exited(127));
    assert!(matches!(&out.events[..], [GuestEvent::ExecFailed { path, .. }] if path == "/bin/nope"));
}

#[test]
fn non_executable_program() {
    let b = Sandbox::builder().file("/bin/x", "not an elf", 0o644).unwrap();
    assert_eq!(run(b, &["/bin/x"]).status, ExitStatus::Exited(126));
    let b = Sandbox::builder().file("/bin/x", "not an elf", 0o755).unwrap();
    assert_eq!(run(b, &["/bin/x"]).status, ExitStatus::Exited(126));
}

#[test]
fn reserved_and_relative_guest_paths_are_rejected() {
    assert!(Sandbox::builder().file("/dev/x", "", 0o644).is_err());
    assert!(Sandbox::builder().file("relative", "", 0o644).is_err());
    assert!(Sandbox::builder().file("/a/../b", "", 0o644).is_err());
}

#[test]
fn timeout() {
    // `sleep` via clock: ask for far less time than the program needs.
    let out = with("clock").timeout(Duration::from_millis(1)).build().unwrap().run(&["/bin/clock"]).unwrap();
    assert_eq!(out.status, ExitStatus::Timeout);
}

// ---------------------------------------------------------------- real-world binaries (Alpine)

fn busybox_sandbox() -> Sandbox {
    Sandbox::builder()
        .import(fixture("alpine/bin/busybox.static"), "/bin/busybox")
        .unwrap()
        .file("/data/t.txt", "line one\nline two\nthree\n", 0o644)
        .unwrap()
        .build()
        .unwrap()
}

fn busybox(sb: &Sandbox, args: &[&str]) -> RunOutput {
    let mut argv = vec!["/bin/busybox"];
    argv.extend(args);
    let out = sb.run(&argv).unwrap();
    assert_eq!(out.status, ExitStatus::Exited(0), "{args:?}: {}{}", out.stderr_str(), out.kernel_log);
    assert!(out.events.is_empty(), "{args:?}: {:?}", out.events);
    out
}

#[test]
fn alpine_static_busybox_applets() {
    let sb = busybox_sandbox();
    assert_eq!(
        busybox(&sb, &["sha256sum", "/data/t.txt"]).stdout_str(),
        "439b12ce87e8b28200496efa3531924c874f139d423f3f8625770148786e43ca  /data/t.txt\n"
    );
    assert_eq!(busybox(&sb, &["sort", "-r", "/data/t.txt"]).stdout_str(), "three\nline two\nline one\n");
    assert_eq!(busybox(&sb, &["grep", "-n", "two", "/data/t.txt"]).stdout_str(), "2:line two\n");
    assert_eq!(
        busybox(&sb, &["awk", "{n+=length($0)} END {print \"chars\", n}", "/data/t.txt"]).stdout_str(),
        "chars 21\n"
    );
    assert_eq!(busybox(&sb, &["sh", "-c", "x=6; echo $((x*7))"]).stdout_str(), "42\n");
    assert_eq!(busybox(&sb, &["uname", "-sm"]).stdout_str(), "Linux aarch64\n");
}

#[test]
fn alpine_dynamically_linked_busybox() {
    let sb = Sandbox::builder()
        .import(fixture("alpine/bin/busybox"), "/bin/busybox")
        .unwrap()
        .import(fixture("alpine/lib"), "/lib")
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(busybox(&sb, &["echo", "dynamic", "works"]).stdout_str(), "dynamic works\n");
}

#[test]
fn shell_running_a_program_needs_process_capability() {
    let out = busybox_sandbox().run(&["/bin/busybox", "sh", "-c", "/bin/busybox true"]).unwrap();
    assert_ne!(out.status, ExitStatus::Exited(0));
    assert_eq!(out.missing_capabilities(), ["process"]);
}

// ---------------------------------------------------------------- threads

#[test]
fn threads_need_the_threads_capability() {
    let out = run(with("spawn"), &["/bin/spawn"]);
    assert_eq!(out.status, ExitStatus::Exited(1));
    assert_eq!(out.stdout_str(), "pthread_create: Resource temporarily unavailable\n");
    assert_eq!(out.missing_capabilities(), ["threads"]);
}

#[test]
fn pthreads() {
    let out = run(with("threads").allow(Capability::Threads), &["/bin/threads"]);
    assert_eq!(out.stdout_str(), "threads ok counter=160000\n");
    assert_eq!(out.status, ExitStatus::Exited(0));
    assert!(out.events.is_empty(), "{:?}", out.events);
}

#[test]
fn deadlocks_are_reported_instead_of_hanging() {
    let out = run(with("deadlock").allow(Capability::Threads), &["/bin/deadlock"]);
    assert_eq!(out.status, ExitStatus::Signaled(9));
    assert!(
        matches!(&out.events[..], [GuestEvent::Fault { signal: 9, detail, .. }] if detail.starts_with("deadlock")),
        "{:?}",
        out.events
    );
}

// ---------------------------------------------------------------- pipes, eventfd, epoll

#[test]
fn pipes_eventfd_epoll_poll_select() {
    let out = run(with("events").allow(Capability::Threads), &["/bin/events"]);
    assert_eq!(out.stdout_str(), "events ok\n");
    assert_eq!(out.status, ExitStatus::Exited(0));
    // The fixture checks that AF_INET sockets are still denied.
    assert_eq!(out.missing_capabilities(), ["net"]);
}

#[test]
fn sigpipe_kills_by_default() {
    let out = run(with("sigpipe"), &["/bin/sigpipe"]);
    assert_eq!(out.status, ExitStatus::Signaled(13));
    assert_eq!(out.stdout_str(), "");
}

// ---------------------------------------------------------------- signals

#[test]
fn signal_handlers() {
    let out = run(with("signals").allow(Capability::Threads), &["/bin/signals"]);
    assert_eq!(out.stdout_str(), "signals ok\n");
    assert_eq!(out.status, ExitStatus::Exited(0));
    assert!(out.events.is_empty(), "{:?}", out.events);
}

#[test]
fn go_runtime_signals() {
    // Async preemption (SIGURG), nil dereference panics (SIGSEGV), os/signal.
    let out = run(with("gosignals").allow(Capability::Threads), &["/bin/gosignals"]);
    assert_eq!(out.stdout_str(), "go signals ok true\n", "{}", out.stderr_str());
    assert_eq!(out.status, ExitStatus::Exited(0));
    assert!(out.events.is_empty(), "{:?}", out.events);
}

// ---------------------------------------------------------------- Linux surface

#[test]
fn users_proc_dev_statfs_xattr_inotify() {
    let out = run(with("compat"), &["/bin/compat"]);
    assert_eq!(out.stdout_str(), "via /dev/stdout\ncompat ok \n");
    assert_eq!(out.status, ExitStatus::Exited(0));
    assert_eq!(out.events, [GuestEvent::MissingPath { path: "/nope".into() }]);
}

#[test]
fn shebang_scripts() {
    let b = Sandbox::builder()
        .import(fixture("alpine/bin/busybox.static"), "/bin/busybox")
        .unwrap()
        .file("/bin/greet", "#!/bin/busybox sh\necho \"hi $1 from $0\"\n", 0o755)
        .unwrap()
        .file("/bin/nested", "#!/bin/greet\n", 0o755)
        .unwrap()
        .file("/bin/missing", "#!/bin/nope\n", 0o755)
        .unwrap();
    let sb = b.build().unwrap();
    let out = sb.run(&["/bin/greet", "there"]).unwrap();
    assert_eq!(out.stdout_str(), "hi there from /bin/greet\n");
    // A script whose interpreter is itself a script.
    let out = sb.run(&["/bin/nested", "x"]).unwrap();
    assert_eq!(out.stdout_str(), "hi /bin/nested from /bin/greet\n");
    let out = sb.run(&["/bin/missing"]).unwrap();
    assert_eq!(out.status, ExitStatus::Exited(127));
    assert!(matches!(&out.events[..], [GuestEvent::ExecFailed { reason, .. }] if reason.contains("/bin/nope")));
}

#[test]
fn busybox_sees_user_and_system_info() {
    let sb = busybox_sandbox();
    assert_eq!(busybox(&sb, &["id"]).stdout_str(), "uid=1000(grix) gid=1000(grix) groups=1000(grix)\n");
    assert_eq!(busybox(&sb, &["whoami"]).stdout_str(), "grix\n");
    assert!(busybox(&sb, &["ps"]).stdout_str().contains("1 grix"));
    assert!(busybox(&sb, &["free"]).stdout_str().contains("Mem:"));
    assert!(busybox(&sb, &["df", "/"]).stdout_str().contains("grix"));
    assert_eq!(busybox(&sb, &["ls", "/proc/self/fd"]).stdout_str(), "0\n1\n2\n3\n");
}
