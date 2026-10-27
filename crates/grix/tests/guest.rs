//! End-to-end tests: boot the real kernel in QEMU and run the C fixtures.
//! Needs `make kernel fixtures` (or just `make test`).

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use grix::{
    Capability, DenyAction, ExitStatus, ExportContent, ExportState, GuestEvent, RunOutput, Sandbox, SandboxBuilder,
    Stream,
};

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
fn network_interfaces_without_net() {
    // getifaddrs, if_nameindex and netlink describe lo; nothing else exists.
    let out = run(with("netif"), &["/bin/netif"]);
    assert_eq!(out.stdout_str(), "netif ok\n");
    assert_eq!(out.status, ExitStatus::Exited(0));
    // The fixture checks that AF_INET sockets are still denied.
    assert_eq!(out.missing_capabilities(), ["net"]);
    assert_eq!(out.events.len(), 1, "{:?}", out.events);
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
fn writable_filesystem() {
    let b = with("files").allow(Capability::FsWrite).file("/data/in.txt", "imported text\n", 0o644).unwrap();
    let out = run(b, &["/bin/files"]);
    assert_eq!(out.stdout_str(), "files ok\n");
    assert_eq!(out.status, ExitStatus::Exited(0));
    assert!(out.events.is_empty(), "{:?}", out.events);
}

#[test]
fn exported_directories() {
    // What the program leaves in /out comes back when it ends, even by a
    // crash: with modes, times and links, and the imported file that was
    // there. An export that isn't a directory is reported missing.
    let sb = with("export")
        .allow(Capability::FsWrite)
        .file("/out/imported.txt", "from the host\n", 0o600)
        .unwrap()
        .export("/out")
        .unwrap()
        .export("/out/imported.txt")
        .unwrap()
        .build()
        .unwrap();
    for (args, status) in
        [(&["/bin/export"][..], ExitStatus::Exited(0)), (&["/bin/export", "crash"], ExitStatus::Signaled(11))]
    {
        let out = sb.run(args).unwrap();
        assert_eq!(out.stdout_str(), "export ok\n");
        assert_eq!(out.status, status, "{}", out.kernel_log);
        let faults = out.events.iter().filter(|e| matches!(e, GuestEvent::Fault { .. })).count();
        assert_eq!(out.events.len(), faults, "{:?}", out.events);
        assert_eq!(faults, if status == ExitStatus::Exited(0) { 0 } else { 1 });
        let ex = out.export("/out").unwrap();
        assert_eq!(ex.state, ExportState::Complete, "{}", out.kernel_log);
        let paths: Vec<&str> = ex.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "a",
                "a/b",
                "a/b/c.txt",
                "big.bin",
                "empty",
                "imported.txt",
                "link",
                "new",
                "run.sh",
                "sub",
                "sub/hard",
                "sub/hello.txt"
            ]
        );
        let get = |p: &str| ex.entries.iter().find(|e| e.path == p).unwrap();
        let hello = get("sub/hello.txt");
        assert_eq!(hello.content, ExportContent::File(b"hello\n".to_vec()));
        assert_eq!(hello.mode, 0o640);
        assert_eq!(hello.mtime, UNIX_EPOCH + Duration::from_secs(1_000_000_000));
        assert_eq!(get("sub/hard").content, hello.content);
        assert_eq!((get("sub").mode, get("sub").content.clone()), (0o750, ExportContent::Dir));
        assert_eq!(get("link").content, ExportContent::Symlink("sub/hello.txt".into()));
        assert_eq!(get("empty").content, ExportContent::File(vec![]));
        assert_eq!(get("run.sh").mode, 0o755);
        assert_eq!(
            (get("imported.txt").mode, get("new").content.clone()),
            (0o600, ExportContent::File(b"renamed\n".to_vec()))
        );
        let big: Vec<u8> = (0..3usize << 20).map(|i| (i % 251) as u8).collect();
        assert!(get("big.bin").content == ExportContent::File(big));
        assert_eq!(out.export("/out/imported.txt").unwrap().state, ExportState::Missing);
    }

    // On the host: the same tree, links left as links.
    let out = sb.run(&["/bin/export"]).unwrap();
    let dest = std::env::temp_dir().join(format!("grix-export-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dest);
    out.export("/out").unwrap().write_to(&dest).unwrap();
    assert_eq!(std::fs::read(dest.join("a/b/c.txt")).unwrap(), b"deep\n");
    assert_eq!(std::fs::read_link(dest.join("link")).unwrap(), PathBuf::from("sub/hello.txt"));
    assert_eq!(std::fs::read(dest.join("link")).unwrap(), b"hello\n");
    std::fs::remove_dir_all(&dest).unwrap();

    // Past the export limit: what came before it, and a note that it's cut off.
    // (No import at /out: the export makes it an empty directory.)
    let out =
        run(with("export").allow(Capability::FsWrite).export("/out").unwrap().max_export(1 << 20), &["/bin/export"]);
    let ex = out.export("/out").unwrap();
    assert_eq!(ex.state, ExportState::Truncated);
    let paths: Vec<&str> = ex.entries.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(paths[..3], ["a", "a/b", "a/b/c.txt"]);
    assert!(!paths.contains(&"big.bin"));
    // Entries that don't fit are left out and smaller ones after them still
    // come: the 3 MiB file, not the next ones.
    assert!(paths.contains(&"sub/hello.txt") && paths.contains(&"run.sh"));

    // Deeper than an export path may go (4096 bytes), and a 100 GiB sparse
    // file: both left out, quickly, and the program's status is intact.
    let started = std::time::Instant::now();
    let out = run(with("export").allow(Capability::FsWrite).export("/out").unwrap(), &["/bin/export", "deep"]);
    assert!(started.elapsed() < Duration::from_secs(20));
    assert_eq!(out.status, ExitStatus::Exited(0));
    let ex = out.export("/out").unwrap();
    assert_eq!(ex.state, ExportState::Truncated);
    let paths: Vec<&str> = ex.entries.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(paths.len(), 34, "33 levels fit, plus top.txt");
    assert!(paths.iter().all(|p| p.len() <= 4096) && paths.contains(&"top.txt"));
    assert!(!paths.iter().any(|p| p.ends_with("bottom.txt") || *p == "sparse.img"));
}

#[test]
fn filesystem_size_limit() {
    // Written data is limited to half of guest memory, like tmpfs.
    let out = run(with("files").allow(Capability::FsWrite), &["/bin/files", "fill"]);
    assert_eq!(out.status, ExitStatus::Exited(0), "{}", out.stdout_str());
    let mib: u64 =
        out.stdout_str().trim().strip_prefix("filled ").unwrap().strip_suffix(" MiB").unwrap().parse().unwrap();
    assert!((150..=256).contains(&mib), "{mib} MiB");
}

#[test]
fn filesystem_metadata_limit() {
    // Names and nodes are bounded too: ENOSPC instead of exhausting kernel memory.
    let out = run(with("files").allow(Capability::FsWrite), &["/bin/files", "meta"]);
    assert_eq!(out.status, ExitStatus::Exited(0), "{}", out.stdout_str());
    assert!(out.stdout_str().starts_with("meta "), "{}", out.stdout_str());
}

#[test]
fn shared_file_mappings_are_reported() {
    let out = run(with("files").allow(Capability::FsWrite), &["/bin/files", "shared"]);
    assert_eq!(out.stdout_str(), "shared ok\n");
    assert_eq!(out.status, ExitStatus::Exited(0));
    let unimplemented: Vec<&str> = out
        .events
        .iter()
        .filter_map(|e| match e {
            GuestEvent::Unimplemented { syscall, .. } => Some(syscall.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(unimplemented, ["mprotect", "write"], "{:?}", out.events);
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
fn timers() {
    let out = run(with("timers").allow(Capability::Threads), &["/bin/timers"]);
    assert_eq!(out.stdout_str(), "timers ok\n");
    assert_eq!(out.status, ExitStatus::Exited(0));
    // The fixture checks that CPU-time interval timers are reported as missing.
    assert!(
        matches!(&out.events[..], [GuestEvent::Unimplemented { syscall, .. }] if syscall == "setitimer"),
        "{:?}",
        out.events
    );
    // SIGALRM's default action ends the program.
    let out = run(with("timers"), &["/bin/timers", "alarm"]);
    assert_eq!(out.status, ExitStatus::Signaled(14));
}

#[test]
fn memfd_signalfd_cpu_clocks_and_more() {
    let out = run(with("linux").allow(Capability::Threads), &["/bin/linux"]);
    assert_eq!(out.stdout_str(), "linux ok\n");
    assert_eq!(out.status, ExitStatus::Exited(0));
    // The fixture tries an unknown prctl option, which must be reported.
    assert!(
        matches!(&out.events[..], [GuestEvent::Unimplemented { syscall, detail, .. }] if syscall == "prctl" && detail == "option 4242"),
        "{:?}",
        out.events
    );
}

#[test]
fn kernel_memory_is_bounded() {
    // Netlink replies, pipe buffers, queued signals, mappings, inotify
    // watches and /proc contents run into errnos, not a kernel panic.
    let out = run(with("limits"), &["/bin/limits"]);
    assert_eq!(out.stdout_str(), "limits ok\n");
    assert_eq!(out.status, ExitStatus::Exited(0));
    assert!(out.events.is_empty(), "{:?}", out.events);
}

// ---------------------------------------------------------------- stdin and output

/// Deterministic bytes, and their FNV-1a hash as the stdin fixture prints it.
fn sample(n: usize) -> (Vec<u8>, String) {
    let mut x: u32 = 12345;
    let data: Vec<u8> = (0..n)
        .map(|_| {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            (x >> 16) as u8
        })
        .collect();
    let hash = data.iter().fold(0xcbf29ce484222325u64, |h, &b| (h ^ b as u64).wrapping_mul(0x100000001b3));
    (data, format!("bytes={n} fnv={hash:016x} fionread=1\n"))
}

#[test]
fn stdin_from_the_host() {
    let sb = with("stdin").build().unwrap();
    // More than the guest's 64 KiB stdin buffer, so it has to push back.
    let (data, want) = sample(100_000);
    let out = sb.run_with_stdin(&["/bin/stdin"], data).unwrap();
    assert_eq!(out.stdout_str(), want);
    assert_eq!(out.status, ExitStatus::Exited(0));
    assert!(out.events.is_empty(), "{:?}", out.events);
    // Empty input, and no input at all: end-of-file either way.
    assert_eq!(
        sb.run_with_stdin(&["/bin/stdin"], b"".to_vec()).unwrap().stdout_str(),
        "bytes=0 fnv=cbf29ce484222325 fionread=1\n"
    );
    assert_eq!(sb.run(&["/bin/stdin"]).unwrap().stdout_str(), "bytes=0 fnv=cbf29ce484222325 fionread=1\n");
}

#[test]
fn stdin_through_busybox() {
    let sb = busybox_sandbox();
    let (data, _) = sample(20_000);
    let out = sb.run_with_stdin(&["/bin/busybox", "cat"], data.clone()).unwrap();
    assert_eq!(out.stdout, data);
    let out = sb.run_with_stdin(&["/bin/busybox", "wc", "-l"], b"a\nb\nc\n".to_vec()).unwrap();
    assert_eq!(out.stdout_str().trim(), "3");
}

#[test]
fn stdout_backpressure() {
    // The host stops reading for a while in each of the program's four
    // phases (at 1, 3, 7 and 11 MiB): long enough for even a slow guest to
    // fill every buffer in between. Big blocking writes complete in one call,
    // the program sees EAGAIN and epoll readiness, blocking writes wait
    // without freezing its other threads, and signals interrupt them without
    // losing or repeating output (see the fixture).
    let sb = with("backpressure").allow(Capability::Threads).build().unwrap();
    let mut seen = 0;
    let out = sb
        .run_streaming(&["/bin/backpressure"], |_, bytes| {
            let crossed = |mib: usize| seen < mib << 20 && seen + bytes.len() >= mib << 20;
            if crossed(1) || crossed(3) || crossed(7) || crossed(11) {
                std::thread::sleep(Duration::from_millis(400));
            }
            seen += bytes.len();
        })
        .unwrap();
    assert_eq!(out.stderr_str(), "full=1 eagain=1 waited=1 ticker_ran=1 interrupted=1\n", "{}", out.kernel_log);
    assert_eq!(out.status, ExitStatus::Exited(0));
    assert!(out.events.is_empty(), "{:?}", out.events);
    let want: Vec<u8> = (0..14usize << 20).map(|i| ((i % (1 << 20)) % 251) as u8).collect();
    assert!(out.stdout == want, "stdout differs ({} bytes)", out.stdout.len());
}

#[test]
fn large_transfers_are_lossless() {
    // Megabytes each way, with a reader that keeps stalling: the guest is
    // held back, and nothing is dropped or reordered.
    let sb = busybox_sandbox();
    let (data, _) = sample(8 << 20);
    let mut seen = 0;
    let out = sb
        .run_streaming_with_stdin(&["/bin/busybox", "cat"], std::io::Cursor::new(data.clone()), |stream, bytes| {
            assert_eq!(stream, Stream::Stdout);
            // Long enough, every MiB, for the guest to fill every buffer
            // between us.
            if (seen + bytes.len()) >> 20 != seen >> 20 {
                std::thread::sleep(Duration::from_millis(100));
            }
            seen += bytes.len();
        })
        .unwrap();
    assert_eq!(out.status, ExitStatus::Exited(0), "{}", out.kernel_log);
    assert_eq!(seen, data.len());
    assert!(out.stdout == data, "stdout differs from stdin");
}

#[test]
fn output_limit() {
    let sb = Sandbox::builder()
        .max_output(1000)
        .import(fixture("alpine/bin/busybox.static"), "/bin/busybox")
        .unwrap()
        .build()
        .unwrap();
    let out = sb.run(&["/bin/busybox", "head", "-c", "5000", "/dev/zero"]).unwrap();
    assert_eq!(out.status, ExitStatus::Exited(0));
    assert_eq!(out.stdout.len(), 1000);
    assert!(out.stdout_truncated && !out.stderr_truncated);
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
