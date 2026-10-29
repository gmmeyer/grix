//! End-to-end tests: boot the real kernel in QEMU and run the C fixtures.
//! Needs `make kernel fixtures` (or just `make test`).

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use grix::{
    Capability, DenyAction, ExitStatus, ExportContent, ExportState, GuestEvent, RunControl, RunOutput, Sandbox,
    SandboxBuilder, Stream,
};

fn x86_64_guest() -> bool {
    grix::Arch::from_env() == grix::Arch::X86_64
}

/// A fixture built for the guest's architecture (`GRIX_ARCH`): x86_64's
/// programs are in `amd64/`, its Alpine in `alpine-x86_64/`. (The x86_64
/// translator's own fixtures are for arm64 guests.)
fn fixture(name: &str) -> PathBuf {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/build");
    let p = match grix::Arch::from_env() {
        grix::Arch::X86_64 => match name.split_once('/') {
            Some(("alpine", rest)) => base.join("alpine-x86_64").join(rest),
            Some(_) => base.join(name),
            None if name == "hello-x86_64" => base.join(name),
            None => base.join("amd64").join(name),
        },
        grix::Arch::Aarch64 => base.join(name),
    };
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

/// An echo server on the host's loopback; returns its port.
fn echo_server() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut c = c;
                let mut r = c.try_clone().unwrap();
                let _ = std::io::copy(&mut r, &mut c);
            });
        }
    });
    port
}

/// A port nothing listens on.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[test]
fn networking_through_the_host() {
    // Blocking and nonblocking connects to the host, 1 MiB each way,
    // half-close, refusals and policy denials, loopback, and DNS (see the
    // fixture).
    let port = echo_server();
    // (The fixture expects port + 1 to be denied, so that's not the closed one.)
    let closed = std::iter::repeat_with(free_port).find(|&c| c != port + 1).unwrap();
    let b = with("inet")
        .allow(Capability::Net)
        .allow_host(&format!("host.grix.internal:{port}"))
        .unwrap()
        .allow_host(&format!("host.grix.internal:{closed}"))
        .unwrap();
    let out = run(b, &["/bin/inet", "client", &port.to_string(), &closed.to_string()]);
    assert_eq!(out.stdout_str(), "net ok\n");
    assert_eq!(out.status, ExitStatus::Exited(0));
    let denied: Vec<&str> = out
        .events
        .iter()
        .map(|e| match e {
            GuestEvent::Denied { syscall, detail, .. } if syscall == "connect" => detail.as_str(),
            e => panic!("unexpected event {e}"),
        })
        .collect();
    assert_eq!(denied.len(), 2, "{denied:?}");
    assert!(denied[0].starts_with(&format!("10.0.2.2:{} is the host itself", port + 1)));
    assert!(denied[1].starts_with("93.184.216.34:80 isn't in the allow-list"));
    // Not a missing capability: the policy said no.
    assert!(out.missing_capabilities().is_empty());

    // Names the guest doesn't know go to the host's resolver; with an
    // allow-list, only names on it.
    let b = with("inet").allow(Capability::Net).file("/etc/hosts", "127.0.0.1 localhost\n", 0o644).unwrap();
    let out = run(b, &["/bin/inet", "resolve", "host.grix.internal"]);
    assert_eq!(out.stdout_str(), "host.grix.internal is 10.0.2.2\n");
    let b = with("inet").allow(Capability::Net).allow_host("example.com").unwrap();
    let out = run(b, &["/bin/inet", "resolve", "elsewhere.example"]);
    assert!(out.stdout_str().starts_with("elsewhere.example: "), "{}", out.stdout_str());
    assert!(
        matches!(&out.events[..], [GuestEvent::Denied { syscall, .. }] if syscall == "DNS lookup"),
        "{:?}",
        out.events
    );
}

#[test]
fn serving_through_a_forwarded_port() {
    use std::io::{BufRead, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let host_port = listener.local_addr().unwrap().port();
    let sb = with("inet").allow(Capability::Net).forward_listener(listener, 8000).unwrap().build().unwrap();
    let guest = std::thread::spawn(move || sb.run(&["/bin/inet", "server", "8000"]).unwrap());
    // Until the program listens, the guest refuses what the host accepts.
    let started = std::time::Instant::now();
    let reply = loop {
        assert!(started.elapsed() < Duration::from_secs(30), "the server never answered");
        let Ok(mut c) = std::net::TcpStream::connect(("127.0.0.1", host_port)) else { continue };
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        if c.write_all(b"ping\n").is_err() {
            continue;
        }
        let mut line = String::new();
        if std::io::BufReader::new(c).read_line(&mut line).is_ok() && !line.is_empty() {
            break line;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(reply, "pong: ping\n");
    let out = guest.join().unwrap();
    assert_eq!(out.stdout_str(), "served one\n");
    assert_eq!(out.status, ExitStatus::Exited(0));
    assert!(out.events.is_empty(), "{:?}", out.events);
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
    let out = run(with("net").allow(Capability::Net), &["/bin/net", "raw"]);
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
fn shared_mappings_of_mounted_files_are_reported() {
    // A live mount's file is the host's: a shared mapping of it is a copy.
    let host = temp_dir("sharedmount");
    let b = with("files").mount(&host, "/work").unwrap();
    let out = run(b, &["/bin/files", "shared", "/work/shm"]);
    assert_eq!(out.stdout_str(), "shared ok\n", "{:?}", out.events);
    assert_eq!(out.status, ExitStatus::Exited(0));
    let unimplemented: Vec<&str> = out
        .events
        .iter()
        .filter_map(|e| match e {
            GuestEvent::Unimplemented { syscall, .. } => Some(syscall.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(unimplemented, ["mmap", "mprotect", "write"], "{:?}", out.events);
}

#[test]
fn memory_management() {
    let out = run(with("mem"), &["/bin/mem"]);
    assert_eq!(out.stdout_str(), "mem ok\n");
    assert_eq!(out.status, ExitStatus::Exited(0));
}

#[test]
fn faults_become_signals() {
    // __builtin_trap: brk on arm64 (SIGTRAP), ud2 on x86_64 (SIGILL).
    let trap = if x86_64_guest() { 4 } else { 5 };
    for (arg, sig) in [("segv", 11), ("abort", 6), ("ill", trap)] {
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
fn program_for_another_machine() {
    // hello for this guest, with RISC-V's e_machine: the kernel names its own.
    let mut elf = std::fs::read(fixture("hello")).unwrap();
    elf[18..20].copy_from_slice(&243u16.to_le_bytes());
    let out = run(Sandbox::builder().file("/bin/x", elf, 0o755).unwrap(), &["/bin/x"]);
    assert_eq!(out.status, ExitStatus::Exited(126));
    let want = if x86_64_guest() { "/bin/x: not an x86_64 binary" } else { "/bin/x: not an AArch64 binary" };
    assert!(matches!(&out.events[..], [GuestEvent::ExecFailed { reason, .. }] if reason == want), "{:?}", out.events);
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

// ---------------------------------------------------------------- images

#[test]
fn images_built_from_oci_images() {
    // The OCI fixtures are arm64 images.
    if x86_64_guest() {
        return;
    }
    // From Docker Hub's alpine (pulled into an OCI layout by `make
    // fixtures`), with files, settings and build steps, through a file, to
    // a run.
    let dir = temp_dir("image");
    std::fs::write(dir.join("hello.sh"), "echo \"$GREETING from $(cat /etc/alpine-release) in $PWD\"\n").unwrap();
    let grixfile = format!(
        r#"
from = "oci:{}"
command = ["/bin/sh", "/app/hello.sh"]
cwd = "/app"
capabilities = ["process"]
run = ["echo built > /app/stamp", "rm /etc/motd"]

[env]
GREETING = "hi"

[[copy]]
host = "hello.sh"
guest = "/app/hello.sh"

[[file]]
guest = "/app/note"
content = "a note"
"#,
        fixture("oci/alpine").display()
    );
    std::fs::write(dir.join("Grixfile"), &grixfile).unwrap();
    // A Grixfile reads only from its own directory: the fixture's layout is
    // outside, so here it's let out, as a path on the command line would be.
    let err = grix::build::Grixfile::build_file(
        &dir.join("Grixfile"),
        grix::build::BuildOptions {
            kernel: None,
            on_output: &mut |_, _| {},
            policy: Default::default(),
            control: None,
        },
    );
    assert!(err.err().unwrap().to_string().contains("outside the build context"));
    let mut g = grix::build::Grixfile::parse(&grixfile).unwrap();
    g.from_outside_context = true;
    let mut log = Vec::new();
    let opts = grix::build::BuildOptions {
        kernel: None,
        on_output: &mut |_, d: &[u8]| log.extend_from_slice(d),
        policy: Default::default(),
        control: None,
    };
    let image = g.build(&dir, opts).unwrap();
    image.write_to(dir.join("hello.grix")).unwrap();
    let image = grix::Image::open(dir.join("hello.grix")).unwrap();
    assert_eq!(image.config.command, ["/bin/sh", "/app/hello.sh"]);
    assert!(image.config.source.as_deref().unwrap().contains("@sha256:"), "{:?}", image.config.source);
    assert!(image.config.env.contains(&"GREETING=hi".to_string()));

    let sb = Sandbox::builder().image(&image).unwrap().build().unwrap();
    let out = sb.run(sb.command()).unwrap();
    assert_eq!(out.status, ExitStatus::Exited(0), "{}{}", out.stderr_str(), out.kernel_log);
    let stdout = out.stdout_str();
    assert!(stdout.starts_with("hi from 3.21.") && stdout.ends_with(" in /app\n"), "{stdout:?}");
    // What build steps did is in the image, removals too; a bare command
    // name is found on the image's PATH.
    let out = sb.run(&["cat", "/app/stamp", "/app/note"]).unwrap();
    assert_eq!(out.stdout_str(), "built\na note");
    let out = sb.run(&["ls", "/etc/motd"]).unwrap();
    assert_eq!(out.status, ExitStatus::Exited(1));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn images_with_no_other_os() {
    // Just the grix kernel and static programs: no base image, and build
    // steps that need no shell. What the kernel makes at boot (/etc/passwd,
    // /tmp, ...) stays out of the image.
    use grix::build::{Copy, Grixfile, Step};
    let g = Grixfile {
        command: Some(vec!["/bin/hello".into(), "world".into()]),
        copies: vec![
            Copy { host: fixture("hello"), guest: "/bin/hello".into(), outside_context: true },
            Copy { host: fixture("alpine/bin/busybox.static"), guest: "/bin/busybox".into(), outside_context: true },
        ],
        run: vec![
            Step::Exec(vec!["/bin/busybox".into(), "mkdir".into(), "/data".into()]),
            Step::Exec(vec!["/bin/busybox".into(), "cp".into(), "/bin/hello".into(), "/data/copy".into()]),
        ],
        ..Default::default()
    };
    let image = g
        .build(
            Path::new("."),
            grix::build::BuildOptions {
                kernel: None,
                on_output: &mut |_, _| {},
                policy: Default::default(),
                control: None,
            },
        )
        .unwrap();
    let (n, _) = image.size();
    assert_eq!(n, 5, "only what was put in");
    let sb = Sandbox::builder().image(&image).unwrap().build().unwrap();
    let out = sb.run(sb.command()).unwrap();
    assert_eq!(out.status, ExitStatus::Exited(7));
    assert!(out.stdout_str().starts_with("hello from grix! argc=2\n"));
    let out = sb.run(&["/bin/busybox", "cmp", "/bin/hello", "/data/copy"]).unwrap();
    assert_eq!(out.status, ExitStatus::Exited(0));
}

#[test]
fn images_built_on_images_and_cached_steps() {
    // A base image whose build step leaves something new every time it
    // runs; the step cache gives the same result while nothing changed.
    use grix::build::{BuildOptions, BuildPolicy, Copy, Grixfile, Step};
    let dir = temp_dir("layered");
    let stamp = "/bin/busybox od -An -tx1 -N16 /dev/urandom > /stamp";
    let base = Grixfile {
        command: Some(vec!["/bin/busybox".into(), "cat".into(), "/stamp".into()]),
        capabilities: vec!["process".into()],
        copies: vec![Copy {
            host: fixture("alpine/bin/busybox.static"),
            guest: "/bin/busybox".into(),
            outside_context: true,
        }],
        run: vec![Step::Exec(vec!["/bin/busybox".into(), "sh".into(), "-c".into(), stamp.into()])],
        ..Default::default()
    };
    let build = |g: &Grixfile, cache: bool| {
        let mut log = Vec::new();
        let policy = BuildPolicy { cache, ..Default::default() };
        let image = g
            .build(
                &dir,
                BuildOptions { kernel: None, on_output: &mut |_, d| log.extend_from_slice(d), policy, control: None },
            )
            .unwrap();
        (image, String::from_utf8_lossy(&log).into_owned())
    };
    let stamp_of = |image: &grix::Image| {
        let sb = Sandbox::builder().image(image).unwrap().build().unwrap();
        let out = sb.run(sb.command()).unwrap();
        assert_eq!(out.status, ExitStatus::Exited(0), "{}", out.stderr_str());
        out.stdout_str()
    };
    let (first, _) = build(&base, true);
    let first_stamp = stamp_of(&first);
    let (again, log) = build(&base, true);
    assert!(log.contains("cached"), "{log}");
    assert_eq!(stamp_of(&again), first_stamp);
    let (fresh, log) = build(&base, false);
    assert!(!log.contains("cached"), "{log}");
    assert_ne!(stamp_of(&fresh), first_stamp);
    // Another image built on it: its files and settings, and more.
    first.write_to(dir.join("base.grix")).unwrap();
    let app = Grixfile::parse(
        r#"
from = "image:base.grix"
capabilities = ["threads"]
run = [["/bin/busybox", "cp", "/stamp", "/copy"]]
"#,
    )
    .unwrap();
    let (image, _) = build(&app, true);
    assert_eq!(image.config.command, ["/bin/busybox", "cat", "/stamp"]);
    assert_eq!(image.config.capabilities, ["process", "threads"]);
    let sb = Sandbox::builder().image(&image).unwrap().build().unwrap();
    let out = sb.run(&["/bin/busybox", "cat", "/copy"]).unwrap();
    assert_eq!(out.stdout_str(), first_stamp);
    // A base outside the build context is refused, as any path is.
    let outside = Grixfile::parse(&format!("from = \"image:{}\"", dir.join("base.grix").display())).unwrap();
    let elsewhere = temp_dir("elsewhere");
    let opts = BuildOptions { kernel: None, on_output: &mut |_, _| {}, policy: Default::default(), control: None };
    let err = outside.build(&elsewhere, opts).err().unwrap();
    assert!(err.to_string().contains("outside the build context"), "{err:#}");
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_dir_all(&elsewhere).unwrap();
}

// ---------------------------------------------------------------- signals from the host

fn hostsig() -> SandboxBuilder {
    with("hostsig").allow(Capability::Process).allow(Capability::FsWrite).export("/out").unwrap()
}

#[test]
fn signals_from_the_host() {
    // SIGINT reaches the program and its child (its process group); SIGTERM
    // makes it clean up, and its exports come back.
    let control = RunControl::new();
    let sb = hostsig().control(&control).build().unwrap();
    let c = control.clone();
    let (mut seen, mut int_sent, mut term_sent) = (String::new(), false, false);
    let out = sb
        .run_streaming(&["/bin/hostsig"], |stream, data| {
            if stream != Stream::Stdout {
                return;
            }
            seen.push_str(&String::from_utf8_lossy(data));
            if !int_sent && seen.contains("ready\n") {
                int_sent = c.signal(2);
            }
            if !term_sent && seen.contains("parent got SIGINT\n") && seen.contains("child got SIGINT\n") {
                term_sent = c.signal(15);
            }
        })
        .unwrap();
    assert_eq!(out.status, ExitStatus::Exited(0), "{}{}", out.stdout_str(), out.kernel_log);
    let stdout = out.stdout_str();
    for line in ["ready", "parent got SIGINT", "child got SIGINT", "got SIGTERM"] {
        assert!(stdout.lines().any(|l| l == line), "{line:?} in {stdout:?}");
    }
    assert!(out.events.is_empty(), "{:?}", out.events);
    let ex = out.export("/out").unwrap();
    assert_eq!(ex.state, ExportState::Complete);
    assert_eq!(ex.entries[0].content, ExportContent::File(b"cleaned up\n".to_vec()));
    // Nothing is running now.
    assert!(!control.signal(15) && !control.stop());
}

#[test]
fn killed_from_the_host_while_running_elsewhere() {
    // A busy child the host's SIGINT kills (its parent ignores it), on
    // whichever CPU it runs: it ends at once, and its parent hears of it.
    for cpus in [1, 4] {
        let control = RunControl::new();
        let sb = hostsig().cpus(cpus).timeout(Duration::from_secs(30)).control(&control).build().unwrap();
        let c = control.clone();
        let mut sent = false;
        let out = sb
            .run_streaming(&["/bin/hostsig", "busy"], |_, data| {
                if !sent && String::from_utf8_lossy(data).contains("ready") {
                    sent = c.signal(2);
                }
            })
            .unwrap();
        assert_eq!(out.status, ExitStatus::Exited(0), "{cpus} CPUs: {}{}", out.stdout_str(), out.kernel_log);
        assert_eq!(out.stdout_str(), "ready\nchild ended by signal 2\n");
        assert!(out.duration < Duration::from_secs(10), "{cpus} CPUs: {:?}", out.duration);
    }
}

#[test]
fn stopped_and_continued_from_the_host() {
    // SIGTSTP from the host stops the program's process group (a shell and
    // the sleep it waits for) until SIGCONT; the host hears of both.
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let control = RunControl::new();
    let sb = Sandbox::builder()
        .timeout(Duration::from_secs(30))
        .import(fixture("alpine/bin/busybox.static"), "/bin/busybox")
        .unwrap()
        .allow(Capability::Process)
        .control(&control)
        .build()
        .unwrap();
    let ticks = Arc::new(AtomicUsize::new(0));
    let (c, t) = (control.clone(), ticks.clone());
    let counts = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = counts.clone();
    let script = "while :; do echo t; /bin/busybox usleep 20000; done";
    let out = sb
        .run_streaming(&["/bin/busybox", "sh", "-c", script], |_, data| {
            let n = data.iter().filter(|&&b| b == b'\n').count();
            if t.fetch_add(n, Ordering::SeqCst) == 0 {
                let (c, t, seen) = (c.clone(), t.clone(), seen.clone());
                std::thread::spawn(move || {
                    let at = |ms| {
                        std::thread::sleep(Duration::from_millis(ms));
                        seen.lock().unwrap().push(t.load(Ordering::SeqCst));
                    };
                    c.signal(20);
                    at(300);
                    at(500);
                    c.signal(18);
                    // Ticking again (slow emulation under load takes a while).
                    for _ in 0..100 {
                        std::thread::sleep(Duration::from_millis(50));
                        if t.load(Ordering::SeqCst) > seen.lock().unwrap()[1] + 2 {
                            break;
                        }
                    }
                    at(0);
                    c.signal(15);
                });
            }
        })
        .unwrap();
    assert_eq!(out.status, ExitStatus::Signaled(15), "{:?} {}", out.events, out.kernel_log);
    let counts = counts.lock().unwrap().clone();
    assert_eq!(counts[0], counts[1], "ticks while stopped: {counts:?}");
    assert!(counts[2] > counts[1] + 2, "ticks after SIGCONT: {counts:?}");
    // (Then SIGTERM's default action ends it, which the host hears of too.)
    assert!(
        matches!(
            &out.events[..],
            [GuestEvent::Stopped { signal: 20 }, GuestEvent::Continued, GuestEvent::Fault { signal: 15, .. }]
        ),
        "{:?}",
        out.events
    );
}

#[test]
fn a_timeout_sends_sigterm_first() {
    // Out of time: SIGTERM, and the program's exports come back if it ends
    // within the grace period. Without one, it's stopped at once.
    let out = hostsig().timeout(Duration::from_secs(2)).build().unwrap().run(&["/bin/hostsig"]).unwrap();
    assert_eq!(out.status, ExitStatus::Timeout, "{:?} {}", out.events, out.kernel_log);
    assert!(out.stdout_str().ends_with("got SIGTERM\n"), "{}", out.stdout_str());
    let ex = out.export("/out").unwrap();
    assert_eq!((ex.state, ex.entries.len()), (ExportState::Complete, 1));

    let sb = hostsig().timeout(Duration::from_secs(3)).grace(Duration::ZERO).build().unwrap();
    let out = sb.run(&["/bin/hostsig"]).unwrap();
    assert_eq!(out.status, ExitStatus::Timeout);
    assert_eq!(out.stdout_str(), "ready\n");
    assert_eq!(out.export("/out").unwrap().state, ExportState::Incomplete);
}

#[test]
fn waiting_for_a_host_signal_is_not_a_deadlock() {
    // With a control attached, a program that only waits for a signal may
    // get one; without handlers, SIGTERM ends it. stop() ends a run outright.
    let control = RunControl::new();
    let sb = with("hostsig").control(&control).build().unwrap();
    let c = control.clone();
    let out = sb
        .run_streaming(&["/bin/hostsig", "plain"], |_, data| {
            if data.starts_with(b"ready") {
                let c = c.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(300));
                    c.signal(15);
                });
            }
        })
        .unwrap();
    assert_eq!(out.status, ExitStatus::Signaled(15), "{:?} {}", out.events, out.kernel_log);
    assert_eq!(out.stdout_str(), "ready\n");
    assert!(!out.events.iter().any(|e| e.to_string().contains("deadlock")), "{:?}", out.events);

    // The same, after a child that was the last to run has exited (the
    // scheduler once spun there, never reading the host's signal).
    let sb2 = with("hostsig").allow(Capability::Process).control(&control).build().unwrap();
    let c = control.clone();
    let out = sb2
        .run_streaming(&["/bin/hostsig", "child"], |_, data| {
            if data.starts_with(b"ready") {
                let c = c.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(600));
                    c.signal(15);
                });
            }
        })
        .unwrap();
    assert_eq!(out.status, ExitStatus::Signaled(15), "{:?} {}", out.events, out.kernel_log);

    let c = control.clone();
    let out = sb
        .run_streaming(&["/bin/hostsig", "plain"], |_, data| {
            if data.starts_with(b"ready") {
                c.stop();
            }
        })
        .unwrap();
    assert_eq!(out.status, ExitStatus::Stopped);
    assert_eq!(out.status.code(), 137);

    // Output doesn't keep a run going: stop() and the time limit end one
    // that writes all the time too.
    let c = control.clone();
    let started = std::time::Instant::now();
    let out = sb
        .run_streaming(&["/bin/hostsig", "chatty"], |_, data| {
            if data.starts_with(b"ready") {
                let c = c.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(500));
                    c.stop();
                });
            }
        })
        .unwrap();
    assert_eq!(out.status, ExitStatus::Stopped);
    assert!(started.elapsed() < Duration::from_secs(30), "{:?}", started.elapsed());
    let sb = with("hostsig").timeout(Duration::from_secs(2)).grace(Duration::from_secs(1)).build().unwrap();
    let out = sb.run(&["/bin/hostsig", "chatty"]).unwrap();
    assert_eq!(out.status, ExitStatus::Timeout);
    assert!(out.stdout_str().contains("still here"));
}

// ---------------------------------------------------------------- real-world binaries (Alpine)

fn temp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("grix-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.canonicalize().unwrap()
}

#[test]
fn live_mount_works_on_the_host_directory() {
    use std::os::unix::fs::PermissionsExt;
    let host = temp_dir("live");
    std::fs::create_dir(host.join("sub")).unwrap();
    std::fs::create_dir(host.join("inbox")).unwrap();
    std::fs::create_dir(host.join("locked")).unwrap();
    std::fs::set_permissions(host.join("locked"), std::fs::Permissions::from_mode(0o000)).unwrap();
    std::fs::write(host.join("a.txt"), "hello\n").unwrap();
    std::os::unix::fs::symlink("a.txt", host.join("link")).unwrap();
    // Outside the mount, where a link the program makes points.
    let outside = temp_dir("live-outside");
    std::fs::write(outside.join("secret"), "no\n").unwrap();
    let sb = Sandbox::builder()
        .import(fixture("alpine/bin/busybox.static"), "/bin/busybox")
        .unwrap()
        .mount(&host, "/work")
        .unwrap()
        .allow(Capability::Process)
        .cwd("/work")
        .build()
        .unwrap();
    let script = format!(
        "b=/bin/busybox
        $b cat link
        echo more >> a.txt
        echo new > sub/new.txt
        $b mkdir d2
        $b mv sub/new.txt d2/moved.txt
        $b rm link
        $b chmod 600 a.txt
        $b ln -s {outside} out
        echo through > out/secret 2>/dev/null; echo \"write through link: $?\"
        $b ln a.txt hard 2>&1 | $b grep -o 'Operation not permitted'
        $b mv /work /elsewhere 2>&1 | $b grep -o 'Resource busy'
        $b dd if=/dev/zero of=big bs=1k count=3000 2>/dev/null
        $b sha256sum big | $b cut -c1-16
        # Removed while open: still readable through the descriptor.
        echo kept > gone.txt; exec 3< gone.txt; $b rm gone.txt; $b cat <&3; exec 3<&-
        $b ls locked 2>&1 | $b grep -o 'Permission denied'
        $b chown 0 a.txt 2>&1 | $b grep -o 'Operation not permitted'
        # Ready: the host adds a file, which shows up here.
        $b touch ready
        cd /
        i=0; while [ ! -e /work/inbox/from-host ] && [ $i -lt 300 ]; do $b sleep 0.1; i=$((i+1)); done
        $b cat /work/inbox/from-host",
        outside = outside.display()
    );
    let watcher = {
        let host = host.clone();
        std::thread::spawn(move || {
            // Patient: under emulation the guest takes a while to get there.
            for _ in 0..3000 {
                if host.join("ready").exists() {
                    std::fs::write(host.join("inbox/from-host"), "hi from the host\n").unwrap();
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        })
    };
    let out = sb.run(&["/bin/busybox", "sh", "-c", &script]).unwrap();
    watcher.join().unwrap();
    assert_eq!(out.status, ExitStatus::Exited(0), "{}{}", out.stderr_str(), out.kernel_log);
    assert_eq!(
        out.stdout_str(),
        "hello\nwrite through link: 1\nOperation not permitted\nResource busy\n\
         76ed5c9c326ba623\nkept\nPermission denied\nOperation not permitted\nhi from the host\n"
    );
    assert!(
        out.events.iter().all(|e| matches!(e, GuestEvent::MissingPath { path } if path == "/elsewhere")),
        "{:?}",
        out.events
    );
    // Everything happened on the host, at once.
    let read = |p: &str| std::fs::read_to_string(host.join(p)).unwrap();
    assert_eq!(read("a.txt"), "hello\nmore\n");
    assert_eq!(read("d2/moved.txt"), "new\n");
    assert!(!host.join("link").exists() && !host.join("sub/new.txt").exists() && !host.join("hard").exists());
    assert_eq!(std::fs::metadata(host.join("a.txt")).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(host.join("big")).unwrap().len(), 3000 * 1024);
    // The program's link was made, but it points into the guest's own
    // namespace, and the host never follows links: the host's file is safe.
    assert_eq!(std::fs::read_link(host.join("out")).unwrap(), outside);
    assert_eq!(std::fs::read_to_string(outside.join("secret")).unwrap(), "no\n");

    // Read-only: changes fail with EROFS and nothing changes.
    let ro = Sandbox::builder()
        .import(fixture("alpine/bin/busybox.static"), "/bin/busybox")
        .unwrap()
        .mount_read_only(&host, "/work")
        .unwrap()
        .allow(Capability::FsWrite)
        .build()
        .unwrap();
    let out = ro.run(&["/bin/busybox", "rm", "/work/a.txt"]).unwrap();
    assert_eq!(out.status, ExitStatus::Exited(1));
    assert!(out.stderr_str().contains("Read-only file system"), "{}", out.stderr_str());
    assert!(host.join("a.txt").exists());
    std::fs::set_permissions(host.join("locked"), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::remove_dir_all(&host).unwrap();
    std::fs::remove_dir_all(&outside).unwrap();
}

#[test]
fn live_mount_walks_trees_larger_than_the_kernel_keeps() {
    // More nodes than the kernel's budget holds at once: 10 directories of
    // 1,000 files, which it forgets once it's done with them, and one of
    // 40,200 entries, whose names it looks up one at a time.
    let host = temp_dir("live-big");
    let mut dirs: Vec<(String, usize)> = (0..10).map(|i| (format!("dir{i:02}"), 1000)).collect();
    dirs.push(("huge".into(), 40_000));
    for (name, n) in &dirs {
        let d = host.join(name);
        std::fs::create_dir(&d).unwrap();
        for j in 0..*n {
            std::fs::File::create(d.join(format!("a-somewhat-long-file-name-{j:05}.txt"))).unwrap();
        }
    }
    std::fs::write(host.join("huge/a-somewhat-long-file-name-01234.txt"), "found\n").unwrap();
    // Directories inside the large one, listed while it fills the budget.
    for i in 0..200 {
        let d = host.join(format!("huge/sub{i:03}"));
        std::fs::create_dir(&d).unwrap();
        for j in 0..5 {
            std::fs::File::create(d.join(format!("f{j}"))).unwrap();
        }
    }
    let sb = Sandbox::builder()
        .import(fixture("alpine/bin/busybox.static"), "/bin/busybox")
        .unwrap()
        .mount_read_only(&host, "/work")
        .unwrap()
        .allow(Capability::Process)
        // Three passes over 50,000 entries, which takes a while emulated.
        .timeout(Duration::from_secs(600))
        .build()
        .unwrap();
    let script = "b=/bin/busybox; $b find /work -type f | $b wc -l; $b ls /work/huge | $b wc -l
        $b cat /work/huge/a-somewhat-long-file-name-01234.txt
        $b stat -c %i /work/huge/a-somewhat-long-file-name-01234.txt
        $b ls -i /work/huge | $b grep 01234 | $b cut -d' ' -f1";
    let out = sb.run(&["/bin/busybox", "sh", "-c", script]).unwrap();
    assert_eq!(out.status, ExitStatus::Exited(0), "{}{}", out.stderr_str(), out.kernel_log);
    let lines: Vec<&str> = out.stdout_str().leak().lines().map(str::trim).collect();
    assert_eq!(lines[..3], ["51000", "40200", "found"]);
    // The same inode number from stat and getdents.
    assert_eq!(lines[3], lines[4]);
    assert!(out.events.is_empty(), "{:?}", out.events);
    std::fs::remove_dir_all(&host).unwrap();
}

#[test]
fn mounted_directory_changes_go_back() {
    use std::os::unix::fs::PermissionsExt;
    let host = std::env::temp_dir().join(format!("grix-mount-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&host);
    std::fs::create_dir_all(host.join("olddir")).unwrap();
    std::fs::create_dir_all(host.join("sub")).unwrap();
    let old = UNIX_EPOCH + Duration::from_secs(1_600_000_000);
    for (name, data) in [
        ("keep.txt", "keep\n"),
        ("edit.txt", "old\n"),
        ("gone.txt", "x"),
        ("olddir/f", "f"),
        ("mv-src.txt", "moved\n"),
        ("sub/deep.txt", "deep\n"),
    ] {
        std::fs::write(host.join(name), data).unwrap();
        std::fs::File::options().write(true).open(host.join(name)).unwrap().set_modified(old).unwrap();
    }
    // A mount at /etc gets none of the files the kernel would make there.
    let etc = std::env::temp_dir().join(format!("grix-mount-etc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&etc);
    std::fs::create_dir(&etc).unwrap();
    let sb = Sandbox::builder()
        .import(fixture("alpine/bin/busybox.static"), "/bin/busybox")
        .unwrap()
        .mount_on_exit(&host, "/work")
        .unwrap()
        .mount_on_exit(&etc, "/etc")
        .unwrap()
        .allow(Capability::Process)
        .cwd("/work")
        .build()
        .unwrap();
    let script = "set -e
        b=/bin/busybox
        $b stat -c %Y keep.txt
        echo new > edit.txt
        $b rm gone.txt
        $b rm -r olddir
        $b mv mv-src.txt renamed.txt
        $b mkdir -p made/inner
        echo hi > made/inner/x.txt
        $b ln -s renamed.txt link
        $b chmod 755 sub/deep.txt
        $b mv /work /elsewhere 2>&1 || true";
    let out = sb.run(&["/bin/busybox", "sh", "-c", script]).unwrap();
    assert_eq!(out.status, ExitStatus::Exited(0), "{}{}", out.stderr_str(), out.kernel_log);
    // Real host mtimes, and the mount point stays put.
    assert_eq!(out.stdout_str(), "1600000000\nmv: can't rename '/work': Resource busy\n");
    assert!(matches!(&out.events[..], [GuestEvent::MissingPath { path }] if path == "/elsewhere"), "{:?}", out.events);
    let m = &out.mount_changes[0];
    assert_eq!(m.state, grix::MountState::Applied);
    assert!(m.conflicts.is_empty(), "{m:?}");
    assert_eq!(m.removed, ["gone.txt", "mv-src.txt", "olddir"]);
    assert_eq!(
        m.written,
        ["edit.txt", "link", "made", "made/inner", "made/inner/x.txt", "renamed.txt", "sub/deep.txt"]
    );
    let read = |p: &str| std::fs::read_to_string(host.join(p)).unwrap();
    assert_eq!(
        (read("edit.txt"), read("renamed.txt"), read("made/inner/x.txt")),
        ("new\n".into(), "moved\n".into(), "hi\n".into())
    );
    assert!(!host.join("gone.txt").exists() && !host.join("olddir").exists() && !host.join("mv-src.txt").exists());
    assert_eq!(std::fs::read_link(host.join("link")).unwrap(), PathBuf::from("renamed.txt"));
    assert_eq!(std::fs::metadata(host.join("sub/deep.txt")).unwrap().permissions().mode() & 0o777, 0o755);
    // Untouched files aren't rewritten.
    assert_eq!(std::fs::metadata(host.join("keep.txt")).unwrap().modified().unwrap(), old);
    let etc_changes = &out.mount_changes[1];
    assert_eq!((etc_changes.written.len(), etc_changes.removed.len()), (0, 0), "{etc_changes:?}");
    assert_eq!(std::fs::read_dir(&etc).unwrap().count(), 0);

    // The next run sees the directory as it is now, and changes nothing.
    let out = sb.run(&["/bin/busybox", "sh", "-c", "/bin/busybox cat renamed.txt; /bin/busybox ls"]).unwrap();
    assert_eq!(out.stdout_str(), "moved\nedit.txt\nkeep.txt\nlink\nmade\nrenamed.txt\nsub\n");
    let m = &out.mount_changes[0];
    assert_eq!((m.state.clone(), m.written.len(), m.removed.len()), (grix::MountState::Applied, 0, 0));

    // Changes over max_export don't go back at all.
    let small = Sandbox::builder()
        .import(fixture("alpine/bin/busybox.static"), "/bin/busybox")
        .unwrap()
        .mount_on_exit(&host, "/work")
        .unwrap()
        .max_export(4096)
        .build()
        .unwrap();
    let out = small.run(&["/bin/busybox", "dd", "if=/dev/zero", "of=/work/big", "bs=1024", "count=64"]).unwrap();
    assert_eq!(out.status, ExitStatus::Exited(0), "{}", out.stderr_str());
    assert_eq!(out.mount_changes[0].state, grix::MountState::NotApplied);
    assert!(!host.join("big").exists());
    std::fs::remove_dir_all(&host).unwrap();
    std::fs::remove_dir_all(&etc).unwrap();
}

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
    assert_eq!(busybox(&sb, &["uname", "-sm"]).stdout_str(), format!("Linux {}\n", grix::Arch::from_env().name()));
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
fn processes() {
    // fork, vfork, posix_spawn, execve of imported and written programs and
    // #! scripts, wait4/waitid, SIGCHLD, orphans, process groups and
    // sessions, copy-on-write, the process limit (see the fixture).
    let b = with("procs")
        .allow(Capability::Process)
        .allow(Capability::Threads)
        .allow(Capability::FsWrite)
        .file("/data/plain.txt", "not a program\n", 0o644)
        .unwrap();
    let out = run(b, &["/bin/procs"]);
    assert_eq!(
        out.stdout_str(),
        "child: procs child via-execve K=from-parent pid_is_new=1\n\
         child: procs child via-vfork K=from-parent pid_is_new=1\n\
         child: procs child via-posix_spawn K=from-parent pid_is_new=1\n\
         child: procs2 child written K=from-parent pid_is_new=1\n\
         child: /tmp/procs2 child /tmp/script arg K=from-parent pid_is_new=1\n\
         procs ok\n"
    );
    assert_eq!(out.status, ExitStatus::Exited(0));
    // The missing program it tried, and the child it let crash.
    assert!(
        matches!(&out.events[..], [GuestEvent::MissingPath { path }, GuestEvent::Fault { signal: 11, detail, .. }]
            if path == "/no/such/program" && detail.starts_with("process ") && detail.contains("(procs): invalid write")),
        "{:?}",
        out.events
    );
}

#[test]
fn shell_pipelines_and_subshells() {
    let sb = Sandbox::builder()
        .allow(Capability::Process)
        .allow(Capability::FsWrite)
        .env("PATH", "/bin")
        .import(fixture("alpine/bin/busybox.static"), "/bin/busybox")
        .unwrap()
        .build()
        .unwrap();
    let script = "/bin/busybox --install -s /bin && echo hello world | tr a-z A-Z && ls /bin | grep -c . >/dev/null && \
                  x=$(echo sub; echo shell) && echo \"$x\" | sort -r && (exit 4); echo \"status $?\"; \
                  sh -c 'exit 7'; echo \"nested $?\"; seq 1 5 | while read n; do echo -n \"$n,\"; done; echo; exit 3";
    let out = sb.run(&["/bin/busybox", "sh", "-c", script]).unwrap();
    assert_eq!(out.stdout_str(), "HELLO WORLD\nsub\nshell\nstatus 4\nnested 7\n1,2,3,4,5,\n", "{}", out.stderr_str());
    assert_eq!(out.status, ExitStatus::Exited(3));
    assert!(out.events.is_empty(), "{:?}", out.events);
}

#[test]
fn go_os_exec() {
    let out = run(with("goexec").allow(Capability::Process).allow(Capability::Threads), &["/bin/goexec"]);
    assert_eq!(
        out.stdout_str(),
        "output \"child K=go\\n\" code 3\nupper \"PIPED THROUGH GO\" <nil>\nkilled: signal: killed\n\
         missing: fork/exec /no/such/program: no such file or directory\n",
        "{}",
        out.stderr_str()
    );
    assert_eq!(out.status, ExitStatus::Exited(0));
    // Go probes pidfd_open, and falls back without it.
    for e in &out.events {
        let fine = matches!(e, GuestEvent::Unimplemented { syscall, .. } if syscall == "pidfd_open")
            || matches!(e, GuestEvent::MissingPath { path } if path == "/no/such/program");
        assert!(fine, "{e}");
    }
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
    assert!(out.events.is_empty(), "{:?}", out.events);
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
    let first = out.stdout.iter().zip(&want).position(|(a, b)| a != b);
    assert!(out.stdout == want, "stdout differs: {} bytes, first difference at {first:?}", out.stdout.len());
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
fn job_control() {
    // Stopping and continuing other processes (and themselves), with every
    // thread; the parent hears of it through wait and SIGCHLD.
    let b = with("jobs").allow(Capability::Process).allow(Capability::Threads);
    let out = run(b, &["/bin/jobs"]);
    assert_eq!(out.stdout_str(), "jobs ok\n", "{}", out.kernel_log);
    assert_eq!(out.status, ExitStatus::Exited(0));
    assert!(out.events.is_empty(), "{:?}", out.events);
}

#[test]
fn pidfds() {
    let out = run(with("pidfd").allow(Capability::Process), &["/bin/pidfd"]);
    assert_eq!(out.stdout_str(), "pidfd ok\n", "{}", out.kernel_log);
    assert_eq!(out.status, ExitStatus::Exited(0));
    assert!(out.events.is_empty(), "{:?}", out.events);
}

#[test]
fn cpu_time_timers() {
    let b = with("cputimers").allow(Capability::Process).allow(Capability::Threads);
    let out = run(b, &["/bin/cputimers"]);
    assert_eq!(out.stdout_str(), "cputimers ok\n", "{}", out.kernel_log);
    assert_eq!(out.status, ExitStatus::Exited(0));
    assert!(out.events.is_empty(), "{:?}", out.events);
}

#[test]
fn stack_follows_rlimit() {
    // RLIMIT_STACK at exec sizes the stack: 32 MiB of it only works with a
    // bigger limit than the default 8 MiB.
    let b = with("stack").import(fixture("alpine/bin/busybox.static"), "/bin/sh").unwrap().allow(Capability::Process);
    let sb = b.build().unwrap();
    let out = sb.run(&["/bin/sh", "-c", "ulimit -s 65536 && exec /bin/stack 32"]).unwrap();
    assert_eq!(out.stdout_str(), "depth 32\n", "{}{}", out.stderr_str(), out.kernel_log);
    assert_eq!(out.status, ExitStatus::Exited(0));
    assert!(out.events.is_empty(), "{:?}", out.events);
    let out = sb.run(&["/bin/sh", "-c", "ulimit -s unlimited && exec /bin/stack 64"]).unwrap();
    assert_eq!(out.stdout_str(), "depth 64\n", "{}{}", out.stderr_str(), out.kernel_log);
    let out = sb.run(&["/bin/stack", "32"]).unwrap();
    assert_eq!(out.status, ExitStatus::Signaled(11), "{}", out.stdout_str());
    assert!(matches!(&out.events[..], [GuestEvent::Fault { signal: 11, .. }]), "{:?}", out.events);
}

#[test]
fn vdso() {
    let out = run(with("vdso").allow(Capability::Process), &["/bin/vdso"]);
    assert_eq!(out.stdout_str(), "vdso ok\n", "{}", out.kernel_log);
    assert_eq!(out.status, ExitStatus::Exited(0));
    assert!(out.events.is_empty(), "{:?}", out.events);
}

#[test]
fn processes_in_parallel() {
    // One CPU on x86_64 (yet).
    if x86_64_guest() {
        return;
    }
    // With four CPUs, three busy processes run at once (their CPU time is
    // nearly three times the wall time); with one, they take turns.
    let ratio = |cpus: u32| {
        let out = run(with("parallel").allow(Capability::Process).cpus(cpus), &["/bin/parallel", "3"]);
        assert_eq!(out.status, ExitStatus::Exited(0), "{}", out.kernel_log);
        assert!(out.events.is_empty(), "{:?}", out.events);
        out.stdout_str().trim().parse::<f64>().unwrap()
    };
    let (four, one) = (ratio(4), ratio(1));
    assert!(four > 2.0, "4 CPUs: {four}");
    assert!(one < 1.2, "1 CPU: {one}");
}

#[test]
fn pseudo_terminals() {
    // The line discipline, controlling terminals and their signals.
    let out = run(with("pty").allow(Capability::Process), &["/bin/pty"]);
    assert_eq!(out.stdout_str(), "pty ok\n", "{}", out.kernel_log);
    assert_eq!(out.status, ExitStatus::Exited(0));
    assert!(out.events.is_empty(), "{:?}", out.events);
}

/// stdin for a run, written as the test goes.
struct Typed(std::sync::mpsc::Receiver<Vec<u8>>, Vec<u8>);

impl std::io::Read for Typed {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.1.is_empty() {
            match self.0.recv() {
                Ok(v) => self.1 = v,
                Err(_) => return Ok(0),
            }
        }
        let n = buf.len().min(self.1.len());
        buf[..n].copy_from_slice(&self.1[..n]);
        self.1.drain(..n);
        Ok(n)
    }
}

#[test]
fn tty_mode() {
    // The program's stdio is a terminal: one stream, CR LF, the shell's
    // stderr too; with nothing typed, a shell reading it gets end-of-file.
    let b = Sandbox::builder()
        .timeout(Duration::from_secs(30))
        .import(fixture("alpine/bin/busybox.static"), "/bin/busybox")
        .unwrap()
        .allow(Capability::Process)
        .tty(24, 80);
    let out = b
        .clone()
        .build()
        .unwrap()
        .run(&["/bin/busybox", "sh", "-c", "echo a; /bin/busybox tty; echo b >&2; read x; echo eof $?"])
        .unwrap();
    assert_eq!(out.stdout_str(), "a\r\n/dev/pts/0\r\nb\r\neof 1\r\n", "{}", out.kernel_log);
    assert_eq!(out.status, ExitStatus::Exited(0));
    assert!(out.events.is_empty(), "{:?}", out.events);

    // An interactive shell: what's typed is echoed, the size is the host's
    // (and changes), and Ctrl-C interrupts the foreground job.
    let control = RunControl::new();
    let sb = b.env("PS1", "$ ").control(&control).build().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let mut seen = String::new();
    let mut step = 0;
    let out = sb
        .run_streaming_with_stdin(&["/bin/busybox", "sh", "-i"], Typed(rx, Vec::new()), |_, data| {
            seen.push_str(&String::from_utf8_lossy(data));
            let type_in = |s: &str| {
                let tx = tx.clone();
                let s = s.as_bytes().to_vec();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(200));
                    let _ = tx.send(s);
                });
            };
            let next = ["$ ", "24 80\r\n", "40 120\r\n", "sleep 30\r\n", "rc=130\r\n"];
            if step < next.len() && seen.contains(next[step]) {
                match step {
                    0 => type_in("/bin/busybox tty; /bin/busybox stty size\n"),
                    1 => {
                        control.resize(40, 120);
                        type_in("/bin/busybox stty size\n")
                    }
                    2 => type_in("/bin/busybox sleep 30\n"),
                    3 => {
                        type_in("\x03");
                        std::thread::sleep(Duration::from_millis(400));
                        type_in("echo rc=$?\n")
                    }
                    _ => type_in("exit\n"),
                }
                step += 1;
            }
        })
        .unwrap();
    let stdout = out.stdout_str();
    assert_eq!(out.status, ExitStatus::Exited(0), "{stdout}\n{}", out.kernel_log);
    for want in
        ["/bin/busybox tty; /bin/busybox stty size\r\n/dev/pts/0\r\n24 80\r\n", "40 120\r\n", "^C", "rc=130\r\n"]
    {
        assert!(stdout.contains(want), "{want:?} in {stdout:?}");
    }
    // (An interactive ash looks for mail.)
    assert!(out.events.iter().all(|e| matches!(e, GuestEvent::MissingPath { .. })), "{:?}", out.events);
}

#[test]
fn shared_file_mappings_and_locks() {
    let b = with("filelocks")
        .allow(Capability::Process)
        .allow(Capability::FsWrite)
        .file("/data/blob", vec![b'A'; 8192], 0o644)
        .unwrap();
    let out = run(b, &["/bin/filelocks"]);
    assert_eq!(out.stdout_str(), "filelocks ok\n", "{}", out.kernel_log);
    assert_eq!(out.status, ExitStatus::Exited(0));
    assert!(out.events.is_empty(), "{:?}", out.events);
}

#[test]
fn lazy_imports() {
    // Read from the host as used; what the program changes is copied into
    // the sandbox first and stays there; the host's directory never changes.
    let host = temp_dir("lazy");
    std::fs::create_dir(host.join("sub")).unwrap();
    std::fs::write(host.join("a.txt"), "hello\n").unwrap();
    std::fs::write(host.join("sub/b.txt"), "bee\n").unwrap();
    std::fs::create_dir(host.join("full")).unwrap();
    std::fs::write(host.join("full/x"), "x").unwrap();
    // Too big to copy in: emptying or truncating them reads none of it.
    for name in ["huge", "huge2"] {
        std::fs::File::create(host.join(name)).unwrap().set_len(1 << 30).unwrap();
    }
    let b = Sandbox::builder()
        .import(fixture("alpine/bin/busybox.static"), "/bin/busybox")
        .unwrap()
        .allow(Capability::Process)
        .import_lazy(&host, "/data")
        .unwrap();
    let script = "b() { /bin/busybox \"$@\"; }; cd /data; i=$(b stat -c %i a.txt); b cat a.txt sub/b.txt; \
                  echo more >> a.txt; echo new > sub/c.txt; b rm sub/b.txt; b mv a.txt sub/a2.txt; \
                  b chmod 600 sub/a2.txt; b ls sub; b cat sub/a2.txt; [ \"$i\" = \"$(b stat -c %i sub/a2.txt)\" ] && echo same; \
                  [ -e sub/nope ] || [ -e nope ] || echo absent; b rm -f nonexistent && b mkdir -p sub && echo fine; \
                  b rmdir full 2>&1; echo hi > huge; b cat huge; b truncate -s 4 huge2; b wc -c < huge2";
    let out = run(b.clone().allow(Capability::FsWrite), &["/bin/busybox", "sh", "-c", script]);
    assert_eq!(
        out.stdout_str(),
        "hello\nbee\na2.txt\nc.txt\nhello\nmore\nsame\nabsent\nfine\nrmdir: 'full': Directory not empty\nhi\n4\n",
        "{}",
        out.stderr_str()
    );
    assert_eq!(out.status, ExitStatus::Exited(0));
    assert!(out.events.is_empty(), "{:?}", out.events);
    assert_eq!(std::fs::read_to_string(host.join("a.txt")).unwrap(), "hello\n");
    assert_eq!(std::fs::read_to_string(host.join("sub/b.txt")).unwrap(), "bee\n");
    assert!(!host.join("sub/c.txt").exists());
    // Without fs_write, as for imports: denied.
    let out = run(b.clone(), &["/bin/busybox", "sh", "-c", "echo x >> /data/a.txt"]);
    assert_eq!(out.status, ExitStatus::Exited(1));
    assert!(
        matches!(&out.events[..], [GuestEvent::Denied { capability, .. }] if capability == "fs_write"),
        "{:?}",
        out.events
    );

    // A file changed on the host after the program saw it reads as EIO,
    // not as a mixture.
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let path = host.join("a.txt");
    let sb = b.build().unwrap();
    let script = "/bin/busybox cat /data/a.txt; echo ready; read x; /bin/busybox cat /data/a.txt || echo failed";
    let out = sb
        .run_streaming_with_stdin(&["/bin/busybox", "sh", "-c", script], Typed(rx, Vec::new()), |_, data| {
            if data.windows(5).any(|w| w == b"ready") {
                std::fs::write(&path, "changed!\n").unwrap();
                tx.send(b"go\n".to_vec()).unwrap();
            }
        })
        .unwrap();
    assert_eq!(out.stdout_str(), "hello\nready\nfailed\n", "{}", out.stderr_str());
    assert!(out.stderr_str().contains("I/O error"), "{}", out.stderr_str());
}

#[test]
fn unix_sockets() {
    // Paths, abstract names, datagrams, seqpackets, credentials, SCM_RIGHTS.
    let b = with("unixsock").allow(Capability::FsWrite).allow(Capability::Process);
    let out = run(b, &["/bin/unixsock"]);
    assert_eq!(out.stdout_str(), "unixsock ok\n", "{}", out.kernel_log);
    assert_eq!(out.status, ExitStatus::Exited(0));
    assert!(out.events.is_empty(), "{:?}", out.events);
}

#[test]
fn udp_beyond_dns() {
    // Between the guest's own sockets, without the host.
    let out = run(with("udp").allow(Capability::Net), &["/bin/udp", "local"]);
    assert_eq!(out.stdout_str(), "udp local ok\n", "{}", out.kernel_log);
    assert!(out.events.is_empty(), "{:?}", out.events);

    // Through the host to a destination the policy allows, and only its
    // replies come back.
    let echo = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = echo.local_addr().unwrap().port();
    echo.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let server = std::thread::spawn(move || {
        let mut buf = [0u8; 64];
        for _ in 0..3 {
            let (n, from) = echo.recv_from(&mut buf).unwrap();
            echo.send_to(&buf[..n], from).unwrap();
        }
    });
    let b = with("udp").allow(Capability::Net).allow_host(&format!("host.grix.internal:{port}")).unwrap();
    let out = run(b, &["/bin/udp", "echo", &port.to_string()]);
    assert_eq!(out.stdout_str(), "udp echo ok\n", "{}", out.kernel_log);
    assert!(out.events.is_empty(), "{:?}", out.events);
    server.join().unwrap();

    // Anywhere else: EPERM, and the host says why.
    let b = with("udp").allow(Capability::Net).allow_host(&format!("host.grix.internal:{port}")).unwrap();
    let out = run(b, &["/bin/udp", "denied", &(port ^ 1).to_string()]);
    assert_eq!(out.stdout_str(), "udp denied ok\n", "{}", out.kernel_log);
    assert!(
        matches!(&out.events[..], [GuestEvent::Denied { capability, .. }] if capability == "allow_host"),
        "{:?}",
        out.events
    );
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

/// Every process has a /proc/<pid> (gone when it ends), and /proc/self is
/// the caller's.
#[test]
fn proc_for_every_process() {
    let sb = Sandbox::builder()
        .import(fixture("alpine/bin/busybox.static"), "/bin/busybox")
        .unwrap()
        .allow(Capability::Process)
        .build()
        .unwrap();
    let script = r#"
        cd /tmp
        /bin/busybox sleep 30 &
        kid=$!
        /bin/busybox sleep 0.2
        echo "kid $(/bin/busybox cat /proc/$kid/cmdline | /bin/busybox tr '\0' ' ')"
        echo "exe $(/bin/busybox readlink /proc/$kid/exe)"
        echo "cwd $(/bin/busybox readlink /proc/$kid/cwd)"
        echo "ppid $(/bin/busybox awk '/^PPid/ {print $2}' /proc/$kid/status)"
        echo "fds $(/bin/busybox ls /proc/$kid/fd | /bin/busybox wc -l)"
        /bin/busybox sh -c 'echo "self $$ $(exec /bin/busybox readlink /proc/self)"'
        /bin/busybox ps -o pid,args | /bin/busybox grep "^ *$kid " | /bin/busybox sed 's/^ *[0-9]* //'
        kill $kid
        wait $kid
        [ -d /proc/$kid ] || echo gone
        cd -P /proc/self && echo "init $(pwd)"
    "#;
    let out = sb.run(&["/bin/busybox", "sh", "-c", script]).unwrap();
    assert_eq!(out.status, ExitStatus::Exited(0), "{}{}", out.stderr_str(), out.kernel_log);
    assert!(out.events.is_empty(), "{:?}", out.events);
    let text = out.stdout_str();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "kid /bin/busybox sleep 30 ", "{text}");
    assert_eq!(lines[1], "exe /bin/busybox", "{text}");
    assert_eq!(lines[2], "cwd /tmp", "{text}");
    assert_eq!(lines[3], "ppid 1", "{text}");
    assert!(lines[4].starts_with("fds ") && lines[4] != "fds 0", "{text}");
    // readlink, a process of its own, sees itself as /proc/self.
    let self_line: Vec<&str> = lines[5].split(' ').collect();
    assert_eq!(self_line[0], "self", "{text}");
    assert_ne!(self_line[2], "1", "{text}");
    assert_eq!(lines[6], "/bin/busybox sleep 30", "{text}");
    assert_eq!(lines[7], "gone", "{text}");
    assert_eq!(lines[8], "init /proc/1", "{text}");
}

/// A stand-in kernel, hand-assembled: it writes `serial` to the PL011 and
/// powers off, which is what the real one does when it panics.
fn fake_kernel(serial: &[u8]) -> Vec<u8> {
    if x86_64_guest() {
        return fake_kernel_x86_64(serial);
    }
    const BASE: u64 = 0x4020_0000;
    assert!(serial.len() < 1 << 16);
    let code: [u32; 13] = [
        0xd2a1_2001,                              // movz x1, #0x0900, lsl #16   (the PL011)
        0x5280_2022,                              // movz w2, #0x101
        0xb900_3022,                              // str  w2, [x1, #0x30]        (UARTCR: on, transmit)
        0x1000_0143,                              // adr  x3, serial             (40 bytes on)
        0xd280_0004 | (serial.len() as u32) << 5, // movz x4, #len
        0x3840_1462,                              // ldrb w2, [x3], #1
        0xb900_0022,                              // str  w2, [x1]               (UARTDR)
        0xf100_0484,                              // subs x4, x4, #1
        0x54ff_ffa1,                              // b.ne (the ldrb)
        0xd280_0100,                              // movz x0, #8
        0xf2b0_8000,                              // movk x0, #0x8400, lsl #16   (PSCI SYSTEM_OFF)
        0xd400_0002,                              // hvc  #0
        0x1400_0000,                              // b    .
    ];
    let mut segment: Vec<u8> = code.iter().flat_map(|i| i.to_le_bytes()).collect();
    segment.extend_from_slice(serial);
    segment.extend_from_slice(&grix_abi::abi_marker());
    let mut elf = Vec::new();
    elf.extend_from_slice(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0");
    elf.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    elf.extend_from_slice(&183u16.to_le_bytes()); // EM_AARCH64
    elf.extend_from_slice(&1u32.to_le_bytes());
    elf.extend_from_slice(&BASE.to_le_bytes()); // entry
    elf.extend_from_slice(&64u64.to_le_bytes()); // program headers
    elf.extend_from_slice(&0u64.to_le_bytes()); // no section headers
    elf.extend_from_slice(&0u32.to_le_bytes());
    for v in [64u16, 56, 1, 64, 0, 0] {
        elf.extend_from_slice(&v.to_le_bytes());
    }
    elf.extend_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    elf.extend_from_slice(&7u32.to_le_bytes()); // rwx
    for v in [0x1000, BASE, BASE, segment.len() as u64, segment.len() as u64, 0x1000] {
        elf.extend_from_slice(&v.to_le_bytes());
    }
    elf.resize(0x1000, 0);
    elf.extend_from_slice(&segment);
    elf
}

/// An x86_64 kernel that writes `serial` to COM1 and ends (a triple fault),
/// entered by PVH (32-bit protected mode) as the real one is.
fn fake_kernel_x86_64(serial: &[u8]) -> Vec<u8> {
    const BASE: u32 = 0x20_0000;
    // The code, then the 6-byte empty IDT descriptor, the PVH note, the bytes.
    let code_len = 29u32;
    let idtr = BASE + code_len;
    let note = idtr + 8;
    let bytes = note + 20;
    let mut code = vec![0x66, 0xba, 0xf8, 0x03]; // mov $0x3f8, %dx
    code.push(0xbe); // mov $bytes, %esi
    code.extend_from_slice(&bytes.to_le_bytes());
    code.push(0xb9); // mov $len, %ecx
    code.extend_from_slice(&(serial.len() as u32).to_le_bytes());
    code.extend_from_slice(&[0xac, 0xee, 0xe2, 0xfc]); // lodsb; out %al, %dx; loop
    code.extend_from_slice(&[0x0f, 0x01, 0x1d]); // lidt (idtr)
    code.extend_from_slice(&idtr.to_le_bytes());
    code.extend_from_slice(&[0xcc, 0xf4, 0xeb, 0xfd]); // int3; hlt; jmp .
    assert_eq!(code.len() as u32, code_len);
    let mut segment = code;
    segment.extend_from_slice(&[0; 8]);
    // XEN_ELFNOTE_PHYS32_ENTRY: "Xen", the entry.
    for v in [4u32, 4, 18] {
        segment.extend_from_slice(&v.to_le_bytes());
    }
    segment.extend_from_slice(b"Xen\0");
    segment.extend_from_slice(&BASE.to_le_bytes());
    segment.extend_from_slice(serial);
    segment.extend_from_slice(&grix_abi::abi_marker());
    let mut elf = Vec::new();
    elf.extend_from_slice(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0");
    elf.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    elf.extend_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    elf.extend_from_slice(&1u32.to_le_bytes());
    elf.extend_from_slice(&(BASE as u64).to_le_bytes()); // entry
    elf.extend_from_slice(&64u64.to_le_bytes()); // program headers
    elf.extend_from_slice(&0u64.to_le_bytes()); // no section headers
    elf.extend_from_slice(&0u32.to_le_bytes());
    for v in [64u16, 56, 2, 64, 0, 0] {
        elf.extend_from_slice(&v.to_le_bytes());
    }
    let len = segment.len() as u64;
    elf.extend_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    elf.extend_from_slice(&7u32.to_le_bytes()); // rwx
    for v in [0x1000, BASE as u64, BASE as u64, len, len, 0x1000] {
        elf.extend_from_slice(&v.to_le_bytes());
    }
    elf.extend_from_slice(&4u32.to_le_bytes()); // PT_NOTE
    elf.extend_from_slice(&4u32.to_le_bytes());
    let at = (note - BASE) as u64;
    for v in [0x1000 + at, note as u64, note as u64, 20, 20, 4] {
        elf.extend_from_slice(&v.to_le_bytes());
    }
    elf.resize(0x1000, 0);
    elf.extend_from_slice(&segment);
    elf
}

/// What a kernel says on the serial port (early boot, panics) reaches the
/// host, whichever VMM runs it.
#[test]
fn kernel_panics_come_through_the_serial_port() {
    use grix_abi::wire::{Channel, ExitKind, encode_exit, frame_header};
    let msg = b"kernel panic: a stand-in";
    let mut serial = frame_header(Channel::Log, msg.len()).to_vec();
    serial.extend_from_slice(msg);
    serial.extend_from_slice(&frame_header(Channel::Exit, 5));
    serial.extend_from_slice(&encode_exit(ExitKind::Panic, -1));
    let kernel = temp_dir("fake-kernel").join("kernel");
    std::fs::write(&kernel, fake_kernel(&serial)).unwrap();
    let default = Sandbox::builder();
    let mut backends = vec![("default", default.clone())];
    if default.vmm_path().is_some() {
        backends.push(("qemu", default.accel("tcg")));
    }
    for (name, b) in backends {
        let out = b.kernel(&kernel).timeout(Duration::from_secs(30)).build().unwrap().run(&["/x"]).unwrap();
        assert_eq!(out.status, ExitStatus::KernelPanic, "{name}: {}", out.kernel_log);
        assert!(out.kernel_log.contains("kernel panic: a stand-in"), "{name}: {}", out.kernel_log);
    }
}

/// On arm64 macOS 15+ and on arm64 Linux with KVM, runs use grix's own VMM
/// (`make vmm`) unless QEMU is asked for.
#[test]
fn the_default_vmm() {
    let qemu_asked = std::env::var_os("GRIX_ACCEL").is_some_and(|v| !v.is_empty())
        || std::env::var_os("GRIX_VMM").is_some_and(|v| v == "qemu");
    let kvm = std::fs::OpenOptions::new().read(true).write(true).open("/dev/kvm").is_ok();
    let macos_15 = std::process::Command::new("sw_vers")
        .arg("-productVersion")
        .output()
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).split('.').next()?.trim().parse::<u32>().ok())
        .is_some_and(|v| v >= 15);
    // grix-vmm runs the host's own architecture's guests: arm64 on macOS
    // 15+ or KVM, x86_64 on KVM.
    let native = if x86_64_guest() {
        cfg!(target_arch = "x86_64") && cfg!(target_os = "linux") && kvm
    } else {
        cfg!(target_arch = "aarch64") && (cfg!(target_os = "macos") && macos_15 || cfg!(target_os = "linux") && kvm)
    };
    if native && !qemu_asked {
        let vmm = Sandbox::builder().vmm_path().map(Path::to_path_buf);
        assert!(vmm.as_ref().is_some_and(|p| p.is_file()), "grix-vmm not found: run `make vmm`");
    } else {
        assert!(Sandbox::builder().vmm_path().is_none());
    }
    assert!(Sandbox::builder().accel("hvf").vmm_path().is_none(), "an accelerator means QEMU");
}

/// A machine saved when its program first waits for input, and runs from
/// there: each its own (stdin, randomness), at the right time of day.
#[test]
fn snapshots_in_tty_mode() {
    // Not on x86_64 yet (`snapshots_resume_where_the_program_waited` checks it says so).
    if x86_64_guest() {
        return;
    }
    // An interactive shell, saved at its prompt: each run types into its
    // terminal, whose size is the runner's.
    let b = Sandbox::builder()
        .cpus(1)
        .import(fixture("alpine/bin/busybox.static"), "/bin/busybox")
        .unwrap()
        .allow(Capability::Process)
        .env("PS1", "$ ")
        .timeout(Duration::from_secs(30))
        .tty(24, 80);
    if b.vmm_path().is_none() {
        return; // snapshots_resume_where_the_program_waited checks the error
    }
    let dir = temp_dir("ttysnap");
    let snap = b.build().unwrap().snapshot(&["/bin/busybox", "sh", "-i"], dir.join("sh.snap")).unwrap();
    assert!(snap.tty());
    for (rows, cols) in [(33, 111), (40, 120)] {
        let control = RunControl::new();
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let c = control.clone();
        std::thread::spawn(move || {
            // Once it runs: the size, then the typing.
            while !c.resize(rows, cols) {
                std::thread::sleep(Duration::from_millis(10));
            }
            std::thread::sleep(Duration::from_millis(100));
            let _ = tx.send(b"/bin/busybox stty size; echo $((6*7)); exit\n".to_vec());
        });
        let out = snap.clone().control(&control).run_streaming(Typed(rx, Vec::new()), |_, _| {}).unwrap();
        assert_eq!(out.status, ExitStatus::Exited(0), "{}{}", out.stdout_str(), out.kernel_log);
        let stdout = out.stdout_str();
        assert!(stdout.contains(&format!("\r\n{rows} {cols}\r\n42\r\n")), "{stdout:?}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn snapshots_with_live_mounts() {
    // Not on x86_64 yet (`snapshots_resume_where_the_program_waited` checks it says so).
    if x86_64_guest() {
        return;
    }
    // A live mount and a lazy import, used before the snapshot and after:
    // each run gives their host directories again (read-only if it likes).
    let dir = temp_dir("mountsnap");
    let (work, lazy) = (dir.join("work"), dir.join("lazy"));
    std::fs::create_dir_all(&work).unwrap();
    std::fs::create_dir_all(&lazy).unwrap();
    std::fs::write(work.join("a.txt"), "A\n").unwrap();
    std::fs::write(lazy.join("b.txt"), "B\n").unwrap();
    let b = Sandbox::builder()
        .cpus(1)
        .import(fixture("alpine/bin/busybox.static"), "/bin/busybox")
        .unwrap()
        .allow(Capability::Process)
        .allow(Capability::FsWrite)
        .mount(&work, "/work")
        .unwrap()
        .import_lazy(&lazy, "/lazy")
        .unwrap()
        .timeout(Duration::from_secs(30));
    if b.vmm_path().is_none() {
        return; // snapshots_resume_where_the_program_waited checks the error
    }
    let script = "/bin/busybox cat /work/a.txt; /bin/busybox ls /lazy; read line; \
                  /bin/busybox cat /work/a.txt /lazy/b.txt; echo \"$line\" > /work/out.txt; echo done";
    let snap = b.build().unwrap().snapshot(&["/bin/busybox", "sh", "-c", script], dir.join("s.snap")).unwrap();
    assert_eq!(snap.live_mounts_needed(), [("/work", true), ("/lazy", false)]);
    // Without its mounts, a run is refused.
    let err = snap.run("x\n").unwrap_err();
    assert!(err.to_string().contains("give it a host directory"), "{err}");
    std::fs::write(work.join("a.txt"), "A2\n").unwrap();
    let out = snap.clone().mount(&work, "/work").unwrap().mount(&lazy, "/lazy").unwrap().run("one\n").unwrap();
    assert_eq!(out.status, ExitStatus::Exited(0), "{}{}", out.stderr_str(), out.kernel_log);
    assert_eq!(out.stdout_str(), "A2\nB\ndone\n");
    assert_eq!(std::fs::read_to_string(work.join("out.txt")).unwrap(), "one\n");
    // Read-only this time: the write fails.
    let out =
        snap.clone().mount_read_only(&work, "/work").unwrap().mount(&lazy, "/lazy").unwrap().run("two\n").unwrap();
    assert_eq!(out.stdout_str(), "A2\nB\ndone\n");
    assert!(out.stderr_str().contains("Read-only"), "{}", out.stderr_str());
    assert_eq!(std::fs::read_to_string(work.join("out.txt")).unwrap(), "one\n");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn snapshots_resume_where_the_program_waited() {
    if x86_64_guest() {
        let sb = Sandbox::builder().import(fixture("alpine/bin/busybox.static"), "/bin/busybox").unwrap();
        let err =
            sb.build().unwrap().snapshot(&["/bin/busybox", "true"], temp_dir("nosnap-x86").join("s")).unwrap_err();
        assert!(err.to_string().contains("x86_64"), "{err}");
        return;
    }
    // One CPU, whatever GRIX_CPUS says (`snapshots_with_more_cpus` has more).
    let b = Sandbox::builder()
        .cpus(1)
        .import(fixture("alpine/bin/busybox.static"), "/bin/busybox")
        .unwrap()
        .allow(Capability::Process)
        .timeout(Duration::from_secs(30));
    if b.vmm_path().is_none() {
        // QEMU and KVM can't: say so clearly.
        let err =
            b.clone().build().unwrap().snapshot(&["/bin/busybox", "true"], temp_dir("nosnap").join("s")).unwrap_err();
        assert!(err.to_string().contains("grix's own VMM"), "{err}");
        return;
    }
    let dir = temp_dir("snapshot");
    let path = dir.join("sh.snap");
    // It waits on a pipe first: that isn't the moment. And `read -t 2`'s
    // deadline is monotonic time, which mustn't jump over the 2 s the
    // snapshot sits there.
    let script = "/bin/busybox echo before | /bin/busybox cat; read -t 2 line; echo \"got $line\"; \
                  /bin/busybox head -c 8 /dev/urandom | /bin/busybox od -An -tx1; /bin/busybox date +%s";
    let snap = b.clone().build().unwrap().snapshot(&["/bin/busybox", "sh", "-c", script], &path).unwrap();
    std::thread::sleep(Duration::from_secs(2));
    let mut randoms = Vec::new();
    let unix_now = || SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    for word in ["one", "two"] {
        let before = unix_now();
        let out = snap.run(format!("{word}\n")).unwrap();
        let after = unix_now();
        assert_eq!(out.status, ExitStatus::Exited(0), "{}{}", out.stderr_str(), out.kernel_log);
        let stdout = out.stdout_str();
        let lines: Vec<&str> = stdout.lines().collect();
        // What the program said before the snapshot isn't said again.
        assert_eq!(lines[0], format!("got {word}"), "{stdout}");
        randoms.push(lines[1].to_string());
        // The clock ran on while the snapshot sat there (2 s and more).
        let guest_time: u64 = lines[2].trim().parse().unwrap();
        assert!(
            (before - 1..=after + 1).contains(&guest_time),
            "guest time {guest_time}, host {before}..{after}\n{}",
            out.kernel_log
        );
        assert!(out.events.is_empty(), "{:?}", out.events);
    }
    assert_ne!(randoms[0], randoms[1], "every run from a snapshot draws its own randomness");
    // The file can be opened again later.
    let again = grix::Snapshot::open(&path).unwrap().run("three\n").unwrap();
    assert!(again.stdout_str().starts_with("got three\n"), "{}", again.stdout_str());
    // While a connection through the host is open it isn't the moment
    // (the host's end wouldn't come with it): the snapshot waits until the
    // program is done with it and waits for stdin alone.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        use std::io::Write;
        let (mut s, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_millis(300));
        s.write_all(b"fetched\n").unwrap();
    });
    let fetch = format!("/bin/busybox nc host.grix.internal {port} </dev/null; read line; echo \"got $line\"");
    let snap = b
        .clone()
        .allow(Capability::Net)
        .allow_host(&format!("host.grix.internal:{port}"))
        .unwrap()
        .build()
        .unwrap()
        .snapshot(&["/bin/busybox", "sh", "-c", &fetch], dir.join("conn"))
        .unwrap();
    server.join().unwrap();
    let out = snap.run("after\n").unwrap();
    assert_eq!(out.stdout_str(), "got after\n", "{}", out.stderr_str());
    // A program that never waits for input leaves no snapshot.
    let err = b.build().unwrap().snapshot(&["/bin/busybox", "true"], dir.join("none")).unwrap_err();
    assert!(err.to_string().contains("didn't wait for input"), "{err}");
    assert!(!dir.join("none").exists());
}

/// A machine with more CPUs is saved whole: every CPU stops, and runs
/// from the snapshot have them all, running threads in parallel again.
#[test]
fn snapshots_with_more_cpus() {
    // Not on x86_64 yet (`snapshots_resume_where_the_program_waited` checks it says so).
    if x86_64_guest() {
        return;
    }
    let b = with("smp")
        .import(fixture("alpine/bin/busybox.static"), "/bin/busybox")
        .unwrap()
        .allow(Capability::Threads)
        .allow(Capability::Process)
        .timeout(Duration::from_secs(60));
    if b.vmm_path().is_none() {
        return;
    }
    let dir = temp_dir("snapshot-cpus");
    // Threads on every CPU before the snapshot, and after it.
    let script = "/bin/smp >/dev/null; read line; echo \"got $line\"; /bin/smp; \
                  /bin/busybox head -c 8 /dev/urandom | /bin/busybox od -An -tx1";
    for cpus in [2, 4] {
        let path = dir.join(format!("smp{cpus}.snap"));
        let snap =
            b.clone().cpus(cpus).build().unwrap().snapshot(&["/bin/busybox", "sh", "-c", script], &path).unwrap();
        assert_eq!(snap.cpus(), cpus);
        let mut randoms = Vec::new();
        for word in ["one", "two"] {
            let out = snap.run(format!("{word}\n")).unwrap();
            assert_eq!(out.status, ExitStatus::Exited(0), "{}{}", out.stdout_str(), out.kernel_log);
            let stdout = out.stdout_str();
            let lines: Vec<&str> = stdout.lines().collect();
            assert_eq!(lines[0], format!("got {word}"), "{stdout}");
            assert!(lines[1].starts_with(&format!("smp ok cpus={cpus} ")), "{stdout}");
            let used: u32 = lines[1].rsplit("cpus_used=").next().unwrap().trim().parse().unwrap();
            assert!(used >= 2, "{stdout}");
            randoms.push(lines[2].to_string());
            assert!(out.events.is_empty(), "{:?}", out.events);
        }
        assert_ne!(randoms[0], randoms[1]);
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// What user code may set in its own registers stays out of the kernel
/// (x86_64: RFLAGS.NT across a system call, a thread pointer that isn't a
/// user address).
#[test]
fn user_registers_stay_out_of_the_kernel() {
    let out = run(with("regs").allow(Capability::Process), &["/bin/regs"]);
    assert_eq!(out.stdout_str(), "regs ok\n", "{}", out.kernel_log);
    assert_eq!(out.status, ExitStatus::Exited(0));
    assert!(out.events.is_empty(), "{:?}", out.events);
}

/// x86_64's AVX state (XSAVE): ymm registers survive context switches
/// and signal handlers, whose frame holds them in Linux's layout, and a
/// frame whose XSAVE header xrstor would refuse is a SIGSEGV, not a fault
/// in the kernel. (On arm64 the fixture only says ok.)
#[test]
fn vector_registers_are_the_programs_own() {
    let out = run(with("fpstate").allow(Capability::Threads), &["/bin/fpstate"]);
    assert_eq!(out.stdout_str(), "fpstate ok\n", "{}", out.kernel_log);
    assert_eq!(out.status, ExitStatus::Exited(0));
    assert!(out.events.is_empty(), "{:?}", out.events);
    if !x86_64_guest() {
        return;
    }
    for bad in ["badheader", "badfeatures"] {
        let out = run(with("fpstate").allow(Capability::Threads), &["/bin/fpstate", bad]);
        assert_eq!(out.status, ExitStatus::Signaled(11), "{bad}: {}", out.stdout_str());
        assert!(
            matches!(&out.events[..], [GuestEvent::Fault { signal: 11, detail, .. }] if detail.contains("rt_sigreturn")),
            "{bad}: {:?}",
            out.events
        );
    }
}

/// More CPUs: programs see them, threads run in parallel on them, and
/// execve and exit work while other threads spin on other CPUs.
#[test]
fn threads_run_in_parallel_on_more_cpus() {
    // One CPU on x86_64 (yet).
    if x86_64_guest() {
        return;
    }
    let b = || with("smp").allow(Capability::Threads).allow(Capability::Process);
    for cpus in [1, 4] {
        let out = run(b().cpus(cpus), &["/bin/smp"]);
        assert_eq!(out.status, ExitStatus::Exited(0), "{}", out.stdout_str());
        let line = out.stdout_str();
        let field = |name: &str| -> f64 {
            let at = line.find(&format!("{name}=")).unwrap_or_else(|| panic!("{line}")) + name.len() + 1;
            line[at..].split_whitespace().next().unwrap().parse().unwrap()
        };
        assert_eq!(field("cpus"), cpus as f64, "{line}");
        if cpus == 4 {
            // Four threads' work in well under four threads' time, on more
            // than one CPU (generous: emulation and busy hosts are slow).
            assert!(field("speedup") >= 1.5, "{line}");
            assert!(field("cpus_used") >= 2.0, "{line}");
        }
        assert!(out.events.is_empty(), "{:?}", out.events);
    }
    let out = run(b().cpus(4), &["/bin/smp", "exec"]);
    assert_eq!(out.stdout_str(), "exec ok\n");
    assert_eq!(out.status, ExitStatus::Exited(0));
    let out = run(b().cpus(4).timeout(Duration::from_secs(20)), &["/bin/smp", "exit"]);
    assert_eq!(out.status, ExitStatus::Exited(3));
    // Other processes get the CPUs a spinning thread holds.
    let out = run(b().cpus(4).timeout(Duration::from_secs(20)), &["/bin/smp", "fork"]);
    assert_eq!(out.stdout_str(), "fork ok\n", "{:?}", out.status);
    assert_eq!(out.status, ExitStatus::Exited(0));
    // The CPU count is checked.
    assert!(Sandbox::builder().cpus(0).build().is_err());
    assert!(Sandbox::builder().cpus(9).build().is_err());
}

/// x86_64 programs run through an x86_64 translator (here Alpine's static
/// qemu-x86_64, user mode), the way binfmt_misc runs them on Linux.
#[test]
fn x86_64_programs_run_through_a_translator() {
    // An x86_64 kernel runs them itself.
    if x86_64_guest() {
        return;
    }
    let qemu = fixture("qemu-x86_64/usr/bin/qemu-x86_64");
    let b = || with("hello-x86_64").env("GREETING", "from x86_64").allow(Capability::Threads);
    let out = run(b().x86_64(&qemu).unwrap(), &["/bin/hello-x86_64", "world"]);
    assert_eq!(out.status, ExitStatus::Exited(7), "{}{}", out.stderr_str(), out.kernel_log);
    assert_eq!(
        out.stdout_str(),
        "hello from grix! argc=2\nargv[0]=/bin/hello-x86_64\nargv[1]=world\nGREETING=from x86_64\n"
    );
    assert!(out.events.iter().all(|e| matches!(e, GuestEvent::MissingPath { .. })), "{:?}", out.events);
    // From a shell too (its execve).
    let sh = b()
        .x86_64(&qemu)
        .unwrap()
        .import(fixture("alpine/bin/busybox.static"), "/bin/busybox")
        .unwrap()
        .allow(Capability::Process);
    let out = run(sh, &["/bin/busybox", "sh", "-c", "/bin/hello-x86_64 a b; echo status $?"]);
    assert_eq!(
        out.stdout_str(),
        "hello from grix! argc=3\nargv[0]=/bin/hello-x86_64\nargv[1]=a\nargv[2]=b\nGREETING=from x86_64\nstatus 7\n"
    );
    // The translator runs in the sandbox: an x86_64 one can't.
    let err = b().x86_64(fixture("hello-x86_64")).err().expect("an x86_64 translator was taken");
    assert!(err.to_string().contains("isn't an arm64 Linux program"), "{err}");
    // Without one, it says what's missing.
    let out = b().build().unwrap().run(&["/bin/hello-x86_64"]).unwrap();
    assert_eq!(out.status, ExitStatus::Exited(126));
    assert!(out.events.iter().any(|e| e.to_string().contains("x86_64 translator")), "{:?}", out.events);
}
