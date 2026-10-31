//! How many descriptors a program's watches cost the process it runs in.
//! A test binary of its own: it lowers this process's RLIMIT_NOFILE, as a
//! macOS shell has it, which other tests running beside it would feel.

use std::path::PathBuf;
use std::time::Duration;

use grix::{Capability, ExitStatus, Sandbox};

fn fixture(name: &str) -> PathBuf {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/build");
    let dir = if grix::Arch::from_env() == grix::Arch::X86_64 { base.join("amd64") } else { base };
    dir.join(name)
}

fn open_fds() -> usize {
    let dir = if cfg!(target_os = "macos") { "/dev/fd" } else { "/proc/self/fd" };
    std::fs::read_dir(dir).unwrap().count()
}

#[test]
fn watches_leave_the_host_its_descriptors() {
    // Watches on 300 directories and a directory of 1500 files: with kqueue
    // that was a descriptor each, up to 9216, past the 256 the process may
    // have, and then live mounts and the proxy fail.
    let host = std::env::temp_dir().join(format!("grix-hostfds-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&host);
    std::fs::create_dir_all(host.join("big")).unwrap();
    for i in 0..1500 {
        std::fs::write(host.join(format!("big/f{i}")), "x").unwrap();
    }
    for i in 0..300 {
        std::fs::create_dir(host.join(format!("d{i}"))).unwrap();
    }
    let echo = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = echo.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for c in echo.incoming().flatten() {
            let mut r = c.try_clone().unwrap();
            let mut w = c;
            let _ = std::io::copy(&mut r, &mut w);
        }
    });
    let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: both take a pointer to the struct.
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
        limit.rlim_cur = 256;
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limit), 0);
    }
    let sb = Sandbox::builder()
        .timeout(Duration::from_secs(60))
        .import(fixture("hardening2"), "/bin/hardening2")
        .unwrap()
        .allow(Capability::Net)
        .allow_host(&format!("host.grix.internal:{port}"))
        .unwrap()
        .mount(&host, "/work")
        .unwrap()
        .build()
        .unwrap();
    let out = sb.run(&["/bin/hardening2", "watchmany", "/work", &port.to_string()]).unwrap();
    assert_eq!(out.status, ExitStatus::Exited(0), "{}{}", out.stdout_str(), out.kernel_log);
    let said = out.stdout_str();
    assert!(said.ends_with("watchmany ok\n"), "{said}");
    // Linux's inotify holds no descriptor per watch; kqueue's budget ran out.
    let told = if cfg!(target_os = "macos") { "overflow" } else { "all" };
    assert!(said.starts_with(&format!("watched 301, {told}\n")), "{said}");
    assert!(out.events.is_empty(), "{:?}", out.events);
    // Files held open are held open on the host too, while its share lasts:
    // 900 of them are more than it may have at all.
    let out = sb.run(&["/bin/hardening2", "holdmany", "/work", &port.to_string()]).unwrap();
    assert_eq!(out.stdout_str(), "holdmany ok\n", "{}", out.kernel_log);
    assert_eq!(out.status, ExitStatus::Exited(0));
    assert!(out.events.is_empty(), "{:?}", out.events);
    // And the watcher's descriptors went with the sandbox.
    drop(sb);
    std::thread::sleep(Duration::from_millis(500));
    assert!(open_fds() < 64, "{} descriptors left open", open_fds());
    std::fs::remove_dir_all(&host).unwrap();
}
