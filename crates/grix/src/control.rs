//! Signals for a running program, from the agent (or the CLI's Ctrl-C).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use grix_abi::wire::{self, Input};

use crate::net::Outbox;

/// Sends signals to a sandbox's program while it runs, or stops it. Attach
/// it with [`SandboxBuilder::control`](crate::SandboxBuilder::control);
/// clones control the same runs, so one can go to another thread.
///
/// ```no_run
/// # use grix::{RunControl, Sandbox};
/// let control = RunControl::new();
/// let sandbox = Sandbox::builder().import("./server", "/bin/server")?.control(&control).build()?;
/// let c = control.clone();
/// std::thread::spawn(move || {
///     std::thread::sleep(std::time::Duration::from_secs(10));
///     c.signal(15); // SIGTERM: the program shuts down, and its exports come back
/// });
/// let out = sandbox.run(&["/bin/server"])?;
/// # Ok::<(), anyhow::Error>(())
/// ```
#[derive(Clone, Default)]
pub struct RunControl(Arc<Mutex<Vec<Weak<Live>>>>);

/// A run in progress, as its control sees it.
pub(crate) struct Live {
    outbox: Arc<Outbox>,
    stop: AtomicBool,
}

impl Live {
    pub fn stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }
}

impl RunControl {
    pub fn new() -> RunControl {
        RunControl::default()
    }

    fn live(&self) -> Vec<Arc<Live>> {
        let mut runs = self.0.lock().unwrap();
        runs.retain(|w| w.strong_count() > 0);
        runs.iter().filter_map(Weak::upgrade).collect()
    }

    /// Send signal `sig` (a Linux signal number, 1 to 64: 2 is SIGINT, 15
    /// SIGTERM, 9 SIGKILL) to the program and every process in its process
    /// group, as a terminal sends Ctrl-C to its foreground group. False if
    /// no run is in progress, or `sig` isn't a signal.
    pub fn signal(&self, sig: i32) -> bool {
        let Ok(sig) = u8::try_from(sig) else { return false };
        if !(1..=64).contains(&sig) {
            return false;
        }
        let runs = self.live();
        for run in &runs {
            let mut f = wire::input_header(Input::Signal, 1).to_vec();
            f.push(sig);
            run.outbox.signal(f);
        }
        !runs.is_empty()
    }

    /// End the runs in progress now, whatever the program is doing: their
    /// status is [`ExitStatus::Stopped`](crate::ExitStatus::Stopped), and
    /// exports don't come back. False if no run is in progress.
    pub fn stop(&self) -> bool {
        let runs = self.live();
        for run in &runs {
            run.stop.store(true, Ordering::Relaxed);
        }
        !runs.is_empty()
    }

    /// A run starts: signals go through `outbox`.
    pub(crate) fn attach(&self, outbox: Arc<Outbox>) -> Arc<Live> {
        let live = Arc::new(Live { outbox, stop: AtomicBool::new(false) });
        let mut runs = self.0.lock().unwrap();
        runs.retain(|w| w.strong_count() > 0);
        runs.push(Arc::downgrade(&live));
        live
    }
}
