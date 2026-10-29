//! Making a vCPU's thread leave KVM_RUN (a snapshot's pause), on either
//! architecture's KVM.

use std::sync::atomic::{AtomicI32, AtomicU8, Ordering};

/// The signal that kicks a vCPU's thread out of KVM_RUN.
const KICK_SIGNAL: i32 = libc::SIGUSR1;

/// Make a vCPU's thread leave KVM_RUN: `immediate_exit` for a run about to
/// start, a signal for one under way (KVM_RUN returns EINTR either way).
pub struct Kick {
    immediate_exit: *const AtomicU8,
    tid: AtomicI32,
}

// SAFETY: `immediate_exit` points into a kvm_run page that's never
// unmapped, and is only used atomically.
unsafe impl Send for Kick {}
unsafe impl Sync for Kick {}

impl Kick {
    /// For the vCPU whose kvm_run's `immediate_exit` byte this is.
    ///
    /// # Safety
    /// It must stay mapped for as long as the process lives.
    pub unsafe fn new(immediate_exit: &AtomicU8) -> Kick {
        Kick { immediate_exit: immediate_exit as *const AtomicU8, tid: AtomicI32::new(0) }
    }

    /// On the vCPU's thread, before it first runs.
    pub fn bind(&self) {
        // SAFETY: gettid has no arguments.
        self.tid.store(unsafe { libc::syscall(libc::SYS_gettid) } as i32, Ordering::SeqCst);
    }

    /// On the vCPU's thread, before each run, then look for what a kick
    /// wants: a kick after this stops the run.
    pub fn clear(&self) {
        // SAFETY: see the type.
        unsafe { &*self.immediate_exit }.store(0, Ordering::SeqCst);
    }

    /// From any thread of this process.
    pub fn kick(&self) {
        // SAFETY: see the type.
        unsafe { &*self.immediate_exit }.store(1, Ordering::SeqCst);
        let tid = self.tid.load(Ordering::SeqCst);
        if tid != 0 {
            // SAFETY: a signal to one of our own threads, whose handler
            // does nothing.
            unsafe { libc::syscall(libc::SYS_tgkill, libc::getpid(), tid, KICK_SIGNAL) };
        }
    }
}

/// The kick signal's handler: nothing (without SA_RESTART, so it
/// interrupts KVM_RUN).
pub fn handle_kicks() -> Result<(), String> {
    extern "C" fn nothing(_: libc::c_int) {}
    // SAFETY: a handler that does nothing, installed before any vCPU runs.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = nothing as extern "C" fn(libc::c_int) as usize;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(KICK_SIGNAL, &action, std::ptr::null_mut()) != 0 {
            return Err(format!("sigaction: {}", std::io::Error::last_os_error()));
        }
    }
    Ok(())
}
