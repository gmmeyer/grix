//! Stopping every vCPU for a snapshot, and (on Hypervisor.framework, where
//! PSCI is ours) turning secondaries on.
//!
//! The vCPU that asks for a snapshot records its own registers and wants a
//! pause; every other vCPU that's on stops between exits (`point`), saves
//! its own registers (a vCPU's state is its thread's to touch) and waits.
//! Once they all have, the caller saves the machine, or calls the pause
//! off and they all go on. Power and the pause share one lock, so a vCPU
//! turned on meanwhile is waited for too, and only one that's on can turn
//! another on.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard};

/// A vCPU's power: a secondary is off until PSCI CPU_ON gives it an entry
/// point and its x0, or a restored run its saved registers. (On KVM, which
/// does PSCI itself, every vCPU's thread runs: they're all `On` here.)
#[derive(Clone, Copy, PartialEq)]
pub enum Power {
    Off,
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    Start(u64, u64),
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    Restore,
    On,
}

struct State {
    power: Vec<Power>,
    pause: Option<Pause>,
    pauses: u64,
}

/// A snapshot being taken: each vCPU's registers once it has stopped.
struct Pause {
    id: u64,
    saved: Vec<Option<Vec<u8>>>,
}

pub struct Pauses {
    state: Mutex<State>,
    changed: Condvar,
    /// A pause is wanted or on: each vCPU looks between exits.
    pausing: AtomicBool,
}

impl Pauses {
    pub fn new(power: Vec<Power>) -> Pauses {
        Pauses {
            state: Mutex::new(State { power, pause: None, pauses: 0 }),
            changed: Condvar::new(),
            pausing: AtomicBool::new(false),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn wait<'a>(&self, g: MutexGuard<'a, State>) -> MutexGuard<'a, State> {
        self.changed.wait(g).unwrap_or_else(|e| e.into_inner())
    }

    /// Secondary `n`, off: wait until it's turned on (`Start`) or is to be
    /// restored (`Restore`). It's `On` from then.
    #[cfg(target_os = "macos")]
    pub fn wait_on(&self, n: usize) -> Power {
        let mut s = self.lock();
        while let Power::Off | Power::On = s.power[n] {
            s = self.wait(s);
        }
        std::mem::replace(&mut s.power[n], Power::On)
    }

    /// PSCI CPU_ON: start vCPU `target` at `entry` with x0 = `context`.
    /// None if there's no such vCPU; false if it isn't off.
    #[cfg(target_os = "macos")]
    pub fn turn_on(&self, target: usize, entry: u64, context: u64) -> Option<bool> {
        let mut s = self.lock();
        let p = s.power.get_mut(target)?;
        if *p != Power::Off {
            return Some(false);
        }
        *p = Power::Start(entry, context);
        self.changed.notify_all();
        Some(true)
    }

    /// Between exits of vCPU `n`: if a snapshot is being taken, stop here
    /// with its registers saved (`save`) until it's taken (the process
    /// ends) or called off.
    pub fn point(&self, n: usize, mut save: impl FnMut() -> Result<Vec<u8>, String>) -> Result<(), String> {
        if !self.pausing.load(Ordering::SeqCst) {
            return Ok(());
        }
        let mut s = self.lock();
        while let Some(p) = &mut s.pause {
            if p.saved[n].is_none() {
                p.saved[n] = Some(save()?);
                self.changed.notify_all();
            }
            let id = p.id;
            while s.pause.as_ref().is_some_and(|p| p.id == id) {
                s = self.wait(s);
            }
        }
        Ok(())
    }

    /// vCPU `n` asks for a snapshot, its own registers `own`: stop every
    /// other vCPU that's on (`kick` makes vCPU m look), then `save` the
    /// machine with all their registers (none for one that's off). True
    /// once it's saved (this run ends there); false if `save` said not now
    /// (None) or another vCPU is taking one, and every vCPU goes on.
    pub fn take(
        &self,
        n: usize,
        own: Vec<u8>,
        kick: impl Fn(usize),
        save: impl FnOnce(&[Option<Vec<u8>>]) -> Option<Result<(), String>>,
    ) -> Result<bool, String> {
        let mut s = self.lock();
        // The kernel's lock makes two at once its bug: the other is told
        // not now, and stops for this one.
        if s.pause.is_some() {
            return Ok(false);
        }
        s.pauses += 1;
        let mut saved = vec![None; s.power.len()];
        saved[n] = Some(own);
        s.pause = Some(Pause { id: s.pauses, saved });
        self.pausing.store(true, Ordering::SeqCst);
        let count = s.power.len();
        drop(s);
        for m in (0..count).filter(|&m| m != n) {
            kick(m);
        }
        let stopped = |s: &State| {
            s.pause
                .as_ref()
                .is_some_and(|p| s.power.iter().zip(&p.saved).all(|(on, r)| *on == Power::Off || r.is_some()))
        };
        let mut s = self.lock();
        while !stopped(&s) {
            s = self.wait(s);
        }
        match save(&s.pause.as_ref().expect("a pause").saved) {
            Some(result) => result.map(|()| true),
            None => {
                s.pause = None;
                self.pausing.store(false, Ordering::SeqCst);
                self.changed.notify_all();
                Ok(false)
            }
        }
    }
}
