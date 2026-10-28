//! A vCPU's and the GIC's state on KVM, for snapshots (`snapshot.rs`).
//!
//! A vCPU is every register KVM lists for it (`KVM_GET_REG_LIST`) and its
//! PSCI power state; the GIC is the in-kernel vGIC's registers through its
//! device attributes, read and put back in one fixed order (`gic_attrs`),
//! so a file only supplies values. The guest's counter is set once, for
//! the whole VM, after everything else.

use std::collections::HashSet;
use std::os::fd::RawFd;

use grix_abi::codec::{Reader, Writer};

use crate::kvm::{self, Cpu};
use crate::snapshot::State;

const GRP_DIST_REGS: u32 = 1;
const GRP_REDIST_REGS: u32 = 5;
const GRP_CPU_SYSREGS: u32 = 6;
const GRP_LEVEL_INFO: u32 = 7;

/// Interrupt ids the vGIC has (`kvm::Vm::create` sets 128).
const IRQS: u64 = 128;

/// A GIC CPU interface register's attribute: its AArch64 encoding.
const fn icc(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> u64 {
    (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2
}

/// The CPU interface, in the order it's put back (SRE and CTLR decide how
/// the rest read).
const ICC_REGS: [u64; 9] = [
    icc(3, 0, 12, 12, 5), // SRE
    icc(3, 0, 12, 12, 4), // CTLR
    icc(3, 0, 12, 12, 6), // IGRPEN0
    icc(3, 0, 12, 12, 7), // IGRPEN1
    icc(3, 0, 4, 6, 0),   // PMR
    icc(3, 0, 12, 8, 3),  // BPR0
    icc(3, 0, 12, 12, 3), // BPR1
    icc(3, 0, 12, 8, 4),  // AP0R0
    icc(3, 0, 12, 9, 0),  // AP1R0
];

/// The vGIC's state as (group, attribute) pairs, in the order they're put
/// back: configuration before enables, line levels before pending state.
/// vCPU n's affinity (bits 63:32) is n: KVM's MPIDR for it.
fn gic_attrs(cpus: usize) -> Vec<(u32, u64)> {
    let mut a = vec![(GRP_DIST_REGS, 0x0)]; // GICD_CTLR
    for n in 0..cpus {
        let cpu = (n as u64) << 32;
        // The redistributor's SGI frame: SGIs and PPIs.
        let mut regs = vec![0x1_0080, 0x1_0c00, 0x1_0c04]; // IGROUPR0, ICFGR0/1
        regs.extend((0..8).map(|k| 0x1_0400 + 4 * k)); // IPRIORITYR
        regs.extend([0x1_0100, 0x1_0200, 0x1_0300]); // ISENABLER0, ISPENDR0, ISACTIVER0
        a.extend(regs.into_iter().map(|r| (GRP_REDIST_REGS, cpu | r)));
    }
    // SPIs, 32 and up.
    let words = 1..IRQS / 32;
    let dist = |regs: &mut Vec<(u32, u64)>, offsets: &mut dyn Iterator<Item = u64>| {
        regs.extend(offsets.map(|o| (GRP_DIST_REGS, o)));
    };
    dist(&mut a, &mut words.clone().map(|k| 0x80 + 4 * k)); // IGROUPR
    dist(&mut a, &mut (2..IRQS / 16).map(|k| 0xc00 + 4 * k)); // ICFGR
    dist(&mut a, &mut (8..IRQS / 4).map(|k| 0x400 + 4 * k)); // IPRIORITYR
    // IROUTER, 64-bit: two halves.
    dist(&mut a, &mut (32..IRQS).flat_map(|i| [0x6000 + 8 * i, 0x6004 + 8 * i]));
    dist(&mut a, &mut words.clone().map(|k| 0x100 + 4 * k)); // ISENABLER
    a.extend(words.clone().map(|k| (GRP_LEVEL_INFO, 32 * k))); // line levels
    dist(&mut a, &mut words.clone().map(|k| 0x200 + 4 * k)); // ISPENDR
    dist(&mut a, &mut words.map(|k| 0x300 + 4 * k)); // ISACTIVER
    for n in 0..cpus {
        a.extend(ICC_REGS.iter().map(|&r| (GRP_CPU_SYSREGS, (n as u64) << 32 | r)));
    }
    a
}

fn err(e: kvm::Error) -> String {
    e.to_string()
}

fn malformed<E>(_: E) -> String {
    "the snapshot's state is malformed".into()
}

/// One vCPU's state, on its own thread, stopped: what its last exit left
/// finished first.
pub fn cpu_state(cpu: &mut Cpu) -> Result<Vec<u8>, String> {
    cpu.complete().map_err(err)?;
    let mut w = Writer::new();
    w.u32(cpu.mp_state().map_err(err)?);
    let list = cpu.reg_list().map_err(err)?;
    w.u32(list.len() as u32);
    // The biggest register without SVE (which grix doesn't turn on).
    let mut value = [0u8; 16];
    for id in list {
        let size = kvm::reg_size(id);
        if size > value.len() {
            return Err(format!("register {id:#x} has {size} bytes"));
        }
        cpu.get_raw(id, &mut value[..size]).map_err(err)?;
        w.u64(id);
        w.raw(&value[..size]);
    }
    Ok(w.buf)
}

/// Put vCPU `n` back, before any vCPU runs. The one that asked returns from
/// its call.
pub fn restore_cpu(state: &State, n: usize, cpu: &mut Cpu) -> Result<(), String> {
    let known: HashSet<u64> = cpu.reg_list().map_err(err)?.into_iter().collect();
    let mut r = Reader::new(state.cpu(n)?);
    let mp = r.u32().map_err(malformed)?;
    if mp != kvm::MP_STATE_RUNNABLE && mp != kvm::MP_STATE_STOPPED {
        return Err(malformed(()));
    }
    let count = r.u32().map_err(malformed)? as usize;
    if count > known.len() {
        return Err(malformed(()));
    }
    for _ in 0..count {
        let id = r.u64().map_err(malformed)?;
        if !known.contains(&id) {
            return Err(format!("the snapshot has a register ({id:#x}) this KVM doesn't: take it again here"));
        }
        let value = r.take(kvm::reg_size(id)).map_err(malformed)?;
        // The counter is the VM's, set once (`set_counter`). The physical
        // one isn't the guest's to move (writing it would also make KVM trap
        // physical timer accesses on hosts without ECV).
        if id != kvm::REG_TIMER_CNT && id != kvm::REG_PTIMER_CNT {
            cpu.set_raw(id, value).map_err(|e| format!("restoring register {id:#x}: {e}"))?;
        }
    }
    r.done().map_err(malformed)?;
    cpu.set_mp_state(mp).map_err(err)?;
    if let Some(x) = state.returns(n) {
        for (i, v) in x.into_iter().enumerate() {
            cpu.set_reg(kvm::reg_x(i as u64), v).map_err(err)?;
        }
    }
    Ok(())
}

/// The guest's counter now, read by a stopped vCPU.
pub fn counter(cpu: &Cpu) -> Result<u64, String> {
    let mut value = [0u8; 8];
    cpu.get_raw(kvm::REG_TIMER_CNT, &mut value).map_err(err)?;
    Ok(u64::from_le_bytes(value))
}

/// Make the guest's counter go on from where it was, as after a suspend
/// (the kernel moves its time of day on by the time since): last, as it
/// sets the offset of every vCPU.
pub fn set_counter(state: &State, cpu: &mut Cpu) -> Result<(), String> {
    cpu.set_reg(kvm::REG_TIMER_CNT, state.counter()).map_err(err)
}

/// The GIC's state (every vCPU stopped).
pub fn gic_state(gic: RawFd, cpus: usize) -> Result<Vec<u8>, String> {
    let attrs = gic_attrs(cpus);
    let mut w = Writer::new();
    w.u32(attrs.len() as u32);
    for (group, attr) in attrs {
        w.u64(kvm::device_attr(gic, group, attr).map_err(|e| format!("reading the GIC ({group}, {attr:#x}): {e}"))?);
    }
    Ok(w.buf)
}

/// Put the GIC back, after the vCPUs (their affinities) and before any
/// runs.
pub fn restore_gic(gic: RawFd, state: &State) -> Result<(), String> {
    let attrs = gic_attrs(state.cpus());
    let mut r = Reader::new(state.gic());
    if r.u32().map_err(malformed)? as usize != attrs.len() {
        return Err(malformed(()));
    }
    for (group, attr) in attrs {
        let value = r.u64().map_err(malformed)?;
        kvm::set_device_attr(gic, group, attr, value)
            .map_err(|e| format!("restoring the GIC ({group}, {attr:#x}): {e}"))?;
    }
    r.done().map_err(malformed)
}
