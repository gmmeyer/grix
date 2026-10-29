//! An x86_64 vCPU's and the interrupt controllers' state on KVM, for
//! snapshots (`snapshot.rs`).
//!
//! A vCPU is what QEMU saves of one: its registers, special registers,
//! XSAVE area and XCRs, the MSRs the kernel sets, its local APIC, its
//! power (MP) state, pending events and debug registers, each as KVM's
//! ioctl has it, put back in QEMU's order. The interrupt controllers are
//! KVM's IOAPIC and 8259s. The guest's counter, the TSC, is set last, the
//! same on every vCPU (KVM keeps them in step).

use grix_abi::codec::{Reader, Writer};

use crate::kvm_x86::{self, Cpu, MP_STATES, MSR_TSC, Part, Vm};
use crate::snapshot::State;

/// The MSRs the kernel sets (`syscall`'s and GS's) and PAT; the rest of
/// what it changes is in the special registers (EFER, FS and GS bases,
/// the APIC base).
const MSRS: [u32; 6] = [
    0xc000_0081, // STAR
    0xc000_0082, // LSTAR
    0xc000_0083, // CSTAR
    0xc000_0084, // SFMASK
    0xc000_0102, // KERNEL_GS_BASE
    0x277,       // PAT
];

/// Restored in this order (as QEMU's kvm_arch_put_registers does): the
/// special registers before the local APIC (its base), events last.
const BEFORE_MSRS: [Part; 1] = [Part::Regs];
const AFTER_XSAVE: [Part; 2] = [Part::Xcrs, Part::Sregs];
const AFTER_MP: [Part; 3] = [Part::Lapic, Part::Events, Part::Debugregs];

/// kvm_vcpu_events.flags (at 20): what KVM_SET_VCPU_EVENTS takes from it.
/// GET sets the shadow and SMM ones; the NMI's and SIPI vector's are ours
/// to say.
const EVENTS_FLAGS: usize = 20;
const EVENTS_VALID_NMI_PENDING: u32 = 1;
const EVENTS_VALID_SIPI_VECTOR: u32 = 2;

fn err(e: kvm_x86::Error) -> String {
    e.to_string()
}

fn malformed<E>(_: E) -> String {
    "the snapshot's state is malformed".into()
}

/// One vCPU's state, on its own thread, stopped: what its last exit left
/// finished first. `xsave` is `Vm::xsave_size`.
pub fn cpu_state(cpu: &mut Cpu, xsave: usize) -> Result<Vec<u8>, String> {
    cpu.complete().map_err(err)?;
    let mut w = Writer::new();
    w.u32(cpu.mp_state().map_err(err)?);
    for part in BEFORE_MSRS.iter().chain(&AFTER_XSAVE).chain(&AFTER_MP) {
        w.bytes(&cpu.get(*part).map_err(err)?);
    }
    w.bytes(&cpu.xsave(xsave).map_err(err)?);
    for (_, value) in cpu.msrs(&MSRS).map_err(err)? {
        w.u64(value);
    }
    Ok(w.buf)
}

/// What `cpu_state` saved, read back and checked for sizes (KVM checks
/// the values).
struct Saved<'a> {
    mp: u32,
    parts: Vec<(Part, &'a [u8])>,
    xsave: &'a [u8],
    msrs: Vec<(u32, u64)>,
}

fn read(raw: &[u8]) -> Result<Saved<'_>, String> {
    let mut r = Reader::new(raw);
    let mp = r.u32().map_err(malformed)?;
    if !MP_STATES.contains(&mp) {
        return Err(malformed(()));
    }
    let mut parts = Vec::new();
    for part in BEFORE_MSRS.iter().chain(&AFTER_XSAVE).chain(&AFTER_MP) {
        let bytes = r.bytes().map_err(malformed)?;
        if bytes.len() != part.size() {
            return Err(malformed(()));
        }
        parts.push((*part, bytes));
    }
    let xsave = r.bytes().map_err(malformed)?;
    let mut msrs = Vec::new();
    for index in MSRS {
        msrs.push((index, r.u64().map_err(malformed)?));
    }
    r.done().map_err(malformed)?;
    Ok(Saved { mp, parts, xsave, msrs })
}

/// Put vCPU `n` back, before any vCPU runs. The one that asked returns from
/// its call: past its `out`, with the answer in rax, rdi, rsi, rdx, rcx and
/// r8 (`VMM_PORT`).
pub fn restore_cpu(state: &State, n: usize, cpu: &mut Cpu, xsave: usize) -> Result<(), String> {
    let saved = read(state.cpu(n)?)?;
    let part = |p: Part| saved.parts.iter().find(|(q, _)| *q == p).map(|(_, b)| *b).expect("read has every part");
    let mut regs = part(Part::Regs).to_vec();
    if let Some(x) = state.returns(n) {
        // kvm_regs: rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp, r8..r15, rip, rflags.
        for (value, slot) in x.into_iter().zip([0, 5, 4, 3, 2, 8]) {
            regs[slot * 8..slot * 8 + 8].copy_from_slice(&value.to_le_bytes());
        }
    }
    fn at(what: &'static str) -> impl Fn(kvm_x86::Error) -> String {
        move |e| format!("restoring the {what}: {e}")
    }
    cpu.set(Part::Regs, &regs).map_err(at("registers"))?;
    cpu.set_xsave(saved.xsave, xsave).map_err(at("XSAVE area"))?;
    for p in AFTER_XSAVE {
        cpu.set(p, part(p)).map_err(at("special registers"))?;
    }
    cpu.set_msrs(&saved.msrs).map_err(at("MSRs"))?;
    cpu.set_mp_state(saved.mp).map_err(at("power state"))?;
    for p in AFTER_MP {
        let mut bytes = part(p).to_vec();
        if p == Part::Events {
            let flags = u32::from_le_bytes(bytes[EVENTS_FLAGS..EVENTS_FLAGS + 4].try_into().unwrap())
                | EVENTS_VALID_NMI_PENDING
                | EVENTS_VALID_SIPI_VECTOR;
            bytes[EVENTS_FLAGS..EVENTS_FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
        }
        cpu.set(p, &bytes).map_err(at("local APIC and events"))?;
    }
    Ok(())
}

/// The guest's counter now, read by a stopped vCPU.
pub fn counter(cpu: &Cpu) -> Result<u64, String> {
    Ok(cpu.msrs(&[MSR_TSC]).map_err(err)?[0].1)
}

/// Make the guest's counter go on from where it was, as after a suspend
/// (the kernel moves its time of day on by the time since): last, the
/// same value on every vCPU, which KVM takes as one TSC for the VM.
pub fn set_counter(state: &State, cpus: &[Cpu]) -> Result<(), String> {
    for cpu in cpus {
        cpu.set_msrs(&[(MSR_TSC, state.counter())]).map_err(err)?;
    }
    Ok(())
}

/// The interrupt controllers' state (every vCPU stopped): KVM's 8259s and
/// IOAPIC.
pub fn irqchip_state(vm: &Vm) -> Result<Vec<u8>, String> {
    let mut w = Writer::new();
    for chip in 0..3 {
        w.bytes(&vm.irqchip(chip).map_err(|e| format!("reading interrupt controller {chip}: {e}"))?);
    }
    Ok(w.buf)
}

/// Put them back, after the vCPUs and before any runs.
pub fn restore_irqchip(vm: &Vm, state: &State) -> Result<(), String> {
    let mut r = Reader::new(state.gic());
    for chip in 0..3u32 {
        let saved = r.bytes().map_err(malformed)?;
        // Each says which it is: only the one it should be.
        if saved.get(..4) != Some(&chip.to_le_bytes()[..]) {
            return Err(malformed(()));
        }
        vm.set_irqchip(saved).map_err(|e| format!("restoring interrupt controller {chip}: {e}"))?;
    }
    r.done().map_err(malformed)
}
