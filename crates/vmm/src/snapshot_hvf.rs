//! A vCPU's and the GIC's state on Hypervisor.framework, for snapshots
//! (`snapshot.rs`).

use grix_abi::codec::{Reader, Writer};

use crate::hvf::{self, Cpu};
use crate::snapshot::State;

/// The system registers a restored vCPU needs, by Hypervisor.framework id.
const SYS_REGS: &[u16] = &[
    0xc005, // MPIDR_EL1
    0xc080, // SCTLR_EL1
    0xc082, // CPACR_EL1
    0xc100, // TTBR0_EL1
    0xc101, // TTBR1_EL1
    0xc102, // TCR_EL1
    0xc108, 0xc109, 0xc10a, 0xc10b, // APIAKEY, APIBKEY
    0xc110, 0xc111, 0xc112, 0xc113, // APDAKEY, APDBKEY
    0xc118, 0xc119, // APGAKEY
    0xc200, // SPSR_EL1
    0xc201, // ELR_EL1
    0xc208, // SP_EL0
    0xc288, 0xc289, // AFSR0/1_EL1
    0xc290, // ESR_EL1
    0xc300, // FAR_EL1
    0xc3a0, // PAR_EL1
    0xc510, // MAIR_EL1
    0xc518, // AMAIR_EL1
    0xc600, // VBAR_EL1
    0xc681, // CONTEXTIDR_EL1
    0xc684, // TPIDR_EL1
    0xc708, // CNTKCTL_EL1
    0xd000, // CSSELR_EL1
    0xde82, // TPIDR_EL0
    0xde83, // TPIDRRO_EL0
    0xdf19, // CNTV_CTL_EL0
    0xdf1a, // CNTV_CVAL_EL0
    0xe208, // SP_EL1
    0x8012, // MDSCR_EL1
];

/// The GIC CPU interface (not in the framework's GIC state).
const ICC_REGS: &[u16] = &[
    0xc230, // PMR
    0xc643, // BPR0
    0xc644, // AP0R0
    0xc648, // AP1R0
    0xc663, // BPR1
    0xc664, // CTLR
    0xc665, // SRE
    0xc666, // IGRPEN0
    0xc667, // IGRPEN1
];

/// X0..X30, PC, FPCR, FPSR, CPSR.
const GP_REGS: u32 = 35;

/// One vCPU's registers, read on its own thread: general purpose,
/// system, FP/SIMD, and its GIC CPU interface.
pub fn cpu_state(cpu: &Cpu) -> Result<Vec<u8>, String> {
    let mut w = Writer::new();
    for r in 0..GP_REGS {
        w.u64(cpu.reg(r));
    }
    for &r in SYS_REGS {
        w.u64(cpu.sys_reg(r));
    }
    for q in 0..32 {
        w.raw(&cpu.simd_reg(q).map_err(|e| e.to_string())?);
    }
    for &r in ICC_REGS {
        w.u64(cpu.icc_reg(r).map_err(|e| e.to_string())?);
    }
    Ok(w.buf)
}

/// The GIC's state (every vCPU stopped).
pub fn gic_state() -> Result<Vec<u8>, String> {
    hvf::gic_state().map_err(|e| e.to_string())
}

/// The vCPU timer offset that makes the guest's counter go on from where
/// it was.
pub fn vtimer_offset(state: &State) -> u64 {
    hvf::now().wrapping_sub(state.counter())
}

/// Put the GIC back, once every vCPU exists and before any runs.
pub fn restore_gic(state: &State) -> Result<(), String> {
    hvf::set_gic_state(state.gic()).map_err(|e| e.to_string())
}

/// Put vCPU `n` back (on its own thread, after the GIC). The one that
/// asked returns from its call.
pub fn restore_cpu(state: &State, n: usize, cpu: &mut Cpu) -> Result<(), String> {
    let bad = |_| "the snapshot's state is malformed".to_string();
    let mut r = Reader::new(state.cpu(n)?);
    for reg in 0..GP_REGS {
        cpu.set_reg(reg, r.u64().map_err(bad)?);
    }
    for &reg in SYS_REGS {
        cpu.set_sys_reg(reg, r.u64().map_err(bad)?).map_err(|e| e.to_string())?;
    }
    for q in 0..32 {
        let v: [u8; 16] = r.take(16).map_err(bad)?.try_into().unwrap();
        cpu.set_simd_reg(q, v).map_err(|e| e.to_string())?;
    }
    for &reg in ICC_REGS {
        cpu.set_icc_reg(reg, r.u64().map_err(bad)?).map_err(|e| e.to_string())?;
    }
    if let Some(x) = state.returns(n) {
        for (i, v) in x.into_iter().enumerate() {
            cpu.set_reg(i as u32, v);
        }
    }
    Ok(())
}
