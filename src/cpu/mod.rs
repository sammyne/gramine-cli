use std::{arch::asm, fmt::Display};

use crate::sgx;

#[derive(Default)]
pub struct Checker {
    pub cpuid_supported: bool,
    pub from_intel: bool,
    pub sgx_supported: bool,
    pub sgx1_supported: bool,
    pub sgx2_supported: bool,
    pub flc_supported: bool,
    pub sgx_virt_supported: bool,
    pub sgx_memsgx_mem_concurrency_supported: bool,
    pub cet_supported: bool,
    pub kss_supported: bool,
    pub maximum_enclave_size_x86: u64,
    pub maximum_enclave_size_x64: u64,
    pub epc_region_size: u64,
}

pub struct CpuId {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

impl Checker {
    pub fn new() -> Self {
        let mut out = Self::default();

        out.cpuid_supported = is_cpuid_supported();
        if !out.cpuid_supported {
            return out;
        }

        let id_0_0 = cpuid(0, 0);
        let cpuid_max_leaf_value = id_0_0.eax;
        out.from_intel = is_from_intel(&id_0_0);
        if !out.from_intel || (cpuid_max_leaf_value < 7) {
            println!("non-intel cpuid(leaf=0,subleaf=0)");
            println!("{id_0_0}");
            return out;
        }

        let id_7_0 = cpuid(7, 0);
        out.sgx_supported = (id_7_0.ebx & (1 << 2)) != 0;
        if !out.sgx_supported || (cpuid_max_leaf_value < 0x12) {
            return out;
        }

        out.flc_supported = (id_7_0.ecx & (1 << 30)) != 0;

        let id_18_0 = cpuid(0x12, 0);
        let id_18_1 = cpuid(0x12, 1);

        out.sgx1_supported = (id_18_0.eax & (1 << 0)) != 0;
        out.sgx2_supported = (id_18_0.eax & (1 << 1)) != 0;
        out.sgx_virt_supported = (id_18_0.eax & (1 << 5)) != 0;
        out.sgx_memsgx_mem_concurrency_supported = (id_18_0.eax & (1 << 6)) != 0;

        out.cet_supported = (id_18_1.eax & (1 << 6)) != 0;
        out.kss_supported = (id_18_1.eax & (1 << 7)) != 0;

        out.maximum_enclave_size_x86 = 2u64.saturating_pow(id_18_0.edx & 0xff);
        out.maximum_enclave_size_x64 = 2u64.saturating_pow((id_18_0.edx >> 8) & 0xff);

        // Check if there's any EPC region allocated by BIOS
        for subleaf in 2u32.. {
            let id = cpuid(0x12, subleaf);
            let t = id.eax & 0x0f;
            if t == 0 {
                break;
            } else if t != 1 {
                continue;
            }

            if ((id.ecx & 0xFFFFF000) != 0) || ((id.edx & 0xFFFFF) != 0) {
                out.epc_region_size += (id.ecx & 0xFFFFF000) as u64;
                out.epc_region_size += ((id.edx & 0xFFFFF) as u64) << 32;
            }
        }

        out
    }
}

impl Display for Checker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.cpuid_supported {
            writeln!(f, "`cpuid` instruction unavailable").unwrap();
            return Ok(());
        }

        if !self.from_intel {
            writeln!(f, "Not an Intel CPU").unwrap();
            return Ok(());
        }

        writeln!(f, "SGX supported by CPU: {}", self.sgx_supported).unwrap();
        if !self.sgx_supported {
            return Ok(());
        }

        writeln!(f, "SGX1 (ECREATE, EENTER, ...): {}", self.sgx1_supported).unwrap();

        writeln!(
            f,
            "SGX2 (EAUG, EACCEPT, EMODPR, ...): {}",
            self.sgx2_supported
        )
        .unwrap();

        writeln!(
            f,
            "Flexible Launch Control (IA32_SGXPUBKEYHASH{{0..3}} MSRs): {}",
            self.flc_supported
        )
        .unwrap();

        writeln!(
            f,
            "SGX extensions for virtualizers (EINCVIRTCHILD, EDECVIRTCHILD, ESETCONTEXT): {}",
            self.sgx_virt_supported
        )
        .unwrap();

        writeln!(
            f,
            "Extensions for concurrent memory management (ETRACKC, ELDBC, ELDUC, ERDINFO): {}",
            self.sgx_memsgx_mem_concurrency_supported
        )
        .unwrap();

        writeln!(
            f,
            "CET enclave attributes support (See Table 37-5 in the SDM): {}",
            self.cet_supported
        )
        .unwrap();

        writeln!(f, "Key separation and sharing (KSS) support (CONFIGID, CONFIGSVN, ISVEXTPRODID, ISVFAMILYID report fields): {}",self.kss_supported).unwrap();

        writeln!(
            f,
            "Max enclave size (32-bit): {:#016x}",
            self.maximum_enclave_size_x86
        )
        .unwrap();

        writeln!(
            f,
            "Max enclave size (64-bit): {:#016x}",
            self.maximum_enclave_size_x64
        )
        .unwrap();

        writeln!(f, "EPC size: {:#016x}", self.epc_region_size).unwrap();

        writeln!(f, "SGX driver loaded:  {}", sgx::driver_loaded()).unwrap();

        writeln!(f, "AESMD installed: {}", sgx::aesmd_installed()).unwrap();

        write!(f, "SGX PSW/libsgx installed: {}", sgx::psw_installed()).unwrap();

        Ok(())
    }
}

impl Display for CpuId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "eax = {:#08x}", self.eax).unwrap();
        writeln!(f, "ebx = {:#08x}", self.ebx).unwrap();
        writeln!(f, "ecx = {:#08x}", self.ecx).unwrap();
        writeln!(f, "edx = {:#08x}", self.edx).unwrap();

        Ok(())
    }
}

pub fn cpuid(leaf: u32, subleaf: u32) -> CpuId {
    let mut eax: u32;
    let mut ebx: u32;
    let mut ecx: u32;
    let mut edx: u32;

    // ref: https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html / 6.47.2.5 Input Operands
    // ref: https://doc.rust-lang.org/nightly/rust-by-example/unsafe/asm.html#inputs-and-outputs
    // ref: https://doc.rust-lang.org/nightly/rust-by-example/unsafe/asm.html#clobbered-registers
    unsafe {
        asm!(
          "push rbx",
          "cpuid",
          "mov {x:e}, ebx",
          "pop rbx",
          x = out(reg) ebx,
          inout("eax") leaf => eax,
          inout("ecx") subleaf => ecx,
          out("edx") edx,
        );
    }

    CpuId { eax, ebx, ecx, edx }
}

fn is_cpuid_supported() -> bool {
    let mut write_diff: u64; // = 0u64;

    // In Intel syntax the base register is enclosed in '[' and ']' whereas in AT&T syntax it is enclosed in '('
    // and ')'.
    // ref: https://imada.sdu.dk/~kslarsen/dm546/Material/IntelnATT.htm#:~:text=The%20direction%20of%20the%20operands,second%20operand%20is%20the%20destination.
    unsafe {
        asm!(
            "pushf",
            "pushf",
            "xor qword ptr [rsp], $(1<<21)",
            "popf",
            "pushf",
            "pop {x}",
            "xor {x}, qword ptr [rsp]",
            "popf",
            x = out(reg) write_diff,
        );
    }

    write_diff != 0
}

fn is_from_intel(id: &CpuId) -> bool {
    (id.ebx == u32::from_le_bytes(*b"Genu"))
        && (id.edx == u32::from_le_bytes(*b"ineI"))
        && (id.ecx == u32::from_le_bytes(*b"ntel"))
}
