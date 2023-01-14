use crate::cpu::Checker;
use crate::sgx;

pub fn check_sgx_availability(quite: bool) -> Result<(), String> {
    let cc = Checker::new();

    if !quite {
        println!("{}", cc);
    }

    if !cc.cpuid_supported
        || !cc.from_intel
        || !cc.sgx_supported
        || (!cc.sgx1_supported && !cc.sgx2_supported)
    {
        return Err("no cpu supported".to_string());
    }

    if (cc.maximum_enclave_size_x86 == 0)
        || (cc.maximum_enclave_size_x64 == 0)
        || (cc.epc_region_size == 0)
    {
        return Err("no BIOS support".to_string());
    }

    if !sgx::psw_installed() {
        return Err("PSW not installed".to_string());
    }

    if !sgx::aesmd_installed() {
        return Err("AESMD not installed".to_string());
    }

    Ok(())
}
