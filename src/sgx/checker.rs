use std::path::Path;

pub fn aesmd_installed() -> bool {
    is_file_exists("/var/run/aesmd/aesm.socket")
}

pub fn driver_loaded() -> bool {
    is_file_exists("/dev/isgx") || is_file_exists("/dev/sgx") || is_file_exists("/dev/sgx_enclave")
}

pub fn psw_installed() -> bool {
    driver_loaded() && is_file_exists("/etc/aesmd.conf")
}

fn is_file_exists(p: &str) -> bool {
    match Path::new(p).try_exists() {
        Ok(true) => true,
        _ => false,
    }
}
