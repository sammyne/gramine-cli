use std::fs::{self, File};
use std::io;

use crate::app;
use crate::app::types::KeyFormat;

pub fn dump_sig_struct(path: String) -> Result<(), String> {
    let b = fs::read(path).map_err(|err| format!("read file: {err}"))?;

    let mut stdout = io::stdout();
    app::decode_and_dump_sig_struct(&mut stdout, &b)
        .map_err(|err| format!("decode and dump: {err}"))
}

pub fn generate_key(out_path: Option<String>) -> Result<(), String> {
    let out_path = match out_path {
        None => {
            let mut out = io::stdout();
            return app::generate_and_encode_key(&mut out, KeyFormat::PEM);
        }
        Some(v) => v,
    };

    let f = if out_path.ends_with(".pkcs8") {
        KeyFormat::DER
    } else if out_path.ends_with(".pem") {
        KeyFormat::PEM
    } else {
        return Err("filename suffix must be one of: '.pkcs8', '.pem'".to_string());
    };

    let mut out = File::create(out_path).map_err(|err| format!("open file: {err}"))?;

    app::generate_and_encode_key(&mut out, f)
}
