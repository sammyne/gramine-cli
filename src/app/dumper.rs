use std::io::Write;

use crate::sgx::SigStruct;

pub fn decode_and_dump_sig_struct<W>(out: &mut W, b: &[u8]) -> Result<(), String>
where
    W: Write,
{
    let ss = SigStruct::try_from(b).map_err(|err| format!("parse: {err}"))?;

    writeln!(out, "{ss}").map_err(|err| format!("write: {err}"))
}
