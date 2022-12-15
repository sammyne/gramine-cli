use std::io::Write;

use crate::sgx::{Quote3, SigStruct};

pub fn decode_and_dump_quote3<W>(out: &mut W, b: &[u8]) -> Result<(), String>
where
    W: Write,
{
    let quote = Quote3::try_from(b).map_err(|err| format!("parse: {err}"))?;

    writeln!(out, "{quote}").map_err(|err| format!("dump: {err}"))
}

pub fn decode_and_dump_sig_struct<W>(out: &mut W, b: &[u8]) -> Result<(), String>
where
    W: Write,
{
    let ss = SigStruct::try_from(b).map_err(|err| format!("parse: {err}"))?;

    writeln!(out, "{ss}").map_err(|err| format!("write: {err}"))
}
