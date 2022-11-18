use std::io::Write;

use openssl::bn::BigNum;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;

use crate::app::types::KeyFormat;

lazy_static::lazy_static! {
  static ref E: BigNum = BigNum::from_u32(3).expect("init public component e for RSA");
}

pub fn generate_and_encode_key<W>(w: &mut W, f: KeyFormat) -> Result<(), String>
where
    W: Write,
{
    let raw = Rsa::generate_with_e(3072, &E).map_err(|err| format!("generate: {err}"))?;
    let privkey = PKey::from_rsa(raw).map_err(|err| format!("RSA privkey as EVP_PKEY: {err}"))?;

    let encoded = match f {
        KeyFormat::DER => privkey
            .private_key_to_der()
            .map_err(|err| format!("PKCS8 encode: {err}"))?,
        KeyFormat::PEM => privkey
            .private_key_to_pem_pkcs8()
            .map_err(|err| format!("PEM encode: {err}"))?,
    };

    w.write_all(encoded.as_slice())
        .map_err(|err| format!("write: {err}"))
}
