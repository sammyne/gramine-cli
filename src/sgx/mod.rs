use std::fmt::Display;

use encoding::hex;

const LENGTH_REPORT_BODY: usize = 384;
const LENGTH_QUOTE_HEADER: usize = 48;
const LENGTH_SIG_STRUCT: usize = 1808;

#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
pub struct Attributes {
    pub flags: u64,
    pub xfrm: u64,
}

/// ref: https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/DCAP_1.14/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_3.h#L177
#[derive(Clone, Debug, Default)]
pub struct Quote3 {
    pub header: QuoteHeader,
    pub body: ReportBody,
    pub signature: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
pub struct QuoteHeader {
    pub version: u16,
    pub att_key_type: u16,
    pub att_key_data_0: u32,
    pub qe_svn: u16,
    pub pce_svn: u16,
    pub vendor_id: [u8; 16],
    pub user_data: [u8; 20],
}
const _QUOTE_HEADER: [u8; LENGTH_QUOTE_HEADER] = [0u8; std::mem::size_of::<QuoteHeader>()];

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct ReportBody {
    pub cpu_svn: [u8; 16],
    pub misc_select: u32,
    pub reserved1: [u8; 12],
    pub isv_ext_prod_id: [u8; 16],
    pub attributes: Attributes,
    pub mr_enclave: [u8; 32],
    pub reserved2: [u8; 32],
    pub mr_signer: [u8; 32],
    pub reserved3: [u8; 32],
    pub config_id: [u8; 64],
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    pub config_svn: u16,
    pub reserved4: [u8; 42],
    pub isv_family_id: [u8; 16],
    pub report_data: [u8; 64],
}
const _REPORT_BODY: [u8; LENGTH_REPORT_BODY] = [0u8; std::mem::size_of::<ReportBody>()];

/// ref: https://github.com/intel/linux-sgx/blob/sgx_2.18/common/inc/internal/arch.h#L258
#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
pub struct SigStruct {
    pub header: SigStructHeader,
    pub key: SigStructKey,
    pub body: SigStructBody,
    pub buffer: SigStructBuffer,
}
const _SIG_STRUCT: [u8; LENGTH_SIG_STRUCT] = [0u8; std::mem::size_of::<SigStruct>()];

/// https://github.com/intel/linux-sgx/blob/sgx_2.18/common/inc/internal/arch.h#L236
#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
pub struct SigStructBody {
    pub misc_select: u32,
    pub misc_mask: u32,
    pub reserved: [u8; 4],
    pub isv_family_id: [u8; 16],
    pub attributes: Attributes,
    pub attribute_mask: Attributes, /* (944) Mask of Attributes to Enforce */
    pub enclave_hash: [u8; 32],     /* (960) MRENCLAVE - (32 bytes) */
    pub reserved2: [u8; 16],        /* (992) Must be 0 */
    pub isvext_prod_id: [u8; 16],   /* (1008) ISV assigned Extended Product ID */
    pub isv_prod_id: u16,           /* (1024) ISV assigned Product ID */
    pub isv_svn: u16,               /* (1026) ISV assigned SVN */
}
const _SIG_STRUCT_BODY: [u8; 128] = [0; std::mem::size_of::<SigStructBody>()];

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct SigStructBuffer {
    pub reserved: [u8; 12],
    pub q1: [u8; 384],
    pub q2: [u8; 384],
}
const _SIG_STRUCT_BUF: [u8; 780] = [0; std::mem::size_of::<SigStructBuffer>()];

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct SigStructHeader {
    pub header: [u8; 12],
    pub type_: u32,
    pub module_vendor: u32,
    pub date: u32,
    pub header2: [u8; 16],
    pub hw_version: u32,
    pub reserved: [u8; 84],
}
const _SIG_STRUCT_HEADER: [u8; 128] = [0; std::mem::size_of::<SigStructHeader>()];

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct SigStructKey {
    pub modulus: [u8; 384],
    pub exponent: [u8; 4],
    pub signature: [u8; 384],
}
const _SIG_STRUCT_KEY: [u8; 772] = [0; std::mem::size_of::<SigStructKey>()];

impl Default for ReportBody {
    fn default() -> Self {
        Self {
            cpu_svn: Default::default(),
            misc_select: Default::default(),
            reserved1: Default::default(),
            isv_ext_prod_id: Default::default(),
            attributes: Default::default(),
            mr_enclave: Default::default(),
            reserved2: Default::default(),
            mr_signer: Default::default(),
            reserved3: Default::default(),
            config_id: [0u8; 64],
            isv_prod_id: Default::default(),
            isv_svn: Default::default(),
            config_svn: Default::default(),
            reserved4: [0u8; 42],
            isv_family_id: Default::default(),
            report_data: [0u8; 64],
        }
    }
}

impl Display for Attributes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (flags, xfrm) = (self.flags, self.xfrm);
        write!(f, "flags={:#066b}, xfrm={:#066b}", flags, xfrm)
    }
}

impl Display for Quote3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "[header]").unwrap();
        writeln!(f, "{}", self.header).expect("write header");
        writeln!(f, "").unwrap();

        writeln!(f, "[body]").unwrap();
        writeln!(f, "{}", self.body).expect("write body");
        writeln!(f, "").unwrap();

        writeln!(f, "[sig]").unwrap();
        writeln!(f, "length = {}", self.signature.len()).expect("write signature_length");
        writeln!(f, "data   = {}", hex::encode_to_string(self.signature.as_ref())).expect("write signature data");

        Ok(())
    }
}

impl TryFrom<&[u8]> for Quote3 {
    type Error = String;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut v = value;

        let header = QuoteHeader::try_from(v).map_err(|err| format!("parse header: {err}"))?;
        v = &v[LENGTH_QUOTE_HEADER..];

        let body = ReportBody::try_from(v).map_err(|err| format!("parse report body: {err}"))?;
        v = &v[LENGTH_REPORT_BODY..];

        let sig_len = u32::from_le_bytes((&v[..4]).try_into().expect("parse signature_length"));
        v = &v[4..];
        if v.len() != (sig_len as usize) {
            let hint = format!("bad sig data length: expect {}, got {}", sig_len, v.len());
            return Err(hint);
        }

        let signature = v.to_vec();

        let out = Self {
            header,
            body,
            signature,
        };

        Ok(out)
    }
}

impl Display for QuoteHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pad = |s: &str| -> String { fixed_length_pad(s, 14) };

        let Self {
            version,
            att_key_type,
            att_key_data_0,
            qe_svn,
            pce_svn,
            ..
        } = *self;

        writeln!(f, "{} = {:#06x}", pad("version"), version).expect("write version");
        writeln!(f, "{} = {:#06x}", pad("attn_key_type"), att_key_type)
            .expect("write attn_key_type");
        writeln!(f, "{} = {:#010x}", pad("attn_key_data0"), att_key_data_0)
            .expect("write attn_key_data0");
        writeln!(f, "{} = {:#06x}", pad("qe_svn"), qe_svn).expect("write qe_svn");
        writeln!(f, "{} = {:#06x}", pad("pce_svn"), pce_svn).expect("write pce_svn");

        writeln!(
            f,
            "{} = {}",
            pad("vendor_id"),
            hex::encode_to_string(self.vendor_id.as_ref())
        )
        .expect("write vendor-id");
        write!(
            f,
            "{} = {}",
            pad("user_data"),
            hex::encode_to_string(self.user_data.as_ref())
        )
        .expect("write user-data");

        Ok(())
    }
}

impl TryFrom<&[u8]> for QuoteHeader {
    type Error = String;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        validate_minimum_length(value.len(), LENGTH_QUOTE_HEADER)
            .map_err(|err| format!("validate length: {err}"))?;

        let out = unsafe { *(value.as_ptr() as *const Self) };

        Ok(out)
    }
}

impl Display for ReportBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pad = |s: &str| -> String { fixed_length_pad(s, 15) };

        writeln!(
            f,
            "{} = {}",
            pad("cpu-svn"),
            hex::encode_to_string(self.cpu_svn.as_ref())
        )
        .expect("write cpu-svn");

        let Self {
            misc_select,
            attributes,
            isv_prod_id,
            isv_svn,
            config_svn,
            ..
        } = *self;

        writeln!(f, "{} = {:#034b}", pad("misc_select"), misc_select).expect("write misc_select");

        writeln!(
            f,
            "{} = {}",
            pad("reserved1"),
            hex::encode_to_string(self.reserved1.as_ref())
        )
        .expect("write reserved1");

        writeln!(
            f,
            "{} = {}",
            pad("isv_ext_prod_id"),
            hex::encode_to_string(self.isv_ext_prod_id.as_ref())
        )
        .expect("write isv_ext_prod_id");

        writeln!(f, "{} = {}", pad("attributes"), attributes).expect("write attributes");

        writeln!(
            f,
            "{} = {}",
            pad("mr_enclave"),
            hex::encode_to_string(self.mr_enclave.as_ref())
        )
        .expect("write mr_enclave");

        writeln!(
            f,
            "{} = {}",
            pad("reserved2"),
            hex::encode_to_string(self.reserved2.as_ref())
        )
        .expect("write reserved2");

        writeln!(
            f,
            "{} = {}",
            pad("mr_signer"),
            hex::encode_to_string(self.mr_signer.as_ref())
        )
        .expect("write mr_signer");

        writeln!(
            f,
            "{} = {}",
            pad("reserved3"),
            hex::encode_to_string(self.reserved3.as_ref())
        )
        .expect("write reserved3");

        writeln!(
            f,
            "{} = {}",
            pad("config_id"),
            hex::encode_to_string(self.config_id.as_ref())
        )
        .expect("write config_id");

        writeln!(f, "{} = {:#06x}", pad("isv_prod_id"), isv_prod_id).expect("write isv_prod_id");
        writeln!(f, "{} = {:#06x}", pad("isv_svn"), isv_svn).expect("write isv_svn");
        writeln!(f, "{} = {:#06x}", pad("config_svn"), config_svn).expect("write config_svn");

        writeln!(
            f,
            "{} = {}",
            pad("reserved4"),
            hex::encode_to_string(self.reserved4.as_ref())
        )
        .expect("write reserved4");

        writeln!(
            f,
            "{} = {}",
            pad("isv_family_id"),
            hex::encode_to_string(self.isv_family_id.as_ref())
        )
        .expect("write isv_family_id");

        write!(
            f,
            "{} = {}",
            pad("report_data"),
            hex::encode_to_string(self.report_data.as_ref())
        )
        .expect("write report_data");

        Ok(())
    }
}

impl TryFrom<&[u8]> for ReportBody {
    type Error = String;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        validate_minimum_length(value.len(), LENGTH_REPORT_BODY)
            .map_err(|err| format!("validate length: {err}"))?;

        let out = unsafe { *(value.as_ptr() as *const Self) };
        Ok(out)
    }
}

impl Display for SigStruct {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "[header]").unwrap();
        writeln!(f, "{}", self.header).expect("write header");

        writeln!(f, "[sig]").unwrap();
        writeln!(f, "{}", self.key).expect("write sig");

        writeln!(f, "[body]").unwrap();
        writeln!(f, "{}", self.body).expect("write body");

        writeln!(f, "[buffer]").unwrap();
        write!(f, "{}", self.buffer).expect("write buffer");

        Ok(())
    }
}

impl TryFrom<&[u8]> for SigStruct {
    type Error = String;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != LENGTH_SIG_STRUCT {
            let hint = format!(
                "bad length: expect {}, got {}",
                LENGTH_SIG_STRUCT,
                value.len()
            );
            return Err(hint);
        }

        let mut out = Self::default();

        let buf = unsafe {
            std::slice::from_raw_parts_mut(&mut out as *mut Self as *mut u8, LENGTH_SIG_STRUCT)
        };

        // todo: validate

        buf.copy_from_slice(value);

        Ok(out)
    }
}

impl Default for SigStructBuffer {
    fn default() -> Self {
        Self {
            reserved: Default::default(),
            q1: [0u8; 384],
            q2: [0u8; 384],
        }
    }
}

impl Display for SigStructBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pad = |s: &str| -> String { fixed_length_pad(s, 8) };

        writeln!(
            f,
            "{} = {}",
            pad("reserved"),
            hex::encode_to_string(self.reserved.as_ref())
        )
        .expect("write reserved");

        writeln!(
            f,
            "{} = {}",
            pad("q1"),
            hex::encode_to_string(self.q1.as_ref())
        )
        .expect("write q1");

        writeln!(
            f,
            "{} = {}",
            pad("q2"),
            hex::encode_to_string(self.q2.as_ref())
        )
        .expect("write q2");

        Ok(())
    }
}

impl Default for SigStructHeader {
    fn default() -> Self {
        Self {
            header: Default::default(),
            type_: Default::default(),
            module_vendor: Default::default(),
            date: Default::default(),
            header2: Default::default(),
            hw_version: Default::default(),
            reserved: [0u8; 84],
        }
    }
}

impl Display for SigStructHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pad = |s: &str| -> String { fixed_length_pad(s, 16) };

        writeln!(
            f,
            "{} = {}",
            pad("header"),
            hex::encode_to_string(self.header.as_ref())
        )
        .expect("write header");

        let type_desc = if (self.type_ & 0x01) == 0x01 {
            "debug"
        } else {
            "prod"
        };
        writeln!(f, "{} = {type_desc}", pad("type")).expect("write type");

        let vendor = if self.module_vendor == 0x8086 {
            "intel"
        } else {
            "isv"
        };
        writeln!(f, "{} = {vendor}", pad("module_vendor")).expect("write module_vendor");

        let (year, month, day) = (
            self.date & 0xffff,
            (self.date >> 16) & 0xff,
            self.date >> 24,
        );
        writeln!(f, "date(yyyy-mm-dd) = {year}-{month:#02}-{day:#02}").expect("write date");

        writeln!(
            f,
            "header2          = {}",
            hex::encode_to_string(self.header2.as_ref())
        )
        .expect("write header2");

        let hw_version = self.hw_version;
        writeln!(
            f,
            "hw_version       = {}  # non-zero for Launch Enclaves; Otherwise 0",
            hw_version
        )
        .expect("write hw_version");

        writeln!(
            f,
            "{} = {}",
            pad("reserved"),
            hex::encode_to_string(self.reserved.as_ref())
        )
        .expect("write reserved");

        Ok(())
    }
}

impl Default for SigStructKey {
    fn default() -> Self {
        Self {
            modulus: [0u8; 384],
            exponent: Default::default(),
            signature: [0u8; 384],
        }
    }
}

impl Display for SigStructKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pad = |s: &str| -> String { fixed_length_pad(s, 9) };

        writeln!(
            f,
            "{} = {}",
            pad("modulus"),
            hex::encode_to_string(self.modulus.as_ref())
        )
        .expect("write modulus");

        writeln!(
            f,
            "{} = {}",
            pad("exponent"),
            u32::from_le_bytes(self.exponent)
        )
        .expect("write exponent");

        writeln!(
            f,
            "{} = {}",
            pad("signature"),
            hex::encode_to_string(self.signature.as_ref())
        )
        .expect("write signature");

        Ok(())
    }
}

impl Display for SigStructBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pad = |s: &str| -> String { fixed_length_pad(s, 14) };

        let v = self.misc_select;
        writeln!(f, "{} = {:#034b}", pad("misc_select"), v).expect("write misc_select");

        let v = self.misc_mask;
        writeln!(f, "{} = {:#034b}", pad("misc_mask"), v).expect("write misc_mask");

        writeln!(
            f,
            "{} = 0x{}",
            pad("reserved"),
            hex::encode_to_string(self.reserved.as_ref())
        )
        .expect("write reserved");

        writeln!(
            f,
            "{} = 0x{}",
            pad("isv_family_id"),
            hex::encode_to_string(self.isv_family_id.as_ref())
        )
        .expect("write isv_family_id");

        writeln!(f, "{} = {}", pad("attributes"), self.attributes).expect("write attributes");
        writeln!(f, "{} = {}", pad("attribute_mask"), self.attribute_mask)
            .expect("write attribute_mask");

        writeln!(
            f,
            "{} = 0x{}",
            pad("mrenclave"),
            hex::encode_to_string(&self.enclave_hash)
        )
        .expect("write MRENCLAVE");

        writeln!(
            f,
            "{} = 0x{}",
            pad("reserved2"),
            hex::encode_to_string(self.reserved2.as_ref())
        )
        .expect("write reserved2");

        writeln!(
            f,
            "{} = 0x{}",
            pad("isvext_prod_id"),
            hex::encode_to_string(self.isvext_prod_id.as_ref())
        )
        .expect("write isvext_prod_id");

        let v = self.isv_prod_id;
        writeln!(f, "{} = {}", pad("isv_prod_id"), v).expect("write isv_prod_id");

        let v = self.isv_svn;
        writeln!(f, "{} = {}", pad("isv_svn"), v).expect("write isv_svn");

        Ok(())
    }
}

fn fixed_length_pad(s: &str, n: usize) -> String {
    if s.len() >= n {
        return s.to_string();
    }

    let mut out = String::with_capacity(n);
    out += s;
    while out.len() != out.capacity() {
        out += " ";
    }

    out
}

fn validate_minimum_length(got: usize, minimum: usize) -> Result<(), String> {
    if minimum <= got {
        Ok(())
    } else {
        let hint = format!("bad length: expect>={}, got={}", minimum, got);
        Err(hint)
    }
}

mod checker;

pub use checker::*;
