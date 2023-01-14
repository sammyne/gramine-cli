use clap::Parser;

/// CLI helps working with gramine libOS.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(clap::Subcommand, Debug)]
pub enum Cmd {
    /// Generate a private key suitable for signing SGX enclaves.
    /// SGX requires RSA 3072 keys with public exponent equal to 3.
    GenerateKey {
        /// Path to write the generated key. Default output to stdout in PEM. Path with '.pem' suffix means output
        /// as PEM file. Path with '.pkcs8' suffix means output as PKCS8-encoded DER file.
        #[arg(long, short)]
        out: Option<String>,
    },
    /// Check SGX availability.
    IsSgxAvailable {
        /// Whether print detailed info.
        #[arg(long, short)]
        quite: bool,
    },
    /// Dump a DCAP-based quote.
    DumpQuote3 {
        #[arg(long = "in", short = 'i')]
        filename: String,
    },
    /// Dump a SIGSTRUCT.
    DumpSigStruct {
        #[arg(long = "in", short = 'i')]
        in_path: String,
    },
}
