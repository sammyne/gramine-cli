use clap::Parser;

use gramine_cli::{cmd, Cli, Cmd};

fn main() -> Result<(), String> {
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::GenerateKey { out } => cmd::generate_key(out),
        Cmd::DumpSigStruct { in_path } => cmd::dump_sig_struct(in_path),
    }
}
