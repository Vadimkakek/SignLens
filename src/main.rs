use std::env;
use std::process::ExitCode;

use signlens::{analyze_calldata, format_human, format_json, RiskLevel};

const HELP: &str = r#"SignLens — offline EVM calldata safety lens

Usage:
  signlens <calldata> [--json]

Options:
  --json       Print machine-readable JSON
  -h, --help   Show this help

Exit codes:
  0  Decoded call without HIGH-risk warning
  1  Invalid arguments or calldata
  2  HIGH-risk pattern detected
  3  Unknown function selector

SignLens never needs a private key, seed phrase, wallet connection, or RPC endpoint."#;

fn run() -> u8 {
    let mut calldata: Option<String> = None;
    let mut json = false;

    for arg in env::args().skip(1) {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{HELP}");
                return 0;
            }
            "--json" => json = true,
            _ if arg.starts_with('-') => {
                eprintln!("SignLens failed: unknown option: {arg}");
                return 1;
            }
            _ if calldata.is_none() => calldata = Some(arg),
            _ => {
                eprintln!("SignLens failed: expected exactly one calldata value");
                return 1;
            }
        }
    }

    let Some(calldata) = calldata else {
        eprintln!("{HELP}");
        return 1;
    };

    let analysis = match analyze_calldata(&calldata) {
        Ok(analysis) => analysis,
        Err(error) => {
            eprintln!("SignLens failed: {error}");
            return 1;
        }
    };

    if json {
        println!("{}", format_json(&analysis));
    } else {
        println!("{}", format_human(&analysis));
    }

    match analysis.risk {
        RiskLevel::High => 2,
        RiskLevel::Unknown => 3,
        RiskLevel::Low | RiskLevel::Medium => 0,
    }
}

fn main() -> ExitCode {
    ExitCode::from(run())
}
