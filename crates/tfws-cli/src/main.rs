#![forbid(unsafe_code)]

use std::{env, fs, process::ExitCode};
use tfws_core::Manifest;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_default();
    if command != "validate" {
        eprintln!("usage: tfws-cli validate <manifest.json>");
        return ExitCode::from(2);
    }
    let Some(path) = args.next() else {
        eprintln!("manifest path is required");
        return ExitCode::from(2);
    };
    if args.next().is_some() {
        eprintln!("unexpected argument");
        return ExitCode::from(2);
    }
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("unable to read manifest: {error}");
            return ExitCode::from(1);
        }
    };
    let manifest: Manifest = match serde_json::from_str(&text) {
        Ok(manifest) => manifest,
        Err(error) => {
            eprintln!("invalid JSON: {error}");
            return ExitCode::from(1);
        }
    };
    match manifest.validate() {
        Ok(()) => {
            println!("valid");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("invalid: {error}");
            ExitCode::from(1)
        }
    }
}
