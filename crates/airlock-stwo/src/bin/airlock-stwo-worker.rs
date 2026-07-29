//! Minimal JSON worker used by AIRLock's subprocess boundary.

use std::io::{Read, Write};
use std::process::ExitCode;

use airlock_stwo::{ReplayRequest, execute_replay_request};

const MAX_REQUEST_BYTES: u64 = 1 << 20;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("airlock-stwo-worker: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), String> {
    let mut request_bytes = Vec::new();
    std::io::stdin()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut request_bytes)
        .map_err(|error| format!("read request: {error}"))?;
    if request_bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("request exceeds the 1 MiB worker limit".to_owned());
    }
    let request: ReplayRequest = serde_json::from_slice(&request_bytes)
        .map_err(|error| format!("decode request: {error}"))?;
    let replay = execute_replay_request(&request).map_err(|error| error.to_string())?;
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &replay)
        .map_err(|error| format!("encode replay: {error}"))?;
    output
        .write_all(b"\n")
        .and_then(|()| output.flush())
        .map_err(|error| format!("write replay: {error}"))
}
