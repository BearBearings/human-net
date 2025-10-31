use std::process::Command;

use anyhow::{anyhow, Result};

fn main() -> Result<()> {
    let status = Command::new("bash")
        .arg("tooling/scripts/m5-smoke.sh")
        .args(std::env::args().skip(1))
        .status()
        .map_err(|err| anyhow!("failed to execute m5-smoke.sh: {err}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("m5 smoke script exited with status {status}"))
    }
}
