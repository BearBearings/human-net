use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::Value;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const REPUTATION_DIR: &str = "reputation";

pub fn load_latest_reputation(trust_root: &Path, target: &str) -> Result<Option<Vec<u8>>> {
    let rep_root = trust_root.join(REPUTATION_DIR);
    if !rep_root.exists() {
        return Ok(None);
    }

    let mut best: Option<(OffsetDateTime, Vec<u8>)> = None;
    for alias_entry in
        fs::read_dir(&rep_root).with_context(|| format!("failed to read {}", rep_root.display()))?
    {
        let alias_entry = alias_entry?;
        if !alias_entry.file_type()?.is_dir() {
            continue;
        }
        let alias_path = alias_entry.path();
        scan_alias_dir(&alias_path, target, &mut best)?;
    }

    Ok(best.map(|(_, data)| data))
}

fn scan_alias_dir(
    dir: &Path,
    target: &str,
    best: &mut Option<(OffsetDateTime, Vec<u8>)>,
) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        let data = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
        let value: Value = match serde_json::from_slice(&data) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if value
            .get("target")
            .and_then(|v| v.as_str())
            .map(|t| t != target)
            .unwrap_or(true)
        {
            continue;
        }
        let timestamp_str = match value.get("generated_at").and_then(|v| v.as_str()) {
            Some(ts) => ts,
            None => continue,
        };
        let generated_at = match OffsetDateTime::parse(timestamp_str, &Rfc3339) {
            Ok(ts) => ts,
            Err(_) => continue,
        };
        match best {
            Some((current, _)) if *current >= generated_at => {}
            _ => *best = Some((generated_at, data.clone())),
        }
    }
    Ok(())
}
