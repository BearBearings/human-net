use std::env;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

const DEFAULT_DIR: &str = ".human-net";
const ENV_HOME: &str = "HN_HOME";

/// Resolve the Human.Net home directory, creating it if necessary.
pub fn ensure_home_dir() -> Result<PathBuf> {
    let path = resolve_home_dir()?;
    if !path.exists() {
        std::fs::create_dir_all(&path)
            .with_context(|| format!("failed to create Human.Net home at {}", path.display()))?;
    }
    Ok(path)
}

fn resolve_home_dir() -> Result<PathBuf> {
    if let Ok(explicit) = env::var(ENV_HOME) {
        let path = PathBuf::from(explicit);
        if path.is_absolute() {
            return Ok(path);
        }
        let cwd = env::current_dir().context("unable to read current working directory")?;
        return Ok(cwd.join(path));
    }

    let home =
        dirs::home_dir().context("could not determine user home directory; set HN_HOME instead")?;
    Ok(home.join(DEFAULT_DIR))
}

/// Ensure the given subdirectory exists inside the Human.Net home.
pub fn ensure_subdir(home: &Path, name: &str) -> Result<PathBuf> {
    let path = home.join(name);
    if !path.exists() {
        std::fs::create_dir_all(&path)
            .with_context(|| format!("failed to create {}", path.display()))?;
    }
    Ok(path)
}
