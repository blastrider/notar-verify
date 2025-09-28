use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_bytes: u64,
}

impl Limits {
    pub fn from_mib(mib: u64) -> Self {
        Self { max_bytes: mib * 1024 * 1024 }
    }
}

fn normalize(path: &str) -> Result<PathBuf> {
    let pb = PathBuf::from(path);
    let abs = pb.canonicalize().with_context(|| format!("Chemin invalide: {path}"))?;
    let s = abs.to_string_lossy();
    if s.contains("..") {
        bail!("Traversal détecté");
    }
    Ok(abs)
}

pub fn read_file_bounded(path: &str, limits: &Limits) -> Result<Vec<u8>> {
    let p = normalize(path)?;
    let md = fs::metadata(&p).with_context(|| format!("Stat échouée: {}", p.display()))?;
    if md.len() > limits.max_bytes {
        bail!("Fichier trop volumineux ({} bytes > limite)", md.len());
    }
    let data = fs::read(&p).with_context(|| format!("Lecture échouée: {}", p.display()))?;
    Ok(data)
}

pub fn read_all_pems(paths: &[String], limits: &Limits) -> Result<Vec<String>> {
    let mut res = Vec::new();
    for p in paths {
        let d = read_file_bounded(p, limits)?;
        let s = String::from_utf8(d).context("PEM non UTF-8")?;
        // Check minimal PEM header presence
        if !s.contains("-----BEGIN") {
            bail!("Fichier --trust sans bloc PEM BEGIN/END");
        }
        res.push(s);
    }
    Ok(res)
}
