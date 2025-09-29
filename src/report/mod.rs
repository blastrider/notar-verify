use comfy_table::{Cell, Table};
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Clone, Copy, Debug)]
pub enum ExitCode {
    Valid = 0,
    Invalid = 1,
    Warning = 2,
}


#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReportVerdict {
    Valid,
    Invalid,
    #[default]
    Warning,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Component {
    pub status: ReportVerdict,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Report {
    pub input_kind: String, // "PDF" | "CMS"
    pub algorithms: Vec<String>,
    pub signer_dn: Option<String>,
    pub certificate_chain: Vec<String>,
    pub signing_time: Option<String>,
    pub timestamp_rfc3161: Option<String>,
    pub revocation: Component,
    pub integrity: Component,
    pub signature: Component,
    pub chain: Component,
    pub ltv: Component,
    pub verdict: ReportVerdict,
    pub document_sha256: Option<String>,
}

pub fn print_table(r: &Report) {
    let mut t = Table::new();
    t.set_header(vec![
        "Intégrité",
        "Signature",
        "Certificat/Chaîne",
        "Horodatage",
        "Révocation",
        "LTV",
        "Verdict",
    ]);
    t.add_row(vec![
        Cell::new(format!("{:?}", r.integrity.status)),
        Cell::new(format!("{:?}", r.signature.status)),
        Cell::new(format!("{:?}", r.chain.status)),
        Cell::new(
            r.timestamp_rfc3161
                .clone()
                .unwrap_or_else(|| "-".to_string()),
        ),
        Cell::new(format!("{:?}", r.revocation.status)),
        Cell::new(format!("{:?}", r.ltv.status)),
        Cell::new(format!("{:?}", r.verdict)),
    ]);
    println!("{t}");
}

pub fn write_json(r: &Report, path: &str) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(r)?;
    fs::write(path, json)?;
    Ok(())
}

pub fn final_verdict(r: &mut Report) {
    use ReportVerdict::*;

    // Critères essentiels
    let sig = &r.signature.status;
    let integ = &r.integrity.status;
    let chain = &r.chain.status;

    if matches!(sig, Invalid) || matches!(integ, Invalid) || matches!(chain, Invalid) {
        r.verdict = Invalid;
        return;
    }

    if matches!(sig, Valid) && matches!(integ, Valid) && matches!(chain, Valid) {
        r.verdict = Valid;
        return;
    }

    // Le reste (revocation/LTV non évalués) => Warning
    r.verdict = Warning;
}
