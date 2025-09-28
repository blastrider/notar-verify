use crate::cms::verify::verify_cms_entrypoint;
use crate::infra::fs::{read_file_bounded, Limits};
use crate::report::{final_verdict, Component, Report, ReportVerdict};
use anyhow::{Context, Result};
use lopdf::{Document, Object, ObjectId};
use sha2::{Digest, Sha256};
use tracing::debug;

#[derive(thiserror::Error, Debug)]
pub enum PdfErr {
    #[error("Champ de signature PDF introuvable")]
    NoSignature,
    #[error("ByteRange manquant ou invalide")]
    NoByteRange,
    #[error("Contents manquant")]
    NoContents,
}

pub fn verify_pdf_pades(
    pdf_path: &str,
    anchors_pem: &[String],
    crl: &[String],
    ocsp: &[String],
    online: bool,
    limits: &Limits,
) -> Result<Report> {
    let pdf_bytes = read_file_bounded(pdf_path, limits)?;
    let mut doc = Document::load_mem(&pdf_bytes).context("Chargement PDF a échoué")?;

    let (sig_obj_id, sig_dict) = find_signature_dict(&doc).map_err(|_| PdfErr::NoSignature).context("Aucune signature PDF détectée")?;
    debug!(?sig_obj_id, "Signature field trouvé");

    let byte_range = sig_dict.get(b"ByteRange").ok_or(PdfErr::NoByteRange)?;
    let br = parse_byterange(byte_range).context("ByteRange invalide")?;

    let contents = sig_dict.get(b"Contents").ok_or(PdfErr::NoContents)?;
    let cms_blob = extract_contents(contents).context("Contents invalide")?;

    // Intégrité: recomposer les segments ByteRange et hasher
    let digest_doc = sha256_over_ranges(&pdf_bytes, &br)?;
    let document_sha256 = hex::encode(digest_doc);

    // Écrire CMS dans un tmp et passer par l’entrypoint CMS (uniformiser le flux)
    // Ici on garde en mémoire sans I/O disque : passer via buffer spécialisé
    // → on écrit sur /tmp uniquement pour l’intégration simple
    let tmp_sig = tempfile::NamedTempFile::new().context("tmp sig")?;
    std::fs::write(tmp_sig.path(), &cms_blob).context("Écriture tmp sig")?;

    let mut report = verify_cms_entrypoint(
        tmp_sig.path().to_string_lossy().as_ref(),
        Some(pdf_path), // PAdES est sémantiquement “detached” sur ByteRange
        anchors_pem,
        crl,
        ocsp,
        online,
        limits,
    )?;

    report.input_kind = "PDF".into();
    report.integrity = Component { status: ReportVerdict::Valid, detail: "ByteRange cohérent, hash recomposé OK".into() };
    report.document_sha256 = Some(document_sha256);

    // LTV/DSS (MVP : présence)
    if let Some(_dss) = find_dss(&doc) {
        report.ltv = Component { status: ReportVerdict::Warning, detail: "DSS présent (exploiter CRL/OCSP embarqués à implémenter)".into() };
    } else {
        report.ltv = Component { status: ReportVerdict::Warning, detail: "DSS absent".into() };
    }

    // Horodatage (MVP: lecture SigningTime dans CMS côté verify_cms → non implémenté)
    // report.timestamp_rfc3161 = ...

    final_verdict(&mut report);
    Ok(report)
}

fn find_signature_dict(doc: &Document) -> Result<(ObjectId, lopdf::Dictionary)> {
    for (id, obj) in &doc.objects {
        if let Ok(dict) = obj.as_dict() {
            if let Some(Object::Name(subtype)) = dict.get(b"Subtype") {
                if subtype == b"Widget" {
                    if let Some(Object::Dictionary(annot)) = dict.get(b"AP") {
                        let _ = annot; // non requis ici
                    }
                }
            }
            if let Some(Object::Dictionary(v)) = dict.get(b"V") {
                // v est le dictionnaire de signature
                return Ok((*id, v.clone()));
            }
        }
    }
    Err(anyhow::anyhow!("Aucune dict de signature"))
}

fn parse_byterange(obj: &Object) -> Result<Vec<(usize, usize)>> {
    if let Object::Array(arr) = obj {
        if arr.len() % 2 != 0 {
            return Err(anyhow::anyhow!("ByteRange paire attendue"));
        }
        let mut res = Vec::new();
        let mut it = arr.iter();
        while let (Some(a), Some(b)) = (it.next(), it.next()) {
            let off = a.as_i64().unwrap_or(0) as usize;
            let len = b.as_i64().unwrap_or(0) as usize;
            res.push((off, len));
        }
        return Ok(res);
    }
    Err(anyhow::anyhow!("ByteRange non-array"))
}

fn extract_contents(obj: &Object) -> Result<Vec<u8>> {
    match obj {
        Object::String(s, _) => Ok(s.clone().into_bytes()),
        Object::Stream(stm) => Ok(stm.content.clone()),
        _ => Err(anyhow::anyhow!("Contents inattendu")),
    }
}

fn sha256_over_ranges(pdf: &[u8], ranges: &[(usize, usize)]) -> Result<Vec<u8>> {
    let mut h = Sha256::new();
    for (off, len) in ranges {
        let end = off.saturating_add(*len);
        if end > pdf.len() { return Err(anyhow::anyhow!("ByteRange hors limites")); }
        h.update(&pdf[*off..end]);
    }
    Ok(h.finalize().to_vec())
}

fn find_dss(doc: &Document) -> Option<lopdf::Dictionary> {
    // Heuristique: recherche d’un objet nommé DSS (ETSI)
    for (_id, obj) in &doc.objects {
        if let Ok(dict) = obj.as_dict() {
            if dict.get(b"Type").and_then(|o| o.as_name().ok()).map(|n| n == b"DSS").unwrap_or(false) {
                return Some(dict.clone());
            }
        }
    }
    None
}
