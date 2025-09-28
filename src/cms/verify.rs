use crate::infra::fs::{read_file_bounded, Limits};
use crate::report::{final_verdict, Component, Report, ReportVerdict};
use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use sha2::{Digest, Sha256};
use tracing::debug;

#[cfg(feature = "openssl-backend")]
mod openssl_impl {
    use super::*;
    use anyhow::{bail};
    use openssl::pkcs7::Pkcs7;
    use openssl::x509::X509;
    use openssl::stack::Stack;
    use openssl::pkey::PKey;

    pub fn verify_detached(sig_der: &[u8], data: &[u8], anchors_pem: &[String]) -> Result<(Vec<String>, Option<String>)> {
        // Charger PKCS7
        let pkcs7 = Pkcs7::from_der(sig_der)?;
        // Construire store de confiance
        let mut store = openssl::x509::store::X509StoreBuilder::new()?;
        for pem in anchors_pem {
            for crt in X509::stack_from_pem(pem.as_bytes())? {
                store.add_cert(crt)?;
            }
        }
        let store = store.build();

        // Extraire chain & signer
        let certs = pkcs7.certificates().unwrap_or(&Stack::new()?).to_owned();
        let mut chain_dns = Vec::new();
        let mut signer_dn = None;
        for c in certs.iter() {
            chain_dns.push(c.subject_name().entries().next().map(|e| e.data().as_utf8().unwrap_or_default().to_string()).unwrap_or_default());
            if signer_dn.is_none() {
                signer_dn = Some(c.subject_name().entries().next().map(|e| e.data().as_utf8().unwrap_or_default().to_string()).unwrap_or_default());
            }
        }

        // Vérif signature (detached)
        let mut bio_in = openssl::bio::MemBio::new()?;
        bio_in.write(data)?;
        let mut bio_out = openssl::bio::MemBio::new()?;
        let flags = openssl::pkcs7::Pkcs7Flags::BINARY | openssl::pkcs7::Pkcs7Flags::NOINTERN;
        let verified = pkcs7.verify(&certs, &store, Some(&bio_in), Some(&mut bio_out), flags);
        if verified.is_err() {
            bail!("Signature PKCS7 non valide");
        }

        Ok((chain_dns, signer_dn))
    }
}

pub fn verify_cms_entrypoint(
    sig_path: &str,
    data_path: Option<&str>,
    anchors_pem: &[String],
    _crl: &[String],
    _ocsp: &[String],
    _online: bool,
    limits: &Limits,
) -> Result<Report> {
    let sig = read_file_bounded(sig_path, limits)?;
    let data = if let Some(d) = data_path {
        Some(read_file_bounded(d, limits)?)
    } else {
        None
    };

    let mut r = Report {
        input_kind: "CMS".to_string(),
        ..Default::default()
    };

    // Empreinte document si data
    if let Some(ref dat) = data {
        let mut h = Sha256::new();
        h.update(dat);
        r.document_sha256 = Some(hex::encode(h.finalize()));
    }

    // Tentative de décodage si Base64 (communs pour .p7s)
    let sig_der = if sig.starts_with(b"-----BEGIN") {
        // PEM → DER (simpliste)
        let s = String::from_utf8(sig.clone()).context("P7S PEM non UTF-8")?;
        let der = extract_pem_block(&s, "PKCS7")?;
        der
    } else {
        // Essai base64 sinon brut
        match B64.decode(&sig) {
            Ok(der) => der,
            Err(_) => sig.clone(),
        }
    };

    #[cfg(feature = "openssl-backend")]
    {
        if let Some(ref dat) = data {
            match openssl_impl::verify_detached(&sig_der, dat, anchors_pem) {
                Ok((chain_dns, signer_dn)) => {
                    r.signature = Component { status: ReportVerdict::Valid, detail: "PKCS#7 détaché valide".into() };
                    r.chain    = Component { status: ReportVerdict::Warning, detail: "Chaîne basique: ancrages chargés (validation avancée à étendre)".into() };
                    r.signer_dn = signer_dn;
                    r.certificate_chain = chain_dns;
                }
                Err(e) => {
                    r.signature = Component { status: ReportVerdict::Invalid, detail: format!("Échec vérif PKCS#7: {e}") };
                    r.chain = Component { status: ReportVerdict::Warning, detail: "Chaîne non évaluée".into() };
                }
            }
        } else {
            r.signature = Component { status: ReportVerdict::Warning, detail: "P7M enveloppé non implémenté dans MVP".into() };
        }
        final_verdict(&mut r);
        return Ok(r);
    }

    // Fallback (sans OpenSSL) → MVP conservateur
    r.signature = Component {
        status: ReportVerdict::Warning,
        detail: "Pile native CMS non activée : utilisez --features openssl-backend pour une vérification cryptographique complète.",
    };
    r.chain = Component {
        status: ReportVerdict::Warning,
        detail: "Validation de chaîne limitée sans backend X.509 avancé.",
    };
    final_verdict(&mut r);
    Ok(r)
}

fn extract_pem_block(pem: &str, _label: &str) -> Result<Vec<u8>> {
    // extraction simple (1er bloc)
    let start = pem.find("-----BEGIN").context("Bloc PEM BEGIN introuvable")?;
    let end = pem.find("-----END").context("Bloc PEM END introuvable")?;
    let inner = &pem[start..].lines().skip(1).take_while(|l| !l.starts_with("-----END")).collect::<Vec<_>>().join("");
    let der = base64::decode(inner)?;
    Ok(der)
}
