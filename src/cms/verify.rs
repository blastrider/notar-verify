use crate::infra::fs::{read_file_bounded, Limits};
use crate::report::{final_verdict, Component, Report, ReportVerdict};
use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use sha2::{Digest, Sha256};

#[cfg(feature = "openssl-backend")]
mod openssl_impl {
    use super::*;
    use openssl::nid::Nid;
    use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
    use openssl::stack::Stack;
    use openssl::x509::{store::X509StoreBuilder, X509NameRef, X509};

    fn x509_cn_or_first(n: &X509NameRef) -> String {
        if let Some(cn) = n.entries_by_nid(Nid::COMMONNAME).next() {
            return cn
                .data()
                .as_utf8()
                .map(|s| s.to_string())
                .unwrap_or_else(|_| String::new());
        }
        n.entries()
            .next()
            .and_then(|e| e.data().as_utf8().ok())
            .map(|s| s.to_string())
            .unwrap_or_default()
    }

    /// Vérifie un PKCS#7 détaché et retourne (subjects des signataires, DN principal).
    pub fn verify_detached(
        sig_der: &[u8],
        data: &[u8],
        anchors_pem: &[String],
    ) -> anyhow::Result<(Vec<String>, Option<String>)> {
        // 1) PKCS#7
        let pkcs7 = Pkcs7::from_der(sig_der).context("PKCS#7 DER invalide")?;

        // 2) Store d’ancrages
        let mut store_bld = X509StoreBuilder::new().context("init X509StoreBuilder")?;
        for pem in anchors_pem {
            for crt in X509::stack_from_pem(pem.as_bytes()).context("anchors PEM invalides")? {
                store_bld.add_cert(crt).context("ajout anchor")?;
            }
        }
        let store = store_bld.build();

        // 3) Pile additionnelle vide
        let extra = Stack::<X509>::new().context("init stack X509")?;

        // 4) Vérif détachée
        let mut sink = Vec::<u8>::new();
        pkcs7
            .verify(
                &extra,
                &store,
                Some(data),
                Some(&mut sink),
                Pkcs7Flags::BINARY,
            )
            .map_err(|e| anyhow::anyhow!("Signature PKCS#7 non valide: {e}"))?;

        // 5) Signataires
        let signers = pkcs7
            .signers(&extra, Pkcs7Flags::empty())
            .context("Extraction des signataires")?;

        let mut subjects = Vec::new();
        let mut signer_dn: Option<String> = None;

        if !signers.is_empty() {
            for (i, cert) in signers.iter().enumerate() {
                let dn = x509_cn_or_first(cert.subject_name());
                if i == 0 {
                    signer_dn = Some(dn.clone());
                }
                subjects.push(dn);
            }
        } else {
            // Fallback: pas de certs embarqués → utiliser les anchors pour remplir informativement
            for pem in anchors_pem {
                for crt in X509::stack_from_pem(pem.as_bytes()).context("anchors PEM invalides")? {
                    let dn = x509_cn_or_first(crt.subject_name());
                    if signer_dn.is_none() {
                        signer_dn = Some(dn.clone());
                    }
                    subjects.push(dn);
                }
            }
        }

        Ok((subjects, signer_dn))
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

    if let Some(ref dat) = data {
        let mut h = Sha256::new();
        h.update(dat);
        r.document_sha256 = Some(hex::encode(h.finalize()));
    }

    let sig_der = if sig.starts_with(b"-----BEGIN") {
        let s = String::from_utf8(sig.clone()).context("P7S PEM non UTF-8")?;
        extract_pem_block(&s, "PKCS7")?
    } else {
        match B64.decode(&sig) {
            Ok(der) => der,
            Err(_) => sig.clone(),
        }
    };

    #[cfg(not(feature = "openssl-backend"))]
    {
        let _ = &sig_der;
        let _ = anchors_pem;
    }

    // --- Branche OpenSSL ----------------------------------------------------
    #[cfg(feature = "openssl-backend")]
    {
        if let Some(ref dat) = data {
            match openssl_impl::verify_detached(&sig_der, dat, anchors_pem) {
                Ok((chain_dns, signer_dn)) => {
                    r.signature = Component {
                        status: ReportVerdict::Valid,
                        detail: "PKCS#7 détaché valide".into(),
                    };
                    r.integrity = Component {
                        status: ReportVerdict::Valid,
                        detail: "MessageDigest/Data vérifiés".into(),
                    };
                    if !anchors_pem.is_empty() {
                        r.chain = Component {
                            status: ReportVerdict::Valid,
                            detail: "Chaîne vérifiée contre les anchors fournis".into(),
                        };
                    } else {
                        r.chain = Component {
                            status: ReportVerdict::Warning,
                            detail: "Aucun anchor fourni (--trust), chaîne non attestée".into(),
                        };
                    }
                    r.signer_dn = signer_dn;
                    r.certificate_chain = chain_dns;

                    r.revocation = Component {
                        status: ReportVerdict::Warning,
                        detail: "Non évaluée (offline par défaut)".into(),
                    };
                    r.ltv = Component {
                        status: ReportVerdict::Warning,
                        detail: "Non applicable (CMS détaché)".into(),
                    };
                }
                Err(e) => {
                    r.signature = Component {
                        status: ReportVerdict::Invalid,
                        detail: format!("Échec vérif PKCS#7: {e}"),
                    };
                    r.chain = Component {
                        status: ReportVerdict::Warning,
                        detail: "Chaîne non évaluée".into(),
                    };
                }
            }
        } else {
            r.signature = Component {
                status: ReportVerdict::Warning,
                detail: "P7M enveloppé non implémenté dans MVP".into(),
            };
        }
        final_verdict(&mut r);
        Ok(r)
    }

// --- Branche SANS OpenSSL -----------------------------------------------
#[cfg(not(feature = "openssl-backend"))]
{
    let _ = &sig_der; // éviter unused
    let _ = anchors_pem;

    r.signature = Component {
        status: ReportVerdict::Warning,
        detail: "Pile native CMS non activée : utilisez --features openssl-backend pour une vérification cryptographique complète.".into(),
    };
    r.chain = Component {
        status: ReportVerdict::Warning,
        detail: "Validation de chaîne limitée sans backend X.509 avancé.".into(),
    };
    r.revocation = Component {
        status: ReportVerdict::Warning,
        detail: "Révocation offline non évaluée (MVP). Fournir CRL/OCSP et activer backend ultérieurement.".into(),
    };
    r.ltv = Component {
        status: ReportVerdict::Warning,
        detail: "".into(),
    };

    final_verdict(&mut r);
    Ok(r)
}

}

fn extract_pem_block(pem: &str, _label: &str) -> Result<Vec<u8>> {
    let start = pem
        .find("-----BEGIN")
        .context("Bloc PEM BEGIN introuvable")?;
    let _end = pem.find("-----END").context("Bloc PEM END introuvable")?;
    let inner = &pem[start..]
        .lines()
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect::<Vec<_>>()
        .join("");
    let der = B64.decode(inner)?;
    Ok(der)
}
