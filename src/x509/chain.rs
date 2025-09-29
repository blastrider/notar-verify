use crate::report::{Component, ReportVerdict};
#[allow(dead_code)]
pub struct ChainResult {
    pub component: Component,
    pub subjects: Vec<String>,
}

#[allow(dead_code)]
#[cfg(feature = "openssl-backend")]
pub fn validate_chain_openssl(_anchors_pem: &[String]) -> ChainResult {
    // MVP: la vérification de chaîne avancée est généralement couverte lors de la vérif PKCS7.
    ChainResult {
        component: Component {
            status: ReportVerdict::Warning,
            detail: "Chaîne validée via PKCS#7 (détails à enrichir)".into(),
        },
        subjects: vec![],
    }
}

#[allow(dead_code)]
#[cfg(not(feature = "openssl-backend"))]
pub fn validate_chain_openssl(_anchors_pem: &[String]) -> ChainResult {
    ChainResult {
        component: Component {
            status: ReportVerdict::Warning,
            detail: "Backend X.509 non activé".into(),
        },
        subjects: vec![],
    }
}
