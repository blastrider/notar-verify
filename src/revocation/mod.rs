use crate::report::{Component, ReportVerdict};

pub fn evaluate_revocation_offline(_crl: &[String], _ocsp: &[String]) -> Component {
    // MVP: prise en compte future (CRL/OCSP fournis en fichiers)
    Component {
        status: ReportVerdict::Warning,
        detail: "Révocation offline non évaluée (MVP). Fournir CRL/OCSP et activer backend ultérieurement.".into(),
    }
}

pub async fn evaluate_revocation_online(_urls: &[String]) -> Component {
    // MVP online: placeholder, appels HTTP à implémenter avec timeouts
    Component {
        status: ReportVerdict::Warning,
        detail: "Révocation online non implémentée dans MVP.".into(),
    }
}
