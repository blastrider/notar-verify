#![forbid(unsafe_code)]

mod cms;
mod infra;
mod pdf;
mod report;
mod revocation;
mod x509;

use anyhow::{Context, Result};
use clap::{ArgAction, Parser};
use report::{ExitCode, ReportVerdict};
use tracing::{debug, info};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser, Debug)]
#[command(
    name = "notar-verify",
    version,
    about = "Vérifie l’intégrité & signatures (PDF PAdES, CMS/P7S). Offline par défaut."
)]
struct Cli {
    /// PDF signé (PAdES)
    #[arg(long, value_name = "FILE", conflicts_with = "sig")]
    r#in: Option<String>,

    /// Signature CMS/P7S (détachée) ou P7M (enveloppée)
    #[arg(long, value_name = "FILE", conflicts_with = "in")]
    sig: Option<String>,

    /// Données signées pour P7S détachée
    #[arg(long, value_name = "FILE", requires = "sig")]
    data: Option<String>,

    /// Fichier(s) PEM d’ancrage de confiance (CA/anchors). Obligatoire pour un verdict VALID.
    #[arg(long = "trust", value_name = "PEM", num_args = 1.., action = ArgAction::Append)]
    trust: Vec<String>,

    /// Fichiers CRL hors-ligne (optionnels)
    #[arg(long, value_name = "CRL", num_args = 0.., action = ArgAction::Append)]
    crl: Vec<String>,

    /// Fichiers OCSP hors-ligne (optionnels)
    #[arg(long, value_name = "OCSP", num_args = 0.., action = ArgAction::Append)]
    ocsp: Vec<String>,

    /// Export JSON du rapport
    #[arg(long, value_name = "FILE")]
    out: Option<String>,

    /// Activer les requêtes réseau (OCSP/CRL). Désactivé par défaut.
    #[arg(long, action = ArgAction::SetTrue)]
    online: bool,

    /// Niveau de log (ex: info,debug,trace). Par défaut lu via RUST_LOG.
    #[arg(long, value_name = "LEVEL")]
    log_level: Option<String>,

    /// Taille max des fichiers en MiB (défense DoS)
    #[arg(long, default_value_t = 50)]
    max_mib: u64,
}

fn init_tracing(level: Option<String>) {
    let env = if let Some(lvl) = level {
        EnvFilter::new(lvl)
    } else {
        EnvFilter::from_default_env()
    };
    fmt().with_env_filter(env).without_time().init();
}

fn main() -> Result<()> {
    init_tracing(Cli::parse().log_level);
    let cli = Cli::parse();

    info!("notar-verify démarré (offline par défaut)");
    debug!(?cli);

    let limits = infra::fs::Limits::from_mib(cli.max_mib);

    // Charger anchors (si fournis)
    let anchors = infra::fs::read_all_pems(&cli.trust, &limits)
        .context("Échec lecture des anchors (--trust)")?;

    // Dispatcher selon mode
    let report = if let Some(pdf_path) = cli.r#in.as_deref() {
        pdf::pades::verify_pdf_pades(pdf_path, &anchors, &cli.crl, &cli.ocsp, cli.online, &limits)
            .context("Vérification PAdES a échoué")?
    } else if let Some(sig_path) = cli.sig.as_deref() {
        cms::verify::verify_cms_entrypoint(
            sig_path,
            cli.data.as_deref(),
            &anchors,
            &cli.crl,
            &cli.ocsp,
            cli.online,
            &limits,
        )
        .context("Vérification CMS a échoué")?
    } else {
        anyhow::bail!(
            "Spécifiez --in <pdf> ou --sig <p7s|p7m> (avec --data si détachée). Voir --help."
        );
    };

    // Rendu terminal
    report::print_table(&report);

    // Export JSON
    if let Some(out) = cli.out.as_deref() {
        report::write_json(&report, out).context("Écriture JSON --out a échoué")?;
        info!("Rapport JSON écrit dans {}", out);
    }

    // Codes de sortie
    std::process::exit(match report.verdict {
        ReportVerdict::Valid => ExitCode::VALID as i32,
        ReportVerdict::Invalid => ExitCode::INVALID as i32,
        ReportVerdict::Warning => ExitCode::WARNING as i32,
    });
}
