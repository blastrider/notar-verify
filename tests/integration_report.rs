use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

#[test]
fn cli_shows_warning_without_backend() {
    let dir = tempdir().unwrap();
    let data = dir.path().join("data.bin");
    let sig = dir.path().join("detached.sig.p7s");
    fs::write(&data, b"hello world").unwrap();
    fs::write(&sig, b"not-a-real-p7s").unwrap();
    let out = dir.path().join("report.json");

    let mut cmd = Command::cargo_bin("notar-verify").unwrap();
    let assert = cmd
        .arg("--sig")
        .arg(sig)
        .arg("--data")
        .arg(data)
        .arg("--out")
        .arg(&out)
        .assert();

    // Ne pas exiger un exit code 0 : selon la build/features, le binaire peut retourner
    // 1/2 (Invalid/Warning) tout en ayant écrit le rapport JSON. Vérifions seulement
    // que le fichier a bien été créé avant de le lire.
    assert!(
        out.exists(),
        "Le rapport JSON attendu n'a pas été créé : {:?}",
        out
    );

    let json = fs::read_to_string(out).unwrap();
    insta::assert_snapshot!("report_warning", json);
}
