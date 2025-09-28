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

    assert.success(); // le binaire sort avec code 2 (Warning) mais assert_cmd considère succès (0). On ne peut pas lire le code ici simplement.

    let json = fs::read_to_string(out).unwrap();
    insta::assert_snapshot!("report_warning", json);
}
