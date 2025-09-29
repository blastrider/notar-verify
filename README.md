# notar-verify

**CLI Rust** pour vérifier l’intégrité et la validité des signatures numériques (PDF PAdES, CMS/P7S). Produit un résumé lisible dans le terminal et un rapport JSON structuré pour archivage ou intégration CI.

---

## Fonctionnalités

* Vérification d’intégrité (ByteRange / SHA-256) pour PDF signés (PAdES).
* Vérification des signatures PKCS#7 détachées (P7S).
* Export JSON du rapport (`--out`).
* Support d’ancrages de confiance via fichiers PEM (`--trust`).
* Option réseau (`--online`) pour activer OCSP/CRL (fonctionnalité à activer lors de la compilation).
* Protection anti-DoS : limite de taille fichier configurable (`--max-mib`).
* `#![forbid(unsafe_code)]` dans le code.

---

## Limitations (MVP)

* Vérification X.509 complète et extraction détaillée de la chaîne disponibles **si compilé** avec la feature `openssl-backend`.
* Évaluation de révocation / LTV partielle en version de base.
* P7M (enveloppé) partiellement supporté / cas non complet.

---

## Installation (Linux / macOS)

Pré-requis pour la feature OpenSSL :

```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install -y pkg-config libssl-dev

# Fedora/RHEL
sudo dnf install -y pkgconfig openssl-devel
```

Compiler :

```bash
# build standard (offline)
cargo build --release

# build avec backend OpenSSL
cargo build --release --features openssl-backend

# build avec OpenSSL + network (OCSP/CRL)
cargo build --release --features "openssl-backend online"
```

Le binaire se trouve dans `target/release/notar-verify`.

---

## Utilisation (exemples)

Vérifier un PDF signé et écrire le rapport JSON :

```bash
notar-verify --in contrat_sig.pdf --trust ca_root.pem --out rapport.json
```

Vérifier une signature détachée :

```bash
notar-verify --sig signature.p7s --data fichier.bin --trust ca_root.pem
```

Activer les requêtes réseau (nécessite build avec `online`) :

```bash
notar-verify --in doc.pdf --trust ca_root.pem --online
```

Options utiles : `--max-mib <N>`, `--log-level <info|debug|trace>`.

---

## Codes de sortie (pour scripts / CI)

* `0` → VALID
* `1` → INVALID
* `2` → WARNING

---

## Format du rapport JSON (champ-clés principaux)

Le JSON export contient, entre autres :

* `input_kind` : `"PDF"` ou `"CMS"`
* `integrity`, `signature`, `chain`, `revocation`, `ltv` : objets `{ status, detail }`
* `verdict` : `VALID` / `INVALID` / `WARNING`
* `document_sha256` : empreinte SHA-256 du document

---

## Sécurité & bonnes pratiques

* Fournissez des **anchors PEM** via `--trust` pour obtenir un verdict fiable.
* Compilez avec `openssl-backend` pour vérification cryptographique complète.
* Ne poussez pas les clés/secrets dans le repo. Si vous supprimez des fichiers sensibles, suivez une procédure d’invalidation/révocation.

---

## Tests

Exemples de tests d’intégration et snapshots fournis dans `tests/`.
Lancer :

```bash
cargo test
```

---

## Contribution

PRs bienvenues. Respectez les contraintes : pas de `unsafe`, tests et snapshots pour modifications fonctionnelles.

---

## Licence

MIT OR Apache-2.0