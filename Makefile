default: fmt lint test build

fmt:
	cargo fmt --all

lint:
	cargo clippy --all-features -- -D warnings

test:
	cargo test --all --locked

build:
	cargo build --release

run-pdf:
	cargo run -- --in examples/signed.pdf --trust examples/trust.pem --out report.json

run-cms:
	cargo run -- --sig examples/detached.sig.p7s --data examples/data.bin --trust examples/trust.pem --out report.json

run-online:
	cargo run --features online -- --in examples/signed.pdf --trust examples/trust.pem --online --out report.json
