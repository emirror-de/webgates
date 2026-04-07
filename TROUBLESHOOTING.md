Troubleshooting

Common issues and quick resolutions when working with this workspace.

- Build failures due to feature flags: crates ship without default features. If a crate fails to build, enable the features you need in your local Cargo.toml or workspace settings.
- Documentation out of date: run `cargo doc --workspace --no-deps` to regenerate docs locally.
- SurrealDB / SeaORM feature issues: these are optional. If you don't need a backend, avoid enabling `repo-surrealdb` or `repo-seaorm` features.
- Tests depending on external services: some examples or integration tests may expect a running DB. Check the test file doc comments for setup instructions.

If you can't resolve an issue, open an issue with steps to reproduce, Rust version, and output of `cargo test`.
