# Contributing to webgates

Thanks for your interest in contributing! This guide helps you get started and understand the quality gates.

## Quick start for contributors

1. **Clone and setup**:
   ```bash
   git clone https://github.com/emirror-de/webgates.git
   cd webgates
    nix develop  # or install Rust 1.91+ directly
   ```

 2. **Fast local validation** (recommended before pushing):
    ```bash
    # Format, lint, and test — this mirrors the fast CI path
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace
    ```

3. **Submit a PR**:
   - All PRs trigger the **fast-pr-check** job first (~3-5 minutes)
   - If that passes, feature matrix and other validation runs in parallel
   - Focus on making the fast check pass to get quick feedback

## CI workflow and quality gates

Our CI is designed with a **fast feedback loop** for contributors while maintaining thorough validation:

### Fast PR validation (`fast-pr-check`)
- **Purpose**: Quick feedback on every PR (~3-5 minutes)
- **What it checks**: Format, workspace clippy, workspace tests
- **When it runs**: Every push to PR branches
- **Why first**: Catches 90% of common issues quickly

### Feature matrix (`feature-matrix`)
- **Purpose**: Ensures all feature combinations work correctly
- **What it checks**: Individual crate features and minimal combinations
- **When it runs**: After fast-pr-check passes
- **Why important**: Prevents feature-gating regressions

### Documentation tests (`doc-tests`)
- **Purpose**: Validates all code examples in documentation
- **What it checks**: `cargo test --workspace --doc`
- **When it runs**: In parallel with feature matrix
- **Why important**: Ensures examples stay up-to-date

### MSRV check (`msrv`)
- **Purpose**: Verifies support for minimum supported Rust version
- **What it checks**: Compilation on Rust 1.91
- **When it runs**: In parallel with other validation
- **Why important**: Maintains backward compatibility promise

### Security audit (`security`)
- **Purpose**: Checks for known vulnerabilities and license issues
- **What it checks**: `cargo audit` and `cargo deny`
- **When it runs**: After core validation completes
- **Why important**: Maintains supply chain security

### Examples validation (`examples`)
- **Purpose**: Ensures example code compiles and runs
- **What it checks**: All example packages in the workspace
- **When it runs**: After feature matrix validation
- **Why important**: Validates real-world usage patterns

### Extended quality checks (`extended-checks`)
- **Purpose**: Advanced quality gates for releases
- **What it checks**: Semver compatibility, test coverage
- **When it runs**: Only on `nightly` and `version/*` branches
- **Why conditional**: Expensive checks not needed for every PR

## Development guidelines

- Run the full test suite locally: `cargo test --workspace`.
- Use stable Rust matching the project's MSRV (1.91).
- Keep changes small and focused; prefer clear commit messages describing the why.
- If your change adds public API, include or update docs and examples.
- For CI checks, ensure `cargo fmt` and `cargo clippy` pass locally where applicable.
- Run `python3 scripts/check_feature_contract.py --check-only` after any feature flag changes to confirm FEATURE_MATRIX.md stays aligned.

## Creating pull requests

- Branch from main and open a Pull Request with a short title and a concise description.
- Link related issues and explain any breaking changes.
- Add tests for bug fixes and new features when practical.

## Feature development

When adding or changing features:

1. **Update `Cargo.toml`** feature definitions
2. **Add tests** for the new functionality
3. **Update documentation** including README files
4. **Test minimal feature combinations** to avoid breaking feature-gating
5. **Run the validation commands** listed above

## Common issues and fixes

- **Format errors**: Run `cargo fmt --all`
- **Clippy errors**: Run `cargo clippy --workspace --all-targets -- -D warnings`
- **Test failures**: Run `cargo test --workspace` and fix failing tests
- **Feature gating issues**: Test minimal combinations like `cargo test -p webgates --no-default-features --features codecs`; refer to `FEATURE_MATRIX.md` for all supported combinations.
- **MSRV issues**: Avoid language features newer than Rust 1.91

If you have questions or need help picking tasks, open an issue and tag it `good first issue` or `help wanted`. For common setup and build issues, see `TROUBLESHOOTING.md`.

**License**: contributions are accepted under the repository's MIT license unless otherwise noted.
