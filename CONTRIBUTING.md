# Contributing to Qbitel EdgeOS

Thanks for your interest in contributing! This guide will get you up and running.

## Getting Started

```bash
git clone https://github.com/YOUR_USERNAME/qbitel-edgeos.git
cd qbitel-edgeos

rustup target add thumbv7em-none-eabihf thumbv8m.main-none-eabihf riscv32imac-unknown-none-elf

# Build and test
cargo test --workspace --all-features

# Install pre-commit hooks
pip install pre-commit && pre-commit install
```

## Workflow

1. **Fork** the repo and create a branch from `main`
2. **Write code** that follows the conventions below
3. **Add tests** for any new functionality
4. **Run checks** before submitting:
   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace --all-features -- -D warnings
   cargo test --workspace --all-features
   ```
5. **Sign commits** with DCO: `git commit -s`
6. **Open a PR** against `main`

## Code Conventions

### Rust

- `no_std` required &mdash; all crates must compile without the standard library
- No `.unwrap()` in production code &mdash; use `Result` with proper error handling
- `unsafe` must have a `// SAFETY:` comment explaining soundness
- Secrets must use `#[derive(Zeroize, ZeroizeOnDrop)]`
- Secret comparisons must use the `subtle` crate (constant-time)
- Gate platform code behind feature flags (`stm32h7`, `stm32u5`, `riscv`)

### Python (Tools)

- Formatter: `black` &mdash; Linter: `ruff` &mdash; Types: `mypy --strict`
- CLI framework: `click` &mdash; Validation: `pydantic`

### Commits

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(crypto): add ML-KEM-1024 parameter set
fix(boot): prevent overflow in version comparison
test(mesh): add handshake timeout test
```

**Types:** `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `ci`, `chore`
**Scopes:** `crypto`, `kernel`, `boot`, `hal`, `identity`, `attest`, `update`, `recover`, `mesh`, `common`, `tools`, `ci`

## Reporting Bugs

1. Check existing [issues](https://github.com/yazhsab/qbitel-edgeos/issues)
2. Include: target platform, Rust toolchain version, steps to reproduce, expected vs. actual behavior

## Security Vulnerabilities

**Do not open public issues.** See [SECURITY.md](SECURITY.md).

## Review Process

- All PRs require at least one maintainer approval
- CI must pass (format, lint, test, audit)
- Significant changes (new crates, architecture) &mdash; open an issue first

## License

By contributing, you agree that your contributions will be licensed under [Apache License 2.0](LICENSE).
