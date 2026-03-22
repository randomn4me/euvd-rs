# Contributing to euvd-rs

Thanks for your interest in contributing! This project welcomes bug reports, new API endpoint implementations, and missing feature additions.

## Workflow

1. **Open an issue** — describe the bug, missing endpoint, or feature you'd like to work on.
2. **Discuss** — wait for feedback before starting work. This avoids wasted effort on changes that may need a different approach or aren't a good fit.
3. **Submit a PR** — once the approach is agreed upon, open a pull request.

## Bug Reports

- Include reproduction steps, expected behavior, and actual behavior.
- Include the Rust version (`rustc --version`) and crate version.
- If possible, include a minimal code snippet that triggers the bug.

## New API Endpoints

The EUVD API may expose endpoints not yet covered by this crate. If you discover one:

1. Open an issue with the endpoint URL, a sample response, and a description of what it returns.
2. In your PR, add:
   - The client method in `src/client.rs`
   - Any new model types in `src/models.rs`
   - A test fixture captured from the real API in `tests/fixtures/`
   - Tests using `mockito` in `tests/client_tests.rs`

## Missing Features

For features like pagination, retry logic, or new builder options:

1. Open an issue explaining the use case.
2. Keep the scope small — one feature per PR.

## Code Guidelines

- Run `cargo fmt`, `cargo clippy -- -D warnings`, and `cargo test` before submitting.
- Follow existing code conventions and patterns.
- One logical change per commit, using [conventional commit](https://www.conventionalcommits.org/) style.
- Keep dependencies minimal.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
