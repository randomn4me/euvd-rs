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

## PR Requirements

PRs are checked automatically by CI. Your PR will be rejected if:

- **No issue reference** — the PR body must contain `Closes #<number>` (or `Fixes`, `Resolves`).
- **Not rebased on main** — merge commits are not allowed. Rebase your branch on `main`.
- **Not squashed** — squash your commits into a single commit before submitting.

```bash
# Rebase and squash onto main
git fetch origin
git rebase -i origin/main
# Mark all commits except the first as "squash", then force-push your branch
git push --force-with-lease
```

## Local Setup

Install the pre-commit hook to mirror CI checks locally:

```bash
cp scripts/pre-commit .git/hooks/pre-commit
```

This runs `cargo fmt --check`, `cargo clippy --all-targets`, `cargo test`, and `cargo doc` before each commit.

## Code Guidelines

- Follow existing code conventions and patterns.
- Use [conventional commit](https://www.conventionalcommits.org/) style for your commit message.
- Keep dependencies minimal.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
