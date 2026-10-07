# Contributing

Thanks for your interest! This is a small project; keep changes small, readable
and focused.

## Before opening a pull request

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test
# with a throwaway MariaDB (the test wipes it):
TEST_DATABASE_URL=mysql://root:<pw>@127.0.0.1:<port>/filehost_test cargo test
```

CI runs the same checks plus a real-browser flow (headless Chromium),
shellcheck, `cargo audit`, `cargo deny`, gitleaks, an SBOM and a Docker build
with a Trivy scan.

## Ground rules

- **No JavaScript.** Interactivity is HTML forms and server rendering; animation
  is CSS. CI rejects `<script>` tags and `.js` files.
- **No hardcoded site name or branding.** Everything visible comes from settings.
- **Runtime-checked SQL** (`sqlx::query`/`query_as`), never the `query!` macros.
- **Never buffer whole files in memory**; stream uploads, imports and downloads.
- Schema changes go in a new file in `migrations/` (never edit an applied one).
- Comment the *why*, keep modules small.
- Security-relevant changes: add a test, and a row in docs/SECURITY-REVIEW.md.

## License of contributions

This project is licensed under the GNU AGPL, version 3 or later
([LICENSE](LICENSE)). By submitting a contribution you agree that it is
licensed under the same terms.
