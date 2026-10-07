**What this changes and why**

**Checklist**

- [ ] `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test` pass
- [ ] Database tests pass (`TEST_DATABASE_URL=... cargo test`) if routes, queries or migrations changed
- [ ] New schema changes are a new file in `migrations/` (no applied migration edited)
- [ ] Docs updated (README, `docs/`, `.env.example`) for user-visible changes
- [ ] No JavaScript, no hardcoded site name, no new outbound requests

By submitting this pull request, I agree that my contribution is licensed
under the GNU AGPL, version 3 or later.
