# Verifying downloads

Every release publishes `SHA256SUMS` and `SHA512SUMS`. When the operator
signs them, there is also `SHA256SUMS.asc` and the signing key at `/gpg.pub`.
Check in this order: **signature first, then checksums**, then cross-check.

## 1. Get the files

From the release on the project page (`/p/<project>`):

```bash
curl -fLOJ https://<site>/download/<id>            # -J keeps the real filename
curl -fLO  https://<site>/p/<project>/<version>/SHA256SUMS
curl -fLO  https://<site>/p/<project>/<version>/SHA256SUMS.asc
curl -fL   https://<site>/gpg.pub -o signing-key.asc
```

## 2. Verify the signature

```bash
gpg --import signing-key.asc
gpg --fingerprint                     # compare with a fingerprint you trust (below)
gpg --verify SHA256SUMS.asc SHA256SUMS
```

You want `Good signature from ...` **and** a key fingerprint you have
confirmed through a second channel: the project's code repository README,
a release announcement, a keyserver you trust, or in person. A good
signature from a key you have not confirmed only proves that whoever runs
the server signed it.

## 3. Verify the checksums

```bash
sha256sum -c --ignore-missing SHA256SUMS
# or
sha512sum -c --ignore-missing SHA512SUMS
```

Each downloaded file must report `OK`. (`--ignore-missing` skips release
files you did not download.)

## 4. Cross-check with a second source

Compare the SHA-256 of what you downloaded with the checksum published in
the project's code repository (for example its README or release notes on
GitHub). Two independent places agreeing makes a quietly swapped file on
one of them very unlikely to go unnoticed.

---

## For the operator: signing a release

The private key never touches the server. On your own machine:

```bash
# once: create a dedicated signing key and publish its public half
gpg --quick-generate-key "Releases <releases@example.org>" ed25519 sign 2y
gpg --armor --export releases@example.org        # paste into /admin/settings -> /gpg.pub
gpg --fingerprint releases@example.org           # publish this in your code repository README

# per release, after all files are imported (SIGN_CHECKSUMS=true in .env)
curl -fsSO https://<site>/p/<project>/<version>/SHA256SUMS
gpg --armor --detach-sign --local-user releases@example.org --output SHA256SUMS.asc SHA256SUMS
cat SHA256SUMS.asc                                # paste on the release's Files page
```

The site only serves the signature while it matches the release's current
SHA256SUMS: adding, removing or recomputing a file makes it stale (shown on
the admin Files page) until you re-sign.
