# Verifying downloads

Every release publishes `SHA256SUMS` and `SHA512SUMS`. When the operator
signs them, there is also `SHA256SUMS.asc` and the signing key at `/gpg.pub`.
Check in this order: **signature first, then checksums**, then cross-check.

## 1. Get the files

Every file has a stable address, `https://<site>/p/<project>/<version>/<path>`,
shown on the release page (`/p/<project>/<version>`). Paths keep their
folders (`sources/a.tar.gz`), and so does `SHA256SUMS`, so download into a
folder that mirrors the release:

```bash
mkdir -p sanctum && cd sanctum
curl -fLO https://<site>/p/<project>/<version>/<file>.iso
curl -fLO https://<site>/p/<project>/<version>/SHA256SUMS
curl -fLO https://<site>/p/<project>/<version>/SHA256SUMS.asc
curl -fL  https://<site>/gpg.pub -o signing-key.asc
# a file in a folder keeps its folder:
curl -fL --create-dirs -o sources/a.tar.gz https://<site>/p/<project>/<version>/sources/a.tar.gz
```

Downloads resume (`curl -C - -O ...`, `wget -c ...`). The newest release's
recommended file is always at `https://<site>/p/<project>/latest/download`
(one redirect to its versioned address: use `curl -fLOJ` or
`wget --content-disposition` to keep its real name).

To fetch a whole release, or check an upload from a script, use the
machine-readable list `https://<site>/p/<project>/<version>/files.json`
(below).

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

Run it from the folder you downloaded into (the release's root): entries
look like `<hash>  sources/a.tar.gz`. Each downloaded file must report
`OK`. (`--ignore-missing` skips release files you did not download.) A
folder may also carry its own checksum file from the project, e.g.
`sources/SHA256SUMS`; check that one from inside `sources/`.

### files.json

`/p/<project>/<version>/files.json` lists every file with its path, size,
SHA-256, SHA-512 and absolute URL (from `PUBLIC_URL` or `DOWNLOAD_BASE_URL`):

```json
{
  "project": "abyssal-sanctum",
  "version": "v0.1.0",
  "released_at": "2026-10-07",
  "recommended": "abyssal-sanctum-v0.1.0-secureboot.iso",
  "files": [
    { "path": "sources/a.tar.gz", "size": 12345, "sha256": "...", "sha512": "...",
      "url": "https://<site>/p/abyssal-sanctum/v0.1.0/sources/a.tar.gz" }
  ]
}
```

Fetch a whole release and verify it:

```bash
curl -fsS https://<site>/p/<project>/<version>/files.json |
  jq -r '.files[] | "\(.url) \(.path)"' |
  while read -r url path; do curl -fsSL --create-dirs -C - -o "$path" "$url"; done
curl -fsSLO https://<site>/p/<project>/<version>/SHA256SUMS && sha256sum -c SHA256SUMS
```

## 4. Cross-check with a second source

Compare the SHA-256 of what you downloaded with the checksum published in
the project's code repository (for example its README or release notes on
GitHub). Two independent places agreeing makes a quietly swapped file on
one of them very unlikely to go unnoticed.

---

## For the operator: checking an upload

After importing, compare the server's list with your local build tree
(run from the release's root folder on your machine):

```bash
curl -fsS https://<site>/p/<project>/<version>/files.json |
  jq -r '.files[] | "\(.sha256)  \(.path)"' | sha256sum -c --quiet && echo "upload matches"
```

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
