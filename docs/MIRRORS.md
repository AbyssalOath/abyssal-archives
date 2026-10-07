# Mirrors

Mirrors are copies of a file hosted elsewhere: Archive.org, GitHub Releases,
or another server. They take bandwidth off this server and give visitors a
fallback. Everything here is **admin-curated and manual**: this app never
uploads anywhere, never stores Archive.org or GitHub credentials, and makes
no network request except an explicit **Verify** click.

## How mirrors work in the app

- Each file has any number of mirrors (`file_mirrors` table), managed from
  the release's **Files** page → **Mirrors (n)** on the file row.
- **Kinds**
  - `http`: a direct download of the same file (`http://` or `https://`).
  - `torrent`: an `http(s)` link to a `.torrent` file, or a `magnet:` link,
    hosted elsewhere (e.g. Archive.org's item torrent).
- **Statuses**: `pending`, `approved`, `rejected`, `failed`. Mirrors you add
  are **approved immediately**. Mirrors from future discovery/federation
  always start `pending` and never show publicly until you approve them.
- **Public display**: only when **Show approved mirrors** is on in
  /admin/settings (`EXTERNAL_MIRRORS_ENABLED`, off by default), and only
  approved mirrors of ready files: "Mirror (label)" and "Torrent (label)".
  They are plain links with `rel="noopener noreferrer nofollow"`; the site
  never proxies or redirects to them. Turning the toggle off hides them
  without deleting anything.
- **Quick add** builds URLs from an Archive.org item identifier or a GitHub
  owner/repo/tag/asset. Pure string templating, no network call, shown to you
  for confirmation before anything is saved.
- **Verify** (http mirrors only) downloads the mirror once in the background,
  hashes it (SHA-256, one pass) and compares size and hash with ours. A match
  records the check time; a mismatch or error marks the mirror `failed` (hidden
  publicly) with the reason. Verify never runs automatically. Torrent mirrors
  cannot be verified and are labelled "unverified" in the admin.

### Verify safety (SSRF protection)

Verify fetches a URL an admin typed, so it is locked down:

- only `http`/`https`, only ports 80 and 443, no credentials in the URL;
- host names are resolved first and refused if **any** address is loopback,
  private (RFC 1918), link-local (incl. 169.254.169.254), CGNAT
  (100.64.0.0/10), unique-local / link-local IPv6, multicast, or another
  reserved range (also IPv4 embedded in IPv6 forms). The connection uses
  exactly the checked addresses, so DNS rebinding cannot sneak in;
- IP-literal URLs are checked directly;
- redirects are followed by hand, at most 3, each one re-checked;
- proxy environment variables are ignored;
- the download is capped at the recorded size + 64 KiB, with a 10 s connect
  timeout, a 30 s stall timeout and an overall time limit.

## Workflow: Archive.org (recommended, also gives you a torrent)

Upload each release as **one Archive.org item**, from **your own machine**
(never from the server or the container), with the `ia` command-line tool:

```bash
pip install internetarchive        # provides the `ia` command
ia configure                       # stores YOUR Archive.org keys on YOUR machine

ia upload my-distro-2.0 my-distro-2.0.iso my-distro-2.0-arm64.iso \
  --metadata="mediatype:software" \
  --metadata="title:My Distro 2.0" \
  --metadata="licenseurl:https://www.gnu.org/licenses/gpl-3.0.html"
```

- Choose the identifier carefully (letters, digits, `.`, `_`, `-`); it is
  permanent, and so is `mediatype` (set it at upload time).
- Archive.org generates a torrent for the whole item,
  `https://archive.org/download/<identifier>/<identifier>_archive.torrent`,
  with Archive.org itself as a web seed. Wait until the item has finished
  processing and check that this file appears in the item's file list.
- Then, for each file on this site: **Mirrors → Quick add → Archive.org item**,
  enter the identifier (and the file name if it differs), confirm the direct
  `http` URL and/or the item `torrent` URL, and optionally click **Verify** on
  the http one.

## Workflow: GitHub Releases

- Each release asset must be **under 2 GiB** (GitHub's per-file limit), so
  most ISOs do not fit. GitHub does **not** generate torrents.
- Upload assets with the GitHub web UI or `gh release upload <tag> <files>`
  from your own machine.
- On this site: **Mirrors → Quick add → GitHub release asset** (owner, repo,
  tag, asset name), confirm, then **Verify**.

## Other servers

Add the direct URL with **Add a mirror** (kind `http`) and **Verify** it.
For a torrent or magnet link published by someone else, add it as kind
`torrent`. It cannot be verified, so only add links from sources you trust.

## Credentials

This app never stores Archive.org or GitHub credentials, and nothing in the
container talks to those services. If upload automation is ever added, see
"Stored credentials" in docs/FUTURE.md for how it must be done.
