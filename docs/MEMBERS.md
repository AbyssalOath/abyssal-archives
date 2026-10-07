# Member accounts

The first account (created at `/setup`) is the **administrator**. Every
other account is a **member**: someone who can share their own files on the
site. Members never see or touch anything that is not theirs, and by default
nothing they make is public until the administrator has looked at it.

## Getting an account

There are two ways, both in the admin's hands:

1. **The admin creates it**: Admin → Users → "Create a member account"
   (username + password; active immediately). Tell the person the username
   and password yourself; they can change the password under Account.
2. **The person requests it** at `/register`, only while Admin → Settings →
   Member accounts → "Allow account requests" is on (off by default; the
   `ALLOW_REGISTRATION` value in `.env` only sets it on the very first
   start). The request stays **pending** until the admin approves or rejects
   it under Admin → Users.

While account requests are off, `/register` (and `/setup`, once the admin
exists) shows **"Requests to join are suspended"** with the contact e-mail
from Settings ("Contact e-mail for access requests"), or "contact the site
administrator" when none is set.

There is **no e-mail** anywhere, by design (nothing leaves the server; see
docs/PRIVACY.md). An applicant finds out by signing in:

| Account state | Signing in with the right password says |
|---|---|
| pending | "Your account is awaiting approval by an administrator." |
| disabled | "This account has been disabled. Contact the site administrator." |
| active | signs in (to `/my`) |

A wrong password always gets the same "Invalid username or password", so
the state is only revealed to someone who knows the password. Usernames are
unique, ignoring case (`Alice` and `alice` are the same name). There is no
"forgot password" link: the admin sets a new password under Users.

Account requests are limited per client address (a few, then an increasing
wait) and stop while 100 requests are waiting for review.

## What members can do

The member area is `/my` (header: My projects, Limits, Account, 2FA):

- create projects, releases and files, and edit or delete **their own**
  (anything else answers 404, as if it did not exist);
- upload files from the browser (when `ALLOW_WEB_UPLOAD=true`), within their
  limits (below);
- download their own files, published or not, from the files page;
- change their password and (with `TOTP_ENABLED=true`) set up 2FA.

Members cannot import from the incoming folder, see storage paths, manage
mirrors or signatures, recompute hashes, change settings, or open any
`/admin` page (403).

## Review before publishing (on by default)

Settings → Member accounts → "Review member uploads before they are
published". While on:

- a member's new project or release starts **awaiting review** and is not
  public (home page, project page, downloads, checksums and SHA256SUMS all
  answer 404);
- a member's edit of a project or release, and every upload into a release,
  sends it back to **awaiting review** (off the public site until approved
  again). Deleting files does not;
- Admin → Review lists everything waiting. "Check and decide" opens the
  project or release; the admin can download the files there (not counted
  as downloads), then **Publish** or **Do not publish** with an optional
  note the member sees.

A release is public only when **both** it and its project are published.
The admin can also unpublish anything at any time from the same Review box
on the project edit page and the release files page, and the admin's own
edits never change a review state.

While off, members publish directly; an admin's "Do not publish" still
stands through the member's later edits until the admin publishes it.

## Limits and quota

Settings → Member accounts:

- **Member upload limit per file** (default 100M), never more than
  `MAX_UPLOAD_BYTES` (the hard cap for every browser upload);
- **Member storage quota** (default 1G): all of a member's files together.

The admin can set different values for one member under Users → Manage.
Members see their limits and usage on `/my/limits` and can **ask for more**
there: the size(s) they need and why. One request at a time. The admin
approves (and may grant different values than asked) or denies, with an
optional note; the member sees the outcome on the same page.

Limits are enforced while the bytes arrive: an upload that goes over is
stopped and nothing of it is stored. (Two uploads running at the same time
can overshoot the quota by at most one file.)

## Managing members (Admin → Users)

Per member: approve / reject (pending requests; a rejected request is
deleted), disable / enable (disabling ends their sessions at once), set
limits, set a new password (ends their sessions), turn off their 2FA, and
delete the account **with all its projects and files**. None of these apply
to the administrator account.

## Security notes

- `/login` is open to everyone so members can sign in; `ADMIN_HOST` and
  `ADMIN_ALLOWED_CIDRS` protect the administrator instead (the `/admin`
  pages, `/setup`, the admin's sign-in and session). See docs/HARDENING.md.
- Every workspace request checks ownership on the server; member content
  goes through the same Markdown sanitizing, filename sanitizing and
  download headers (`attachment`, `nosniff`, strict CSP) as the admin's.
- Sessions of pending or disabled accounts are never valid.
