"""Real-browser smoke test (headless Chromium via Playwright).

Unit and HTTP tests set request headers themselves; only a real browser shows
what it actually sends (e.g. `Origin: null` under `Referrer-Policy:
no-referrer`, which once made every form fail with 403). Covers setup,
sign-out, sign-in, an admin form, the footer Login link, and a member's
account request, approval, sign-in and first project. Exits non-zero on
failure.

  python3 tests/browser/flow.py http://localhost:8080    # against a FRESH site
"""

import sys

from playwright.sync_api import sync_playwright

BASE = sys.argv[1].rstrip("/")
PW = "correct horse battery"


def expect(cond, msg):
    if not cond:
        print("FAIL:", msg)
        sys.exit(1)
    print("ok:", msg)


with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()
    posts = {}
    page.on("request", lambda r: posts.update({r.url: r.headers}) if r.method == "POST" else None)

    page.goto(BASE + "/setup")
    page.fill("#username", "admin")
    page.fill("#password", PW)
    page.fill("#password_confirm", PW)
    page.click("button[type=submit]")
    page.wait_for_load_state()
    origin = posts.get(BASE + "/setup", {}).get("origin")
    expect(origin == BASE, f"setup form sent Origin {origin!r}")
    expect(page.url == BASE + "/admin", f"setup lands on /admin (got {page.url})")

    page.click("text=Sign out")
    page.wait_for_load_state()
    page.goto(BASE + "/login")
    page.fill("#username", "admin")
    page.fill("#password", PW)
    page.click("button[type=submit]")
    page.wait_for_load_state()
    expect(page.url == BASE + "/admin", f"login lands on /admin (got {page.url})")

    page.goto(BASE + "/admin/projects")
    page.fill("#name", "Browser Project")
    page.click("text=Create project")
    page.wait_for_load_state()
    expect("/admin/projects/" in page.url, f"admin form accepted (got {page.url})")

    page.goto(BASE + "/p/browser-project")
    expect(page.title().startswith("Browser Project"), "public page renders")

    # Open account requests (Settings), as the admin.
    page.goto(BASE + "/admin/settings")
    page.check("input[name=registration_open]")
    page.click("text=Save settings")
    page.wait_for_load_state()
    expect(page.is_visible("text=Settings saved."), "settings saved")

    # A visitor follows the footer link and requests an account.
    member = browser.new_context().new_page()
    member.on("request", lambda r: posts.update({r.url: r.headers}) if r.method == "POST" else None)
    member.goto(BASE + "/")
    member.click("footer >> text=Login")
    member.wait_for_load_state()
    expect(member.url == BASE + "/login", f"footer Login link (got {member.url})")
    member.click("text=Request access")
    member.wait_for_load_state()
    member.fill("#username", "member1")
    member.fill("#password", PW)
    member.fill("#password_confirm", PW)
    member.fill("#note", "hello from the browser test")
    member.click("text=Send request")
    member.wait_for_load_state()
    origin = posts.get(BASE + "/register", {}).get("origin")
    expect(origin == BASE, f"register form sent Origin {origin!r}")
    expect(member.is_visible("text=Request received"), "account requested")

    member.goto(BASE + "/login")
    member.fill("#username", "member1")
    member.fill("#password", PW)
    member.click("button[type=submit]")
    member.wait_for_load_state()
    expect(member.is_visible("text=awaiting approval"), "pending account cannot sign in yet")

    # The admin approves it.
    page.goto(BASE + "/admin/users")
    page.click("text=Approve")
    page.wait_for_load_state()
    expect(page.is_visible("text=Account approved"), "admin approved the request")

    member.goto(BASE + "/login")
    member.fill("#username", "member1")
    member.fill("#password", PW)
    member.click("button[type=submit]")
    member.wait_for_load_state()
    expect(member.url == BASE + "/my/projects", f"member lands on /my/projects (got {member.url})")
    member.fill("#name", "Member Project")
    member.click("text=Create project")
    member.wait_for_load_state()
    expect("/my/projects/" in member.url, f"member form accepted (got {member.url})")
    expect(member.is_visible("text=awaiting review"), "member project awaits review")
    browser.close()
print("browser flow passed")
