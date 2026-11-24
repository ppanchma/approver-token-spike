"""GitHub App user access token helper for the spike.

Never prints a token. Every token is masked before any other output.
Commands:
  bootstrap        device flow; stores the refresh token in the Environment secret
  act ACTION PR    rotates the refresh token, saves the new one first, then
                   approves, dismisses or only checks identity (ACTION=refresh)
"""

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"
REPO = os.environ["REPO"]
ENV_NAME = os.environ["ENV_NAME"]
CLIENT_ID = os.environ["CLIENT_ID"]


def mask(value):
    if value:
        print(f"::add-mask::{value}", flush=True)


def post_form(url, data):
    req = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(data).encode(),
        headers={"Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = json.load(resp)
    for key in ("access_token", "refresh_token", "device_code"):
        mask(body.get(key))
    return body


def api(method, path, token, payload=None):
    req = urllib.request.Request(
        f"{API}{path}",
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read() or b"{}")


def save_refresh_token(value):
    # GH_TOKEN is the App installation token with Environments: write.
    subprocess.run(
        ["gh", "secret", "set", "APP_REFRESH_TOKEN", "--env", ENV_NAME, "-R", REPO],
        input=value.encode(),
        check=True,
        capture_output=True,
    )
    print("Saved the new refresh token to the Environment secret.")


def summary(text):
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as fh:
        fh.write(text + "\n")
    print(text, flush=True)


def describe(tokens):
    summary(
        f"- access token lifetime: {tokens.get('expires_in')} s; "
        f"refresh token lifetime: {tokens.get('refresh_token_expires_in')} s"
    )


def bootstrap():
    dev = post_form("https://github.com/login/device/code", {"client_id": CLIENT_ID})
    if "user_code" not in dev:
        sys.exit(f"device code request failed: {dev.get('error')}: {dev.get('error_description')}")
    summary(
        f"## Authorize\nOpen {dev['verification_uri']} and enter code **{dev['user_code']}** "
        f"(valid {dev['expires_in']} s). Sign in as the account that should approve."
    )
    interval = int(dev.get("interval", 5))
    deadline = time.time() + int(dev["expires_in"])
    while time.time() < deadline:
        time.sleep(interval)
        tok = post_form(
            "https://github.com/login/oauth/access_token",
            {
                "client_id": CLIENT_ID,
                "device_code": dev["device_code"],
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            },
        )
        err = tok.get("error")
        if err == "authorization_pending":
            continue
        if err == "slow_down":
            interval += 5
            continue
        if err:
            sys.exit(f"device flow failed: {err}: {tok.get('error_description')}")
        if not tok.get("refresh_token"):
            sys.exit("No refresh token returned: enable 'Expire user authorization tokens' on the App.")
        save_refresh_token(tok["refresh_token"])
        status, user = api("GET", "/user", tok["access_token"])
        summary(f"- authorized as: {user.get('login')} (HTTP {status})")
        describe(tok)
        return
    sys.exit("device code expired before authorization")


def act(action, pr):
    tok = post_form(
        "https://github.com/login/oauth/access_token",
        {
            "client_id": CLIENT_ID,
            "client_secret": os.environ["CLIENT_SECRET"],
            "grant_type": "refresh_token",
            "refresh_token": os.environ["REFRESH_TOKEN"],
        },
    )
    if tok.get("error"):
        sys.exit(f"refresh failed: {tok['error']}: {tok.get('error_description')}. Re-run bootstrap.")
    # Save first: the old refresh token is now dead, so losing the new one locks the bot out.
    save_refresh_token(tok["refresh_token"])
    access = tok["access_token"]
    describe(tok)
    status, user = api("GET", "/user", access)
    login = user.get("login")
    summary(f"- acting as: {login} (HTTP {status})")
    if action == "refresh":
        return
    status, pull = api("GET", f"/repos/{REPO}/pulls/{pr}", access)
    head = pull["head"]["sha"]
    if action == "approve":
        status, review = api(
            "POST",
            f"/repos/{REPO}/pulls/{pr}/reviews",
            access,
            {
                "event": "APPROVE",
                "commit_id": head,
                "body": f"Spike approval by {login} through the App user token at {head}.",
            },
        )
        summary(
            f"- approve HTTP {status}: "
            + json.dumps(
                {
                    "id": review.get("id"),
                    "user": (review.get("user") or {}).get("login"),
                    "state": review.get("state"),
                    "commit_id": review.get("commit_id"),
                    "message": review.get("message"),
                }
            )
        )
        if status >= 300:
            sys.exit(1)
    elif action == "dismiss":
        status, reviews = api("GET", f"/repos/{REPO}/pulls/{pr}/reviews?per_page=100", access)
        mine = [r["id"] for r in reviews if r["user"]["login"] == login and r["state"] == "APPROVED"]
        if not mine:
            summary("- nothing to dismiss")
        for rid in mine:
            status, out = api(
                "PUT",
                f"/repos/{REPO}/pulls/{pr}/reviews/{rid}/dismissals",
                access,
                {"message": f"Spike: {login} dismisses its own approval.", "event": "DISMISS"},
            )
            summary(f"- dismiss {rid} HTTP {status}: state={out.get('state')} message={out.get('message')}")
            if status >= 300:
                sys.exit(1)


if __name__ == "__main__":
    if sys.argv[1] == "bootstrap":
        bootstrap()
    else:
        act(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "0")
