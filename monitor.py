#!/usr/bin/env python3
"""
botbot - domain breach monitor

Queries breach.vip's public search API for each domain in DOMAINS.
Extracts any record whose email field ends in @<your domain>.
Diffs against the last run (state.json, committed back to the repo)
and sends a Telegram alert ONLY for newly-seen findings.

Scope, on purpose:
  - Only searches the domains you own (DOMAINS below).
  - Only looks at records belonging to those domains (one hop).
  - Does NOT take any email/username/password found and search again
    with it. No recursion, no harvesting of unrelated third parties.
"""

import os
import sys
import json
import time
import hashlib
import requests

# ── Config ───────────────────────────────────────────────────────────
DOMAINS = [
    "dislogroup.com",   # <-- replace with your real domains
    "lavoieexpress.ma",
    "mrbricolage.ma",
]

API_URL = "https://breach.vip/api/search"
STATE_FILE = "state.json"
RATE_LIMIT_SLEEP = 5  # seconds between requests (API allows 15/min, we stay well under)

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")


# ── Helpers ──────────────────────────────────────────────────────────
def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    return {"seen_hashes": []}


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def record_hash(domain, record):
    """Stable fingerprint for a record so we can detect 'new' vs 'already alerted'."""
    raw = json.dumps(record, sort_keys=True) + domain
    return hashlib.sha256(raw.encode()).hexdigest()


def search_domain(domain):
    """
    Query breach.vip for a single domain.
    We search the 'domain' field directly -- this is the one legitimate
    "my own asset" lookup. We do NOT then take results and re-query.
    """
    payload = {
        "term": domain,
        "fields": ["domain"],
        "wildcard": False,
        "case_sensitive": False,
    }
    try:
        resp = requests.post(API_URL, json=payload, timeout=30)
    except requests.RequestException as e:
        print(f"[!] Request failed for {domain}: {e}", file=sys.stderr)
        return []

    if resp.status_code == 429:
        print(f"[!] Rate limited on {domain}, backing off 60s", file=sys.stderr)
        time.sleep(60)
        return search_domain(domain)

    if resp.status_code != 200:
        print(f"[!] Unexpected status {resp.status_code} for {domain}: {resp.text[:300]}", file=sys.stderr)
        return []

    try:
        data = resp.json()
    except ValueError:
        print(f"[!] Non-JSON response for {domain}", file=sys.stderr)
        return []

    # API may return either a bare list or a dict with a results key
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("results") or data.get("data") or []
    return []


def belongs_to_domain(record, domain):
    """Only keep records actually tied to our domain (email ends with @domain)."""
    email = (record.get("email") or "").lower()
    return email.endswith("@" + domain.lower())


def format_finding(domain, record):
    email = record.get("email", "unknown")
    password = record.get("password", "")
    username = record.get("username", "")
    source = record.get("source") or record.get("database") or record.get("breach") or "unknown source"

    lines = [f"🔓 *New exposure for {domain}*", f"Email: `{email}`"]
    if username:
        lines.append(f"Username: `{username}`")
    if password:
        lines.append(f"Password: `{password}`")
    lines.append(f"Source: {source}")
    return "\n".join(lines)


def send_telegram(message):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[!] Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID, skipping send.", file=sys.stderr)
        print(message)
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    resp = requests.post(url, json={
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown",
    }, timeout=15)
    if resp.status_code != 200:
        print(f"[!] Telegram send failed: {resp.status_code} {resp.text}", file=sys.stderr)


# ── Main ─────────────────────────────────────────────────────────────
def main():
    state = load_state()
    seen = set(state.get("seen_hashes", []))
    new_findings = []

    for i, domain in enumerate(DOMAINS):
        print(f"[*] Searching domain: {domain}")
        records = search_domain(domain)
        print(f"    -> {len(records)} raw record(s)")

        for record in records:
            if not belongs_to_domain(record, domain):
                continue
            h = record_hash(domain, record)
            if h in seen:
                continue
            seen.add(h)
            new_findings.append((domain, record))

        if i < len(DOMAINS) - 1:
            time.sleep(RATE_LIMIT_SLEEP)

    if new_findings:
        print(f"[+] {len(new_findings)} new finding(s). Sending alert(s).")
        # Batch into one message if possible to avoid spamming
        chunks = [format_finding(d, r) for d, r in new_findings]
        message = "\n\n".join(chunks)
        # Telegram message limit is 4096 chars; split if needed
        MAX_LEN = 3500
        if len(message) <= MAX_LEN:
            send_telegram(message)
        else:
            buf = ""
            for chunk in chunks:
                if len(buf) + len(chunk) + 2 > MAX_LEN:
                    send_telegram(buf)
                    buf = chunk
                else:
                    buf = (buf + "\n\n" + chunk) if buf else chunk
            if buf:
                send_telegram(buf)
    else:
        print("[*] No new findings this run.")

    state["seen_hashes"] = list(seen)
    save_state(state)


if __name__ == "__main__":
    main()
