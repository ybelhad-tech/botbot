# botbot — domain breach monitor

Checks your owned domains against [breach.vip](https://breach.vip)'s public
search API twice a day, and sends a Telegram message whenever a **new**
breached record turns up for one of your domains. Re-runs don't re-alert on
things you've already seen — `state.json` tracks what's been reported.

Scope, by design: this only searches the domains you list below, and only
looks at records actually matching `@yourdomain`. It does **not** take any
discovered email, username, or password and search again with it. One hop,
your own assets only.

## 1. Set your domains

Edit `monitor.py`, replace the placeholder values in `DOMAINS`:

```python
DOMAINS = [
    "yourcompany.com",
    "yoursecondsite.com",
    "yourthirdsite.com",
]
```

## 2. Create a Telegram bot (free, ~1 minute)

1. Open Telegram, message **[@BotFather](https://t.me/BotFather)**.
2. Send `/newbot`, follow the prompts, give it any name.
3. BotFather replies with a token like `123456789:AAExxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`.
   This is your `TELEGRAM_BOT_TOKEN`.
4. Send your new bot a message (anything, e.g. "hi") so it knows about you.
5. Visit `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates` in a browser
   and find `"chat":{"id":NNNNNNN,...}` — that number is your `TELEGRAM_CHAT_ID`.

## 3. Add the secrets to GitHub

In this repo: **Settings → Secrets and variables → Actions → New repository secret**

- `TELEGRAM_BOT_TOKEN` — from step 2
- `TELEGRAM_CHAT_ID` — from step 2

## 4. Push everything

```bash
git add .
git commit -m "Initial breach monitor setup"
git push
```

## 5. Test it

Go to the **Actions** tab → **Breach Monitor** → **Run workflow** (manual
trigger) to confirm it runs cleanly before waiting for the schedule.

## Schedule

Default: 07:00 and 19:00 UTC. Edit the `cron` lines in
`.github/workflows/monitor.yml` to change timing —
[crontab.guru](https://crontab.guru) helps if you want a different timezone
offset.

## Notes

- breach.vip's API is rate-limited to 15 requests/minute; this script stays
  well under that (3 requests per run, 5s apart).
- `state.json` is committed back to the repo by the workflow itself after
  each run — that's expected, not a bug, and is what prevents duplicate alerts.
- If you ever rotate a leaked password, you can leave its entry in
  `state.json` — it just means you won't be re-alerted for that specific
  already-handled record.
