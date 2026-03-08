# Graylog AI Summary – Setup

Fetches error and security logs from Graylog, analyzes them with Ollama, and sends a structured summary to Telegram and/or Slack.

---

## Table of Contents

- [Files](#files)
- [Requirements](#requirements)
- [Which logs are included](#which-logs-are-included)
- [Local testing with .env](#local-testing-with-env)
- [1. Create Graylog API token](#1-create-graylog-api-token)
- [2. Find Stream ID](#2-find-stream-id)
- [3. Create Slack webhook](#3-create-slack-webhook)
- [3b. Telegram (optional)](#3b-telegram-optional)
- [4. Deployment](#4-deployment)
- [5. Testing](#5-testing)
- [6. Set up systemd timer](#6-set-up-systemd-timer)
- [Ollama model recommendations](#ollama-model-recommendations)
- [Troubleshooting](#troubleshooting)

---

## Files

| File | Purpose |
|------|---------|
| `log_summary.py` | Main script |
| `config.yaml` | Configuration (defaults; overridden by .env) |
| `.env` | Optional: secrets for local testing (do not commit) |
| `Makefile` | venv, install, test, run |
| `systemd-setup.conf` | Timer/Service units |

## Requirements

- **Python 3.11 or 3.12** (recommended). The Makefile automatically uses `python3.12` or `python3.11` if available.

With Make (recommended):

```bash
make install   # creates .venv and installs requirements
make test      # dry run for testing
```

Without Make:

```bash
pip install -r requirements.txt
```

### Which logs are included

The summary is built from two kinds of logs in your Graylog stream:

1. **By severity (error levels)**  
   Syslog levels: `0` = Emergency, `1` = Alert, `2` = Critical, `3` = Error, `4` = Warning, `5` = Notice, `6` = Info, `7` = Debug.  
   You can include **all** levels or only specific ones.

2. **By security keywords**  
   Any log whose `message` field contains one of the configured keywords (case-insensitive), e.g. `unauthorized`, `login failed`, `invalid token`, etc.

Both are configured in `config.yaml` under `summary`. You can override them with environment variables (e.g. in `.env`): `SUMMARY_ERROR_LEVELS` and `SUMMARY_SECURITY_KEYWORDS` (see [Local testing with .env](#local-testing-with-env)).

- **`error_levels`**  
  - `"all"` or `[0,1,2,3,4,5,6,7]` → include every level.  
  - A list like `[0, 1, 2, 3]` → only Emergency, Alert, Critical, Error (default).  
  - Use a smaller set, e.g. `[2, 3]`, to focus on Critical and Error only.

- **`security_keywords`**  
  - A list of strings: only messages containing at least one of these are considered “security events”.  
  - Set to `[]` to disable security-event search.

Example for “all” severity levels and custom keywords:

```yaml
summary:
  error_levels: "all"
  security_keywords:
    - "unauthorized"
    - "login failed"
    - "invalid token"
    # add or remove keywords as needed
```

### Local testing with .env

Instead of putting tokens in `config.yaml`, you can use a `.env` file (ignored by git):

```bash
cp .env.example .env
# Edit .env: set GRAYLOG_API_TOKEN, GRAYLOG_STREAM_ID, OLLAMA_BASE_URL, OLLAMA_BEARER_TOKEN
```

Environment variables override values from `config.yaml`. This lets you test with your Graylog token and Bearer-secured Ollama instance without changing the config. **Language:** `SUMMARY_LANGUAGE=de` (default) or `SUMMARY_LANGUAGE=en` for English summaries (or set `summary.language` in `config.yaml`).  
**Which logs:** `SUMMARY_ERROR_LEVELS=all` or `0,1,2,3` (comma-separated); `SUMMARY_SECURITY_KEYWORDS=keyword1,keyword2` or leave unset to use `config.yaml`.

## 1. Create Graylog API token

1. Open Graylog UI
2. Top right: **User menu → Edit Profile**
3. Tab **API Tokens → Create Token**
4. Copy the token → set it in `config.yaml` or `.env` as `GRAYLOG_API_TOKEN`

Authentication:
- Username = **your token**
- Password = **"token"** (literal, always)

## 2. Find Stream ID

1. Graylog UI → **Streams**
2. Open the desired stream
3. The URL contains the ID: `.../streams/`**`6507abc123def456`**`/...`
4. Set `stream_id` in `config.yaml` or `GRAYLOG_STREAM_ID` in `.env`

## 3. Create Slack webhook

1. https://api.slack.com/apps → **Create New App → From Scratch**
2. **Incoming Webhooks → Activate → Add New Webhook**
3. Choose channel → copy webhook URL
4. Set in `config.yaml` as `slack.webhook_url` or in `.env` as `SLACK_WEBHOOK_URL`

## 3b. Telegram (optional)

The summary can be sent to Telegram in addition to or instead of Slack (formatted with HTML).

1. Create a bot via [@BotFather](https://t.me/BotFather) → copy **Bot Token**
2. Get your chat ID: e.g. start the bot, then use [@userinfobot](https://t.me/userinfobot), or send a message to the bot and call `https://api.telegram.org/bot<TOKEN>/getUpdates`
3. Set in `.env`: `TELEGRAM_BOT_TOKEN=...`, `TELEGRAM_CHAT_ID=...` (or under `telegram` in `config.yaml`)

## 4. Deployment

```bash
# Create directory
sudo mkdir -p /opt/graylog-summary
sudo cp log_summary.py config.yaml requirements.txt /opt/graylog-summary/

# Install dependencies (system Python)
sudo pip3 install -r /opt/graylog-summary/requirements.txt
# Or use a venv: python3 -m venv /opt/graylog-summary/.venv && /opt/graylog-summary/.venv/bin/pip install -r /opt/graylog-summary/requirements.txt
# Then in the systemd service use: ExecStart=/opt/graylog-summary/.venv/bin/python ...

# Secure config (never commit real secrets in config.yaml; use .env on server if needed)
sudo chmod 600 /opt/graylog-summary/config.yaml
sudo chown nobody:nobody /opt/graylog-summary/config.yaml
```

## 5. Testing

```bash
# With Make (uses .venv)
make test    # Dry run: no delivery, output only
make run     # Full run (Telegram and/or Slack, depending on config)

# Without Make
python3 log_summary.py --dry-run
python3 log_summary.py
```

## 6. Set up systemd timer (recommended)

The service runs once per day (e.g. 07:00); the unit includes `TimeoutStartSec=600` so long Ollama runs are not killed.

```bash
# Copy service and timer from systemd-setup.conf into separate files
sudo nano /etc/systemd/system/graylog-summary.service
sudo nano /etc/systemd/system/graylog-summary.timer

# Enable
sudo systemctl daemon-reload
sudo systemctl enable --now graylog-summary.timer

# Check status
sudo systemctl status graylog-summary.timer
sudo systemctl list-timers graylog-summary.timer
```

To run at a different time, edit the timer’s `OnCalendar=` (e.g. `*-*-* 06:00:00` or `08:00:00`).

## Ollama model recommendations

| Model | Quality | RAM | Recommendation |
|-------|---------|-----|----------------|
| `qwen2.5:72b` | ⭐⭐⭐⭐⭐ | ~45GB | Best choice for log analysis |
| `llama3.3:70b` | ⭐⭐⭐⭐⭐ | ~45GB | Equivalent |
| `llama3.1:405b` | ⭐⭐⭐⭐⭐ | ~250GB | If available |

## Troubleshooting

**SSL errors with Graylog:**  
→ Set `verify_ssl: false` in config.yaml

**Ollama timeout:**  
→ Increase `timeout` in config.yaml (e.g. 600 for 120B models)

**Ollama SSL errors (HTTPS with self-signed cert):**  
→ Set `verify_ssl: false` under `ollama` in config.yaml

**Graylog 401 Unauthorized:**  
→ Check token; password must be literal `"token"`

**Slack message not received:**  
→ Verify webhook URL; use `--dry-run` to inspect Ollama output
