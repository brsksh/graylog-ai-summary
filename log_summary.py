#!/usr/bin/env python3
"""
Graylog AI Log Summary
----------------------
Fetches error and security logs from Graylog, analyzes them with Ollama,
and sends a structured summary to Telegram and/or Slack.

Requirements:
    pip install -r requirements.txt
    Optional: .env with GRAYLOG_*, OLLAMA_* for local testing (overrides config.yaml)

Graylog API token:
    Graylog UI → User menu (top right) → Edit Profile → API Tokens → Create Token
    Auth: Username=TOKEN, Password="token" (literal)
"""

import os
import re
import sys
import json
import logging
import argparse
import warnings
from datetime import datetime, timezone
from collections import defaultdict

# Suppress urllib3 LibreSSL warning (set before importing urllib3)
warnings.filterwarnings("ignore", message=".*OpenSSL.*")
warnings.filterwarnings("ignore", module="urllib3")

import requests
import yaml
from dotenv import load_dotenv

load_dotenv()

# ── Logging Setup ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


# ── Config loading ───────────────────────────────────────────────────────────
def _resolve_config_path(path: str) -> str:
    """Resolve config path; require it to be under current directory (no path traversal)."""
    abs_path = os.path.abspath(path)
    cwd = os.path.realpath(os.getcwd())
    if not os.path.isfile(abs_path):
        raise FileNotFoundError(f"Config file not found: {path}")
    # Require config to live under cwd (or be cwd-relative)
    try:
        abs_path_real = os.path.realpath(abs_path)
    except OSError:
        raise FileNotFoundError(f"Config file not found: {path}")
    if abs_path_real != cwd and not abs_path_real.startswith(cwd + os.sep):
        raise ValueError(
            f"Config path must be under current directory ({cwd}): {path}"
        )
    return abs_path_real


def load_config(path: str) -> dict:
    path = _resolve_config_path(path)
    with open(path) as f:
        cfg = yaml.safe_load(f)
    # Environment variables override config (for .env testing)
    if os.environ.get("GRAYLOG_BASE_URL"):
        cfg["graylog"]["base_url"] = os.environ["GRAYLOG_BASE_URL"].rstrip("/")
    if os.environ.get("GRAYLOG_API_TOKEN"):
        cfg["graylog"]["api_token"] = os.environ["GRAYLOG_API_TOKEN"]
    if os.environ.get("GRAYLOG_STREAM_ID"):
        cfg["graylog"]["stream_id"] = os.environ["GRAYLOG_STREAM_ID"]
    if os.environ.get("OLLAMA_BASE_URL"):
        cfg["ollama"]["base_url"] = os.environ["OLLAMA_BASE_URL"].rstrip("/")
    if os.environ.get("OLLAMA_BEARER_TOKEN"):
        cfg["ollama"]["bearer_token"] = os.environ["OLLAMA_BEARER_TOKEN"]
    if os.environ.get("OLLAMA_MODEL"):
        cfg["ollama"]["model"] = os.environ["OLLAMA_MODEL"]
    cfg.setdefault("telegram", {})
    if os.environ.get("TELEGRAM_BOT_TOKEN"):
        cfg["telegram"]["bot_token"] = os.environ["TELEGRAM_BOT_TOKEN"]
    if os.environ.get("TELEGRAM_CHAT_ID"):
        cfg["telegram"]["chat_id"] = os.environ["TELEGRAM_CHAT_ID"]
    cfg.setdefault("slack", {})
    if os.environ.get("SLACK_WEBHOOK_URL"):
        cfg["slack"]["webhook_url"] = os.environ["SLACK_WEBHOOK_URL"].strip()
    cfg.setdefault("summary", {})
    if os.environ.get("SUMMARY_LANGUAGE"):
        lang = os.environ["SUMMARY_LANGUAGE"].strip().lower()
        if lang in ("de", "en"):
            cfg["summary"]["language"] = lang
    if "SUMMARY_ERROR_LEVELS" in os.environ:
        raw = os.environ["SUMMARY_ERROR_LEVELS"].strip().lower()
        if raw == "all":
            cfg["summary"]["error_levels"] = "all"
        else:
            levels = [int(x.strip()) for x in raw.split(",") if x.strip().isdigit()]
            if levels:
                cfg["summary"]["error_levels"] = sorted(set(levels))
    if "SUMMARY_SECURITY_KEYWORDS" in os.environ:
        raw = os.environ["SUMMARY_SECURITY_KEYWORDS"].strip()
        cfg["summary"]["security_keywords"] = [k.strip() for k in raw.split(",") if k.strip()] if raw else []
    return cfg


# ── Graylog API ───────────────────────────────────────────────────────────────
class GraylogClient:
    def __init__(self, cfg: dict):
        self.base_url = cfg["base_url"].rstrip("/")
        self.token = cfg["api_token"]
        self.stream_id = cfg["stream_id"]
        self.verify_ssl = cfg.get("verify_ssl", True)
        # Graylog token auth: Username=token, Password="token"
        self.auth = (self.token, "token")
        self.headers = {"Accept": "application/json", "X-Requested-By": "graylog-ai-summary"}

    def _get(self, path: str, params: dict = None) -> dict:
        url = f"{self.base_url}/api{path}"
        resp = requests.get(
            url, auth=self.auth, headers=self.headers,
            params=params, verify=self.verify_ssl, timeout=30
        )
        resp.raise_for_status()
        return resp.json()

    def search(self, query: str, lookback_hours: int, limit: int) -> list[dict]:
        """Run a Graylog search and return messages."""
        params = {
            "query": query,
            "range": lookback_hours * 3600,
            "limit": limit,
            "filter": f"streams:{self.stream_id}",
            "fields": "timestamp,source,level,message,facility,_id",
            "sort": "timestamp:desc",
        }
        log.info(f"Graylog Query: {query!r}, Lookback: {lookback_hours}h, Limit: {limit}")
        data = self._get("/search/universal/relative", params)
        messages = [m["message"] for m in data.get("messages", [])]
        log.info(f"  → {len(messages)} messages found")
        return messages


# ── Log data preparation ──────────────────────────────────────────────────────
# Syslog levels: 0=Emergency, 1=Alert, 2=Critical, 3=Error, 4=Warning, 5=Notice, 6=Info, 7=Debug
ALL_LEVELS = list(range(8))


def _escape_graylog_phrase(phrase: str) -> str:
    """Escape a string for use inside double quotes in a Graylog/Lucene-style query (injection-safe)."""
    return phrase.replace("\\", "\\\\").replace('"', '\\"')


def fetch_error_logs(client: GraylogClient, cfg: dict) -> list[dict]:
    """Fetch logs by severity level (config: error_levels = list of 0–7, or 'all')."""
    raw = cfg["summary"].get("error_levels", [0, 1, 2, 3])
    levels = ALL_LEVELS if raw == "all" or raw == ["all"] else raw
    if not levels:
        return []
    level_query = " OR ".join(f"level:{l}" for l in levels)
    query = f"({level_query})"
    return client.search(
        query=query,
        lookback_hours=cfg["summary"]["lookback_hours"],
        limit=cfg["summary"]["max_total_logs"],
    )


def fetch_security_logs(client: GraylogClient, cfg: dict) -> list[dict]:
    """Fetch logs that contain any of the configured security keywords (message field)."""
    keywords = cfg["summary"].get("security_keywords") or []
    if not keywords:
        return []
    kw_query = " OR ".join(f'message:"{_escape_graylog_phrase(kw)}"' for kw in keywords)
    query = f"({kw_query})"
    return client.search(
        query=query,
        lookback_hours=cfg["summary"]["lookback_hours"],
        limit=cfg["summary"]["max_total_logs"] // 2,
    )


def group_by_source(messages: list[dict], max_per_source: int) -> dict[str, list[dict]]:
    """Group messages by source, limit per source."""
    grouped = defaultdict(list)
    for msg in messages:
        source = msg.get("source", "unknown")
        if len(grouped[source]) < max_per_source:
            grouped[source].append(msg)
    return dict(grouped)


def build_prompt(
    error_grouped: dict[str, list],
    security_msgs: list[dict],
    lookback_hours: int,
    language: str,
) -> str:
    """Build the prompt for Ollama."""

    lang_instruction = (
        "Antworte auf Deutsch." if language == "de" else "Respond in English."
    )

    # Build error section
    error_section = ""
    total_errors = sum(len(v) for v in error_grouped.values())
    if total_errors > 0:
        error_section = f"\n## ERROR/CRITICAL LOGS ({total_errors} total)\n"
        for source, msgs in sorted(error_grouped.items()):
            error_section += f"\n### Source: {source} ({len(msgs)} entries)\n"
            for m in msgs[:20]:  # max 20 pro Source im Prompt
                ts = m.get("timestamp", "?")
                msg_text = m.get("message", "")[:300]  # Truncate
                error_section += f"  [{ts}] {msg_text}\n"
    else:
        error_section = "\n## ERROR/CRITICAL LOGS\nNo errors in the observation period.\n"

    # Security section
    security_section = ""
    if security_msgs:
        security_section = f"\n## SECURITY EVENTS ({len(security_msgs)} total)\n"
        for m in security_msgs[:50]:
            ts = m.get("timestamp", "?")
            src = m.get("source", "?")
            msg_text = m.get("message", "")[:300]
            security_section += f"  [{ts}] [{src}] {msg_text}\n"
    else:
        security_section = "\n## SECURITY EVENTS\nNo notable security events.\n"

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    format_de = """
WICHTIG – Ausgabeformat (strikt einhalten):
- Schreibe genau diese Abschnittsüberschriften (mit ## und einem Leerzeichen davor):
  ## Kritische Fehler
  ## Security-Events
  ## Betroffene Systeme
  ## Sofortmaßnahmen
  ## Gesamtbewertung
- Pro betroffenem System: Konkrete Angaben. Bei jedem System (z.B. he-mon-01, atelierpeart-backend) kurz benennen: welcher Fehler oder welches Security-Event, und welche konkrete Maßnahme (oder „keine Auffälligkeiten“). Keine vagen Formulierungen wie nur „Logs prüfen“ ohne Kontext.
- Bei jedem in „Betroffene Systeme“ genannten System kurz begründen, warum es aufgeführt ist (z.B. „im Log-Stream, in 24h keine Fehler/Security“ oder „keine Auffälligkeiten“). Ein reines „keine“ ohne Kontext vermeiden.
- Tabellen: Nur Markdown-Tabellen mit | Spalte1 | Spalte2 |. Keine Leerzeilen innerhalb einer Tabelle. Den Abschnitt „Gesamtbewertung“ immer mit genau einer Tabelle ausgeben: zwei Spalten System | Bewertung, eine Zeile pro System, Werte nur Rot, Gelb oder Grün. Diesen Abschnitt nicht weglassen.
- Bewertungen: Exakt die Wörter Rot, Gelb oder Grün. Keine anderen Bezeichnungen.
- Listen: Einrückung mit „- “ am Zeilenanfang. Keine doppelten Leerzeilen innerhalb eines Abschnitts.
- Kurz und prägnant. Kein Fazit-Block außerhalb von „Gesamtbewertung“."""

    format_en = """
IMPORTANT – Output format (strict):
- Use exactly these section headers (with ## and one space after):
  ## Critical Errors
  ## Security Events
  ## Affected Systems
  ## Immediate Actions
  ## Overall Assessment
- Per affected system: Be specific. For each system (e.g. he-mon-01) state briefly: which error or security event, and which concrete action (or \"no issues\"). Avoid vague phrases like \"review logs\" without context.
- For every system listed under \"Affected Systems\", briefly state why it is listed (e.g. \"in log stream, no errors/security in 24h\" or \"no issues\"). Avoid a bare \"none\" or \"no\" without context.
- Tables: Markdown tables only with | Col1 | Col2 |. No blank lines inside a table. You must always include the \"Overall Assessment\" section with exactly one table: two columns System | Rating, one row per system, rating values Red, Yellow or Green only. Do not omit this section.
- Ratings: Use exactly Red, Yellow or Green. No other terms.
- Lists: Use \"- \" at line start. No double blank lines inside a section.
- Keep it concise."""

    format_instruction = format_de if language == "de" else format_en

    prompt = f"""Du bist ein erfahrener System-Administrator und Security-Analyst.
{lang_instruction}

Analysiere die folgenden Log-Daten aus dem Zeitraum der letzten {lookback_hours} Stunden (Stand: {now}).

Erstelle eine strukturierte Zusammenfassung mit diesen fünf Abschnitten: Kritische Fehler, Security-Events, Betroffene Systeme, Sofortmaßnahmen, Gesamtbewertung.
{format_instruction}

---
{error_section}
{security_section}
---

Deine Analyse (beginne mit ## Kritische Fehler bzw. ## Critical Errors):"""

    return prompt


# ── Ollama ────────────────────────────────────────────────────────────────────
def query_ollama(prompt: str, cfg: dict) -> str:
    """Send prompt to Ollama and return the response."""
    url = f"{cfg['ollama']['base_url']}/api/generate"
    payload = {
        "model": cfg["ollama"]["model"],
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.3,   # Niedrig = konsistenter, weniger halluziniert
            "num_predict": 2048,
        },
    }
    headers = {}
    bearer = cfg["ollama"].get("bearer_token") or os.environ.get("OLLAMA_BEARER_TOKEN")
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    verify_ssl = cfg["ollama"].get("verify_ssl", True)
    log.info(f"Querying Ollama: {cfg['ollama']['model']} @ {cfg['ollama']['base_url']}")
    resp = requests.post(
        url, json=payload, headers=headers if headers else None,
        timeout=cfg["ollama"].get("timeout", 300),
        verify=verify_ssl,
    )
    resp.raise_for_status()
    result = resp.json()
    return result.get("response", "").strip()


# ── Parse & Format (LLM output → structured → channel) ─────────────────────────
def parse_summary(raw: str) -> dict:
    """
    Parse raw LLM output into a unified structure.
    Returns: {"sections": [{"title": str, "blocks": [{"type": "table"|"text", "lines"|"content": ...}]}]}
    """
    text = "".join(c for c in raw if c in "\n\r\t" or ord(c) >= 32)
    lines = [ln.strip() for ln in text.splitlines()]
    table_row = re.compile(r"^\|.+\|$")
    section_header = re.compile(r"^##\s+(.+)$")

    sections = []
    current_title = None
    current_blocks = []
    current_table = []
    current_text_lines = []

    def flush_table():
        nonlocal current_table, current_blocks
        if current_table:
            current_blocks.append({"type": "table", "lines": current_table})
            current_table = []

    def flush_text():
        nonlocal current_text_lines, current_blocks
        if current_text_lines:
            content = "\n".join(current_text_lines).strip()
            if content:
                current_blocks.append({"type": "text", "content": content})
            current_text_lines = []

    def flush_section():
        nonlocal current_title, current_blocks, sections
        if current_title is not None:
            flush_table()
            flush_text()
            if current_blocks:
                sections.append({"title": current_title, "blocks": current_blocks})
            current_blocks = []
        current_title = None

    for line in lines:
        if not line:
            if current_table:
                flush_table()
            elif current_text_lines:
                current_text_lines.append("")
            continue
        m = section_header.match(line)
        if m:
            flush_section()
            current_title = m.group(1).strip()
            continue
        if table_row.match(line):
            flush_text()
            current_table.append(line)
        else:
            flush_table()
            current_text_lines.append(line)

    flush_section()

    # Fallback: no ## found → treat entire text as one section
    if not sections and text.strip():
        blocks = []
        seg_table = []
        seg_text = []
        for line in lines:
            if not line:
                if seg_table:
                    blocks.append({"type": "table", "lines": seg_table})
                    seg_table = []
                elif seg_text:
                    seg_text.append("")
            elif table_row.match(line):
                if seg_text:
                    blocks.append({"type": "text", "content": "\n".join(seg_text).strip()})
                    seg_text = []
                seg_table.append(line)
            else:
                if seg_table:
                    blocks.append({"type": "table", "lines": seg_table})
                    seg_table = []
                seg_text.append(line)
        if seg_table:
            blocks.append({"type": "table", "lines": seg_table})
        if seg_text:
            blocks.append({"type": "text", "content": "\n".join(seg_text).strip()})
        if blocks:
            sections = [{"title": "Zusammenfassung", "blocks": blocks}]

    return {"sections": sections}


def _escape_html(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# Overall rating section: table titles (case-insensitive) for emoji list
_RATING_SECTION_TITLES_LOWER = frozenset(("gesamtbewertung", "overall assessment"))
_RATING_TO_EMOJI = {
    "rot": "🔴", "gelb": "🟡", "grün": "🟢",
    "red": "🔴", "yellow": "🟡", "green": "🟢",
}


def _parse_rating_table(lines: list[str]) -> list[tuple[str, str]] | None:
    """
    Parse a markdown table with System/Rating columns.
    Returns: [(system, emoji), ...] or None if not a rating table.
    """
    if not lines or len(lines) < 2:
        return None
    rows = []
    for line in lines:
        cells = [c.strip() for c in line.split("|") if c.strip()]
        if not cells:
            continue
        if re.match(r"^[-:\s]+$", cells[0]):  # Separatorzeile |---|
            continue
        if len(cells) >= 2:
            rating_cell = cells[-1].lower()
            if rating_cell in _RATING_TO_EMOJI:
                system = cells[0]
                rows.append((system, _RATING_TO_EMOJI[rating_cell]))
            else:
                # Header row (e.g. System | Rating) – skip
                pass
    return rows if rows else None


def _text_to_telegram_html(content: str) -> str:
    """Convert plain text to Telegram HTML (bold, italic, rating emojis)."""
    t = _escape_html(content)
    t = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", t)
    t = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<i>\1</i>", t)
    t = re.sub(r"\bRot für\b", "🔴 Rot für", t)
    t = re.sub(r"\bGelb für\b", "🟡 Gelb für", t)
    t = re.sub(r"\bGrün für\b", "🟢 Grün für", t)
    t = re.sub(r"\bRed for\b", "🔴 Red for", t)
    t = re.sub(r"\bYellow for\b", "🟡 Yellow for", t)
    t = re.sub(r"\bGreen for\b", "🟢 Green for", t)
    t = re.sub(r"^-\s*Rot\b(?!\s*für)", "- 🔴 Rot", t, flags=re.MULTILINE)
    t = re.sub(r"^-\s*Gelb\b(?!\s*für)", "- 🟡 Gelb", t, flags=re.MULTILINE)
    t = re.sub(r"^-\s*Grün\b(?!\s*für)", "- 🟢 Grün", t, flags=re.MULTILINE)
    t = re.sub(r"^-\s*Red\b(?!\s*for)", "- 🔴 Red", t, flags=re.MULTILINE)
    t = re.sub(r"^-\s*Yellow\b(?!\s*for)", "- 🟡 Yellow", t, flags=re.MULTILINE)
    t = re.sub(r"^-\s*Green\b(?!\s*for)", "- 🟢 Green", t, flags=re.MULTILINE)
    return t


def format_for_telegram(parsed: dict, stats: dict) -> str:
    """Build Telegram HTML body from parsed summary (no header)."""
    parts = []
    for sec in parsed.get("sections", []):
        title = sec.get("title", "")
        parts.append(f"\n<b>{_escape_html(title)}</b>\n")
        for blk in sec.get("blocks", []):
            if blk.get("type") == "table":
                lines = blk.get("lines", [])
                if title.strip().lower() in _RATING_SECTION_TITLES_LOWER:
                    rating_rows = _parse_rating_table(lines)
                    if rating_rows:
                        for system, emoji in rating_rows:
                            parts.append(f"{emoji} {_escape_html(system)}\n")
                        continue
                table_str = "\n".join(_escape_html(ln) for ln in lines)
                parts.append(f"<pre>{table_str}</pre>\n")
            else:
                parts.append(_text_to_telegram_html(blk.get("content", "")) + "\n")
    out = "".join(parts)
    out = re.sub(r"\n{3,}", "\n\n", out)
    return out.strip()


def format_for_slack(parsed: dict, stats: dict) -> list:
    """Build Slack blocks from parsed summary (no header/context)."""
    blocks = []
    for sec in parsed.get("sections", []):
        title = sec.get("title", "")
        section_text = f"*{title}*\n\n"
        for blk in sec.get("blocks", []):
            if blk.get("type") == "table":
                lines = blk.get("lines", [])
                if title.strip().lower() in _RATING_SECTION_TITLES_LOWER:
                    rating_rows = _parse_rating_table(lines)
                    if rating_rows:
                        for system, emoji in rating_rows:
                            section_text += f"{emoji} {system}\n"
                        section_text += "\n"
                        continue
                table_str = "\n".join(lines)
                section_text += f"```\n{table_str}\n```\n\n"
            else:
                content = blk.get("content", "")
                content = re.sub(r"\bRot für\b", "🔴 Rot für", content)
                content = re.sub(r"\bGelb für\b", "🟡 Gelb für", content)
                content = re.sub(r"\bGrün für\b", "🟢 Grün für", content)
                content = re.sub(r"\bRed for\b", "🔴 Red for", content)
                content = re.sub(r"\bYellow for\b", "🟡 Yellow for", content)
                content = re.sub(r"\bGreen for\b", "🟢 Green for", content)
                content = re.sub(r"^-\s*Rot\b(?!\s*für)", "- 🔴 Rot", content, flags=re.MULTILINE)
                content = re.sub(r"^-\s*Gelb\b(?!\s*für)", "- 🟡 Gelb", content, flags=re.MULTILINE)
                content = re.sub(r"^-\s*Grün\b(?!\s*für)", "- 🟢 Grün", content, flags=re.MULTILINE)
                content = re.sub(r"^-\s*Red\b(?!\s*for)", "- 🔴 Red", content, flags=re.MULTILINE)
                content = re.sub(r"^-\s*Yellow\b(?!\s*for)", "- 🟡 Yellow", content, flags=re.MULTILINE)
                content = re.sub(r"^-\s*Green\b(?!\s*for)", "- 🟢 Green", content, flags=re.MULTILINE)
                section_text += content + "\n\n"
        section_text = section_text.strip()
        if section_text:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": section_text[:2900]}})
            if len(section_text) > 2900:
                blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": section_text[2900:5800]}})
    return blocks


# ── Header labels by language ──────────────────────────────────────────────────
def _header_labels(lang: str) -> dict:
    if lang == "en":
        return {"period": "last", "errors": "Errors", "security": "Security", "sources": "Sources"}
    return {"period": "letzte", "errors": "Fehler", "security": "Security", "sources": "Sources"}


# ── Slack ─────────────────────────────────────────────────────────────────────
def send_to_slack(summary: str, cfg: dict, stats: dict):
    """Send summary as formatted Slack message (parsed, channel-specific formatting)."""
    webhook_url = cfg["slack"]["webhook_url"]
    now = datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M UTC")
    hours = cfg["summary"]["lookback_hours"]
    labels = _header_labels(cfg["summary"].get("language", "de"))

    parsed = parse_summary(summary)
    body_blocks = format_for_slack(parsed, stats)

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"🤖 Graylog AI Summary – {now}"},
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": (
                        f"📅 {labels['period']} *{hours}h* | "
                        f"🔴 *{stats['error_count']}* {labels['errors']} | "
                        f"🔒 *{stats['security_count']}* {labels['security']} | "
                        f"🖥️ *{stats['source_count']}* {labels['sources']}"
                    ),
                }
            ],
        },
        {"type": "divider"},
    ]
    blocks.extend(body_blocks)

    payload = {
        "username": cfg["slack"].get("username", "GraylogAI"),
        "icon_emoji": cfg["slack"].get("icon_emoji", ":mag:"),
        "blocks": blocks,
    }
    if "channel" in cfg["slack"]:
        payload["channel"] = cfg["slack"]["channel"]

    log.info("Sending summary to Slack...")
    resp = requests.post(webhook_url, json=payload, timeout=10)
    resp.raise_for_status()
    log.info("✓ Slack message sent")


# ── Telegram ───────────────────────────────────────────────────────────────────
def send_to_telegram(summary: str, cfg: dict, stats: dict):
    """Send summary formatted to Telegram (parsed, channel-specific formatting)."""
    telegram = cfg.get("telegram", {})
    bot_token = telegram.get("bot_token")
    chat_id = telegram.get("chat_id")
    if not bot_token or not chat_id:
        log.warning("Telegram not configured (missing bot_token/chat_id) – skipping")
        return
    now = datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M UTC")
    hours = cfg["summary"]["lookback_hours"]
    labels = _header_labels(cfg["summary"].get("language", "de"))
    header = (
        f"🤖 <b>Graylog AI Summary</b>\n"
        f"<i>{now}</i> · {labels['period']} {hours}h\n"
        f"🔴 {stats['error_count']} {labels['errors']} · "
        f"🔒 {stats['security_count']} {labels['security']} · "
        f"🖥️ {stats['source_count']} {labels['sources']}\n"
        f"────────────────\n\n"
    )
    parsed = parse_summary(summary)
    body_html = format_for_telegram(parsed, stats)
    full = header + body_html
    # Telegram limit 4096 characters per message
    max_len = 4096
    if len(full) <= max_len:
        messages = [full]
    else:
        messages = [header + body_html[: max_len - len(header) - 20] + "\n\n… (truncated)"]
        rest = body_html[max_len - len(header) - 20 :]
        while rest:
            chunk = rest[: max_len - 10]
            rest = rest[len(chunk) :]
            messages.append(chunk + ("\n\n…" if rest else ""))
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    log.info("Sending summary to Telegram...")
    for i, msg in enumerate(messages):
        payload = {
            "chat_id": chat_id,
            "text": msg,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        resp = requests.post(url, json=payload, timeout=15)
        if not resp.ok:
            log.error("Telegram API error: %s", resp.text)
        resp.raise_for_status()
    log.info("✓ Telegram message(s) sent")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Graylog AI Log Summary")
    parser.add_argument(
        "--config", default="config.yaml", help="Pfad zur config.yaml"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="No delivery; print summary only"
    )
    args = parser.parse_args()

    log.info("=== Graylog AI Summary started ===")
    cfg = load_config(args.config)

    client = GraylogClient(cfg["graylog"])

    # 1. Fetch logs
    log.info("Fetching error logs...")
    error_msgs = fetch_error_logs(client, cfg)

    log.info("Fetching security logs...")
    security_msgs = fetch_security_logs(client, cfg)

    if not error_msgs and not security_msgs:
        log.info("No relevant logs found — all clear! 🟢")
        if not args.dry_run:
            ok_msg = (
                "✅ All clear! No errors or security events in the last "
                f"{cfg['summary']['lookback_hours']} hours."
            )
            stats0 = {"error_count": 0, "security_count": 0, "source_count": 0}
            if cfg.get("telegram", {}).get("bot_token") and cfg["telegram"].get("chat_id"):
                send_to_telegram(ok_msg, cfg, stats0)
            slack_url = (cfg.get("slack") or {}).get("webhook_url") or ""
            if slack_url.strip() and "XXX" not in slack_url:
                send_to_slack(ok_msg, cfg, stats0)
        return

    # 2. Aufbereiten
    max_per_source = cfg["summary"]["max_logs_per_source"]
    error_grouped = group_by_source(error_msgs, max_per_source)

    stats = {
        "error_count": len(error_msgs),
        "security_count": len(security_msgs),
        "source_count": len(error_grouped),
    }

    # 3. Prompt bauen
    prompt = build_prompt(
        error_grouped,
        security_msgs,
        cfg["summary"]["lookback_hours"],
        cfg["summary"].get("language", "de"),
    )

    log.info(f"Prompt length: {len(prompt)} characters")

    # 4. Ollama fragen
    summary = query_ollama(prompt, cfg)

    if args.dry_run:
        print("\n" + "=" * 60)
        print("DRY RUN - Summary:")
        print("=" * 60)
        print(summary)
        print("=" * 60)
        return

    # 5. Send to Telegram and/or Slack (Slack only if webhook URL is set)
    if cfg.get("telegram", {}).get("bot_token") and cfg["telegram"].get("chat_id"):
        send_to_telegram(summary, cfg, stats)
    slack_url = (cfg.get("slack") or {}).get("webhook_url") or ""
    if slack_url.strip() and "XXX" not in slack_url:
        send_to_slack(summary, cfg, stats)
    log.info("=== Done ===")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        log.error(f"Error: {e}", exc_info=True)
        sys.exit(1)
