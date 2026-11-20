"""Lejárati értesítések: napi összesítő webhookra és/vagy ntfy-ra."""
from __future__ import annotations

import datetime as dt
import json
import os
import threading
import time
import urllib.parse
import urllib.request

import audit
import ca

STATE_FILE = ca.DATA_DIR / "notify-state.json"


def config() -> dict:
    def _int(name, default):
        try:
            return int(os.environ.get(name, default))
        except ValueError:
            return default
    return {
        "days": _int("NOTIFY_DAYS", 30),
        "hour": _int("NOTIFY_HOUR", 8),
        "webhook_url": os.environ.get("NOTIFY_WEBHOOK_URL", "").strip(),
        "ntfy_url": os.environ.get("NOTIFY_NTFY_URL", "").strip(),
        "ntfy_token": os.environ.get("NOTIFY_NTFY_TOKEN", "").strip(),
        "public_url": os.environ.get("PUBLIC_URL", "").strip().rstrip("/"),
    }


def enabled(cfg: dict | None = None) -> bool:
    cfg = cfg or config()
    return bool(cfg["webhook_url"] or cfg["ntfy_url"])


def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text())
    except (OSError, ValueError):
        return {}


def _save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))


def _line(it: dict) -> str:
    i = it["info"]
    when = (f"LEJÁRT {-i['days_left']} napja" if i["status"] == "expired"
            else f"{i['days_left']} nap múlva")
    return f"• {i['cn']} ({it['kind_label']}) – {i['not_after'][:10]}, {when}"


def build_message(items: list[dict], cfg: dict) -> tuple[str, str]:
    title = f"Local CA: {len(items)} tanúsítvány lejár {cfg['days']} napon belül"
    lines = [_line(it) for it in items]
    if cfg["public_url"]:
        lines.append("")
        lines.append(cfg["public_url"] + "/")
    return title, "\n".join(lines)


def _post(url: str, body: bytes, headers: dict) -> None:
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"User-Agent": "local-ca-manager", **headers})
    with urllib.request.urlopen(req, timeout=15) as r:
        if r.status >= 300:
            raise RuntimeError(f"HTTP {r.status}")


def send(title: str, text: str, items: list[dict], cfg: dict, urgent: bool = False) -> list[str]:
    """Elküldi az üzenetet minden beállított csatornára. Visszaad: hibák listája."""
    errors = []
    if cfg["webhook_url"]:
        payload = {
            "title": title,
            "text": f"{title}\n{text}",       # Slack, Mattermost, Rocket.Chat
            "content": f"**{title}**\n{text}",  # Discord
            "certs": [{"id": i["id"], "cn": i["info"]["cn"], "kind": i["kind"],
                       "not_after": i["info"]["not_after_dt"].isoformat(),
                       "days_left": i["info"]["days_left"]} for i in items],
        }
        try:
            _post(cfg["webhook_url"], json.dumps(payload, ensure_ascii=False).encode(),
                  {"Content-Type": "application/json"})
        except Exception as e:
            errors.append(f"webhook: {e}")
    if cfg["ntfy_url"]:
        # JSON publikálás: a cím így UTF-8 is lehet (fejlécben nem)
        u = urllib.parse.urlsplit(cfg["ntfy_url"])
        base_path, _, topic = u.path.rstrip("/").rpartition("/")
        base = urllib.parse.urlunsplit((u.scheme, u.netloc, base_path or "/", "", ""))
        payload = {"topic": topic, "title": title, "message": text,
                   "tags": ["warning"], "priority": 4 if urgent else 3}
        if cfg["public_url"]:
            payload["click"] = cfg["public_url"] + "/"
        headers = {"Content-Type": "application/json"}
        if cfg["ntfy_token"]:
            headers["Authorization"] = f"Bearer {cfg['ntfy_token']}"
        try:
            _post(base, json.dumps(payload, ensure_ascii=False).encode(), headers)
        except Exception as e:
            errors.append(f"ntfy: {e}")
    return errors


def run_check(force: bool = False, req=None) -> dict:
    """Lejáró certek összegyűjtése és értesítés küldése. force=False: naponta egyszer."""
    cfg = config()
    today = dt.date.today().isoformat()
    state = load_state()
    if not force and state.get("last_run_date") == today:
        return state
    items = ca.expiring_items(cfg["days"])
    result = {"last_run_date": today,
              "last_run": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
              "expiring": len(items), "sent": False, "errors": []}
    if items and enabled(cfg):
        title, text = build_message(items, cfg)
        urgent = any(i["info"]["days_left"] <= 7 for i in items)
        errors = send(title, text, items, cfg, urgent=urgent)
        channels = bool(cfg["webhook_url"]) + bool(cfg["ntfy_url"])
        result["sent"] = len(errors) < channels  # legalább egy csatornán kiment
        result["errors"] = errors
        if errors:
            audit.log("notify_error", req, errors=errors)
        if result["sent"]:
            audit.log("notify", req, count=len(items), certs=[i["info"]["cn"] for i in items])
    _save_state(result)
    return result


def send_test(req=None) -> list[str]:
    cfg = config()
    if not enabled(cfg):
        return ["Nincs beállítva értesítési csatorna (NOTIFY_WEBHOOK_URL / NOTIFY_NTFY_URL)."]
    errors = send("Local CA: teszt értesítés",
                  "Ha ezt látod, a lejárati értesítések működnek. ✓", [], cfg)
    audit.log("notify_error" if errors else "notify", req, test=True, errors=errors)
    return errors


_started = False


def start_scheduler() -> None:
    """Háttérszál: 10 percenként megnézi, elérte-e a NOTIFY_HOUR-t, és ha ma még nem futott, fut."""
    global _started
    if _started or os.environ.get("NOTIFY_DISABLE_SCHEDULER"):
        return
    _started = True

    def loop():
        time.sleep(30)
        while True:
            try:
                if dt.datetime.now().hour >= config()["hour"]:
                    run_check()
            except Exception as e:  # a háttérszál soha ne álljon le
                print(f"notify hiba: {e}", flush=True)
            time.sleep(600)

    threading.Thread(target=loop, name="notify", daemon=True).start()
