"""Audit log: JSON Lines file in the data directory (data/audit.log)."""
from __future__ import annotations

import datetime as dt
import json
import os
import threading
from collections import deque

from ca import DATA_DIR

LOG_FILE = DATA_DIR / "audit.log"
_lock = threading.Lock()

# User name header(s) sent by the reverse proxy, tried in order.
USER_HEADERS = [h.strip() for h in (
    os.environ.get("AUDIT_USER_HEADER", "").strip()
    or "X-Forwarded-User,X-Forwarded-Preferred-Username,X-Auth-Request-User,Remote-User,X-Remote-User"
).split(",") if h.strip()]

ACTIONS = {
    "create": "Create",
    "sign_csr": "Sign CSR",
    "import": "Import",
    "delete": "Delete",
    "download_key": "Download key",
    "view_key": "View key",
    "download_key_encrypted": "Download encrypted key",
    "download_p12": "Download PKCS#12",
    "download_zip": "Download zip (with key)",
    "backup": "Download full backup",
    "remove_key": "Remove key (offline)",
    "notify": "Expiry notification",
    "notify_error": "Notification error",
}


def _who(req) -> tuple[str, str]:
    user = ""
    if req is not None:
        for h in USER_HEADERS:
            if req.headers.get(h):
                user = req.headers[h]
                break
        ip = (req.headers.get("X-Forwarded-For", "").split(",")[0].strip()
              or req.headers.get("X-Real-IP", "") or req.remote_addr or "")
    else:
        ip = ""
    return user, ip


def log(action: str, req=None, item: dict | None = None, **details) -> None:
    user, ip = _who(req)
    entry = {
        "ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "action": action,
        "user": user or ("system" if req is None else "-"),
        "ip": ip,
    }
    if item:
        entry["item_id"] = item["id"]
        entry["cn"] = item["info"]["cn"]
        entry["kind"] = item["kind"]
    entry.update({k: v for k, v in details.items() if v not in (None, "", [])})
    line = json.dumps(entry, ensure_ascii=False)
    with _lock:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    print(f"AUDIT {line}", flush=True)  # also to the container log (docker logs)


def read(limit: int = 500, item_id: str | None = None, action: str | None = None) -> list[dict]:
    if not LOG_FILE.is_file():
        return []
    buf: deque = deque(maxlen=limit)
    with open(LOG_FILE, encoding="utf-8") as f:
        for line in f:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if item_id and e.get("item_id") != item_id:
                continue
            if action and e.get("action") != action:
                continue
            buf.append(e)
    return list(reversed(buf))
