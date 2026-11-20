"""Audit napló: JSON Lines fájl a data könyvtárban (data/audit.log)."""
from __future__ import annotations

import datetime as dt
import json
import os
import threading
from collections import deque

from ca import DATA_DIR

LOG_FILE = DATA_DIR / "audit.log"
_lock = threading.Lock()

# A reverse proxy által küldött felhasználónév fejléc(ek), sorrendben próbálva.
USER_HEADERS = [h.strip() for h in (
    os.environ.get("AUDIT_USER_HEADER", "").strip()
    or "X-Forwarded-User,X-Forwarded-Preferred-Username,X-Auth-Request-User,Remote-User,X-Remote-User"
).split(",") if h.strip()]

ACTIONS = {
    "create": "Létrehozás",
    "sign_csr": "CSR aláírás",
    "import": "Import",
    "delete": "Törlés",
    "download_key": "Kulcs letöltése",
    "view_key": "Kulcs megtekintése",
    "download_key_encrypted": "Titkosított kulcs letöltése",
    "download_p12": "PKCS#12 letöltése",
    "download_zip": "Zip letöltése (kulccsal)",
    "backup": "Teljes mentés letöltése",
    "remove_key": "Kulcs eltávolítása (offline)",
    "notify": "Lejárati értesítés",
    "notify_error": "Értesítés hiba",
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
    print(f"AUDIT {line}", flush=True)  # a konténer logjába is (docker logs)


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
