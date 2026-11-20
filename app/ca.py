"""Local CA kezelés: tárolás, kulcs/CSR/cert generálás openssl-lel, import, export."""
from __future__ import annotations

import datetime as dt
import io
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
STORE = DATA_DIR / "store"
TRASH = DATA_DIR / "trash"

KINDS = {
    "root": "Root CA",
    "intermediate": "Intermediate CA",
    "server": "Szerver",
    "client": "mTLS kliens",
}
CA_KINDS = ("root", "intermediate")
LEAF_KINDS = ("server", "client")

KEY_TYPES = {
    "rsa2048": ("RSA 2048", ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"], "sha256"),
    "rsa3072": ("RSA 3072", ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"], "sha256"),
    "rsa4096": ("RSA 4096", ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096"], "sha256"),
    "ec256": ("ECDSA P-256", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"], "sha256"),
    "ec384": ("ECDSA P-384", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"], "sha384"),
}

DN_FIELDS = [("C", "Ország (C)"), ("ST", "Megye/állam (ST)"), ("L", "Település (L)"),
             ("O", "Szervezet (O)"), ("OU", "Szervezeti egység (OU)"), ("CN", "Common Name (CN)")]

ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,80}$")
DNS_RE = re.compile(r"^(\*\.)?([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)*"
                    r"[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")


class CAError(Exception):
    pass


# --------------------------------------------------------------------------- utils

def ensure_dirs() -> None:
    STORE.mkdir(parents=True, exist_ok=True)
    TRASH.mkdir(parents=True, exist_ok=True)


def run_openssl(args: list[str], cwd: Path | None = None, env: dict | None = None) -> bytes:
    full_env = {**os.environ, **(env or {})}
    p = subprocess.run(["openssl", *args], cwd=cwd, capture_output=True, env=full_env)
    if p.returncode != 0:
        msg = p.stderr.decode(errors="replace").strip()
        raise CAError(f"openssl {args[0]} hiba:\n{msg}")
    return p.stdout


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower().replace("*", "wildcard")).strip("-")
    return s[:40] or "cert"


def _new_id(kind: str, cn: str) -> str:
    return f"{kind}-{_slug(cn)}-{secrets.token_hex(3)}"


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _cnf_escape(value: str) -> str:
    if any(c in value for c in "\r\n\0"):
        raise CAError("A mezők nem tartalmazhatnak sortörést.")
    out = []
    for c in value:
        if c in '\\$#"\'':
            out.append("\\" + c)
        else:
            out.append(c)
    return "".join(out)


# --------------------------------------------------------------------------- cert info

def _attr(name: x509.Name, oid) -> str:
    a = name.get_attributes_for_oid(oid)
    return str(a[0].value) if a else ""


def name_fields(name: x509.Name) -> dict:
    from cryptography.x509.oid import NameOID as N
    return {
        "C": _attr(name, N.COUNTRY_NAME), "ST": _attr(name, N.STATE_OR_PROVINCE_NAME),
        "L": _attr(name, N.LOCALITY_NAME), "O": _attr(name, N.ORGANIZATION_NAME),
        "OU": _attr(name, N.ORGANIZATIONAL_UNIT_NAME), "CN": _attr(name, N.COMMON_NAME),
    }


def key_description(pub) -> str:
    if isinstance(pub, rsa.RSAPublicKey):
        return f"RSA {pub.key_size}"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"ECDSA {pub.curve.name}"
    return type(pub).__name__


def cert_info(cert: x509.Certificate) -> dict:
    sans: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        sans += [f"DNS:{v}" for v in san.get_values_for_type(x509.DNSName)]
        sans += [f"IP:{v}" for v in san.get_values_for_type(x509.IPAddress)]
        sans += [f"email:{v}" for v in san.get_values_for_type(x509.RFC822Name)]
        sans += [f"URI:{v}" for v in san.get_values_for_type(x509.UniformResourceIdentifier)]
    except x509.ExtensionNotFound:
        pass
    is_ca, pathlen = False, None
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        is_ca, pathlen = bc.ca, bc.path_length
    except x509.ExtensionNotFound:
        pass
    eku: list[str] = []
    try:
        for oid in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
            eku.append(oid._name if oid._name != "Unknown OID" else oid.dotted_string)
    except x509.ExtensionNotFound:
        pass
    nc_permitted, nc_excluded = name_constraints_of(cert)
    nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
    now = _now()
    days_left = (na - now).days
    if now < nb:
        status = "notyet"
    elif now > na:
        status = "expired"
    elif days_left < 30:
        status = "expiring"
    else:
        status = "valid"
    fp = cert.fingerprint(hashes.SHA256()).hex().upper()
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "cn": _attr(cert.subject, x509.oid.NameOID.COMMON_NAME) or cert.subject.rfc4514_string(),
        "dn": name_fields(cert.subject),
        "serial": format(cert.serial_number, "X"),
        "not_before": nb.strftime("%Y-%m-%d %H:%M UTC"),
        "not_after": na.strftime("%Y-%m-%d %H:%M UTC"),
        "not_after_dt": na,
        "days_left": days_left,
        "status": status,
        "sans": sans,
        "eku": eku,
        "is_ca": is_ca,
        "pathlen": pathlen,
        "self_signed": cert.subject == cert.issuer,
        "sha256": ":".join(fp[i:i + 2] for i in range(0, len(fp), 2)),
        "key": key_description(cert.public_key()),
        "nc_permitted": [f"{t}:{v}" for t, v in nc_permitted],
        "nc_excluded": [f"{t}:{v}" for t, v in nc_excluded],
    }


# --------------------------------------------------------------------------- name constraints

def _gn_list(subtrees) -> list[tuple[str, object]]:
    out = []
    for gn in subtrees or []:
        if isinstance(gn, x509.DNSName):
            out.append(("DNS", gn.value.lower()))
        elif isinstance(gn, x509.IPAddress):
            out.append(("IP", gn.value))  # ip_network
        elif isinstance(gn, x509.RFC822Name):
            out.append(("email", gn.value.lower()))
        elif isinstance(gn, x509.UniformResourceIdentifier):
            out.append(("URI", gn.value.lower()))
    return out


def name_constraints_of(cert: x509.Certificate):
    try:
        nc = cert.extensions.get_extension_for_class(x509.NameConstraints).value
    except x509.ExtensionNotFound:
        return [], []
    return _gn_list(nc.permitted_subtrees), _gn_list(nc.excluded_subtrees)


def parse_name_constraints(text: str) -> list[tuple[str, str]]:
    """Űrlap -> [(típus, érték)]. DNS: home.arpa, IP: 192.168.0.0/16, email: email:home.arpa"""
    out: list[tuple[str, str]] = []
    for t in [t for t in re.split(r"[\s,;]+", text or "") if t]:
        low = t.lower()
        if low.startswith("email:"):
            val = t[6:].lower()
            if not re.fullmatch(r"([^@\s]+@)?\.?[a-z0-9.-]+", val):
                raise CAError(f"Érvénytelen e-mail korlát: {val}")
            out.append(("email", val))
            continue
        if low.startswith("ip:"):
            t = t[3:]
        elif low.startswith("dns:"):
            t = t[4:]
        if "/" in t or low.startswith("ip:"):
            try:
                net = ipaddress.ip_network(t, strict=False)
            except ValueError:
                raise CAError(f"Érvénytelen IP tartomány: {t} (CIDR formátum kell, pl. 192.168.0.0/16)")
            out.append(("IP", str(net)))
            continue
        val = t.lower().rstrip(".")
        if val.startswith("*."):
            raise CAError(f"Name Constraint-ben nincs wildcard, a '{val[2:]}' az aldomaineket is lefedi.")
        if not DNS_RE.match(val.lstrip(".")):
            raise CAError(f"Érvénytelen DNS korlát: {val}")
        out.append(("DNS", val))
    return out


def _dns_ok(name: str, c: str) -> bool:
    name = name.lower()
    if c.startswith("."):
        return name.endswith(c)
    base = name[2:] if name.startswith("*.") else name
    return base == c or base.endswith("." + c)


def _email_ok(addr: str, c: str) -> bool:
    addr = addr.lower()
    if "@" in c:
        return addr == c
    host = addr.rsplit("@", 1)[-1]
    return host.endswith(c) if c.startswith(".") else host == c


def _name_matches(typ: str, val: str, c) -> bool:
    if typ == "DNS":
        return _dns_ok(val, c)
    if typ == "IP":
        try:
            return ipaddress.ip_address(val) in c
        except (ValueError, TypeError):
            return False
    if typ == "email":
        return _email_ok(val, c)
    return False


def check_name_constraints(parent_id: str, sans: list[tuple[str, str]], cn: str = "") -> None:
    """A kiállító lánc Name Constraints korlátainak ellenőrzése kiadás előtt (RFC 5280 szerint:
    egy névtípust csak akkor korlátoz a permitted lista, ha van benne ilyen típusú elem)."""
    ids = [parent_id] + chain_ids(parent_id)
    sans = list(sans)
    # OpenSSL a hostnévnek látszó CN-t is ellenőrzi, ha nincs DNS SAN
    if cn and "." in cn and DNS_RE.match(cn) and not any(t == "DNS" for t, _ in sans):
        sans.append(("DNS", cn.lower()))
    problems = []
    for cid in ids:
        cert = load_cert(cid)
        permitted, excluded = name_constraints_of(cert)
        cn = cert_info(cert)["cn"]
        for typ, val in sans:
            if typ not in ("DNS", "IP", "email"):
                continue
            same = [c for t, c in permitted if t == typ]
            if same and not any(_name_matches(typ, val, c) for c in same):
                problems.append(f"{typ}:{val} – nincs a(z) '{cn}' engedélyezett névterében "
                                f"({', '.join(str(c) for c in same)})")
            if any(_name_matches(typ, val, c) for t, c in excluded if t == typ):
                problems.append(f"{typ}:{val} – a(z) '{cn}' kizárta")
    if problems:
        raise CAError("Name Constraints sértés, a tanúsítványt a kliensek elutasítanák:\n"
                      + "\n".join(problems))


# --------------------------------------------------------------------------- storage

def item_dir(item_id: str) -> Path:
    if not ID_RE.match(item_id or ""):
        raise CAError("Érvénytelen azonosító.")
    return STORE / item_id


def load_cert(item_id: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate((item_dir(item_id) / "cert.pem").read_bytes())


def load_item(item_id: str) -> dict | None:
    try:
        d = item_dir(item_id)
    except CAError:
        return None
    if not (d / "meta.json").is_file():
        return None
    meta = json.loads((d / "meta.json").read_text())
    cert = x509.load_pem_x509_certificate((d / "cert.pem").read_bytes())
    meta["info"] = cert_info(cert)
    meta["has_key"] = (d / "key.pem").is_file()
    meta["has_csr"] = (d / "csr.pem").is_file()
    meta["has_cnf"] = (d / "openssl.cnf").is_file()
    meta["kind_label"] = KINDS.get(meta["kind"], meta["kind"])
    return meta


def list_items() -> list[dict]:
    ensure_dirs()
    items = []
    for d in STORE.iterdir():
        if d.is_dir() and not d.name.startswith("."):
            it = load_item(d.name)
            if it:
                items.append(it)
    items.sort(key=lambda i: i["created"])
    return items


def list_cas(with_key_only: bool = False) -> list[dict]:
    return [i for i in list_items()
            if i["kind"] in CA_KINDS and (i["has_key"] or not with_key_only)]


def _save_meta(d: Path, meta: dict) -> None:
    (d / "meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False))


def chain_ids(item_id: str) -> list[str]:
    """A kiállítók listája felfelé (szülő, nagyszülő, ...)."""
    out, seen = [], {item_id}
    meta = load_item(item_id)
    pid = meta.get("parent_id") if meta else None
    while pid and pid not in seen:
        seen.add(pid)
        parent = load_item(pid)
        if not parent:
            break
        out.append(pid)
        pid = parent.get("parent_id")
    return out


def chain_pem(item_id: str, include_root: bool = True) -> bytes:
    parts = []
    for cid in chain_ids(item_id):
        it = load_item(cid)
        if it["kind"] == "root" and not include_root:
            continue
        parts.append((item_dir(cid) / "cert.pem").read_bytes())
    return b"".join(parts)


def children_of(item_id: str) -> list[dict]:
    return [i for i in list_items() if i.get("parent_id") == item_id]


def delete_item(item_id: str) -> None:
    d = item_dir(item_id)
    if not d.is_dir():
        raise CAError("Nincs ilyen elem.")
    if children_of(item_id):
        raise CAError("Ez a CA még tanúsítványokat tartalmaz, előbb azokat töröld.")
    TRASH.mkdir(parents=True, exist_ok=True)
    shutil.move(str(d), TRASH / f"{item_id}-{_now().strftime('%Y%m%d%H%M%S')}")


# --------------------------------------------------------------------------- validation

def _clean_dn(form: dict) -> dict:
    dn = {k: (form.get(k) or "").strip() for k, _ in DN_FIELDS}
    if not dn["CN"]:
        raise CAError("A Common Name (CN) kötelező.")
    if dn["C"] and not re.fullmatch(r"[A-Za-z]{2}", dn["C"]):
        raise CAError("Az ország (C) kétbetűs kód legyen, pl. HU.")
    dn["C"] = dn["C"].upper()
    for k, v in dn.items():
        if len(v) > 64:
            raise CAError(f"A(z) {k} mező legfeljebb 64 karakter lehet.")
    email = (form.get("email") or "").strip()
    if email:
        if not re.fullmatch(r"[^@\s]+@[^@\s]+", email):
            raise CAError("Érvénytelen e-mail cím.")
        dn["emailAddress"] = email
    return dn


def _clean_days(form: dict, default: int) -> int:
    try:
        days = int(form.get("days") or default)
    except ValueError:
        raise CAError("Az érvényesség napokban megadott egész szám legyen.")
    if not 1 <= days <= 36500:
        raise CAError("Az érvényesség 1 és 36500 nap között lehet.")
    return days


def _clean_pathlen(form: dict) -> int | None:
    v = (form.get("pathlen") or "").strip()
    if v == "":
        return None
    if not v.isdigit() or int(v) > 10:
        raise CAError("A pathlen 0-10 közötti szám, vagy üres (korlátlan).")
    return int(v)


def parse_sans(text: str, cn: str | None = None, add_cn: bool = False) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    tokens = [t for t in re.split(r"[\s,;]+", text or "") if t]
    if add_cn and cn:
        tokens.insert(0, cn)
    for t in tokens:
        low = t.lower()
        if low.startswith("dns:"):
            typ, val = "DNS", t[4:]
        elif low.startswith("ip:"):
            typ, val = "IP", t[3:]
        elif low.startswith("email:"):
            typ, val = "email", t[6:]
        elif low.startswith("uri:"):
            typ, val = "URI", t[4:]
        else:
            try:
                ipaddress.ip_address(t)
                typ, val = "IP", t
            except ValueError:
                typ, val = ("email", t) if "@" in t else ("DNS", t)
        if typ == "DNS":
            val = val.lower().rstrip(".")
            if not DNS_RE.match(val):
                if add_cn and t == cn and not out:
                    continue  # a CN nem hostnév -> nem kerül a SAN-ba
                raise CAError(f"Érvénytelen DNS név: {val}")
        elif typ == "IP":
            try:
                val = str(ipaddress.ip_address(val))
            except ValueError:
                raise CAError(f"Érvénytelen IP cím: {val}")
        elif typ == "email" and not re.fullmatch(r"[^@\s]+@[^@\s]+", val):
            raise CAError(f"Érvénytelen e-mail: {val}")
        elif typ == "URI" and ":" not in val:
            raise CAError(f"Érvénytelen URI: {val}")
        if (typ, val) not in out:
            out.append((typ, val))
    return out


# --------------------------------------------------------------------------- config

def build_config(kind: str, dn: dict, key_type: str, *, sans=None, pathlen=None,
                 client_auth: bool = False, name_constraints=None) -> str:
    from_csr = key_type not in KEY_TYPES  # külső CSR: key_type = kulcs leírása, pl. "RSA 2048"
    if from_csr:
        label, md, is_rsa = key_type, "sha256", key_type.startswith("RSA")
    else:
        label, _, md = KEY_TYPES[key_type]
        is_rsa = key_type.startswith("rsa")
    L = [f"# Local CA Manager - {KINDS[kind]}",
         f"# Generálva: {_now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
         f"# Kulcs: {label}"]
    if from_csr:
        L += ["# Külső CSR aláírása: a subject a CSR-ből jön, a [ req ] / [ dn ] rész csak dokumentáció.",
              "# A CSR-ben kért kiterjesztések NEM kerülnek át, csak az alábbi aláíró szekcióban lévők."]
    L += ["", "[ req ]"]
    if is_rsa and not from_csr:
        L.append(f"default_bits        = {label.split()[1]}")
    L += [f"default_md          = {md}",
          "prompt              = no",
          "encrypt_key         = no",
          "utf8                = yes",
          "string_mask         = utf8only",
          "distinguished_name  = dn"]
    if kind == "root":
        L.append("x509_extensions     = v3_ca")
    elif kind == "intermediate":
        L.append("req_extensions      = v3_intermediate_ca_req")
    else:
        L.append("req_extensions      = req_ext")
    L += ["", "[ dn ]"]
    for k in ("C", "ST", "L", "O", "OU", "CN", "emailAddress"):
        if dn.get(k):
            L.append(f"{k} = {_cnf_escape(dn[k])}")
    L.append("")

    pl = f", pathlen:{pathlen}" if pathlen is not None else ""
    if kind == "root":
        L += ["[ v3_ca ]",
              f"basicConstraints = critical, CA:true{pl}",
              "keyUsage = critical, keyCertSign, cRLSign",
              "subjectKeyIdentifier = hash",
              "authorityKeyIdentifier = keyid:always", ""]
    elif kind == "intermediate":
        nc = ["nameConstraints = critical, @name_constraints"] if name_constraints else []
        L += ["# CSR-be kerülő kiterjesztések",
              "[ v3_intermediate_ca_req ]",
              f"basicConstraints = critical, CA:true{pl}",
              "keyUsage = critical, keyCertSign, cRLSign",
              "subjectKeyIdentifier = hash", *nc, "",
              "# Aláíráskor használt kiterjesztések (openssl x509 -req -extensions v3_intermediate_ca)",
              "[ v3_intermediate_ca ]",
              f"basicConstraints = critical, CA:true{pl}",
              "keyUsage = critical, keyCertSign, cRLSign",
              "subjectKeyIdentifier = hash",
              "authorityKeyIdentifier = keyid:always", *nc, ""]
        if name_constraints:
            L += ["# Ez a CA csak az alábbi névterekre adhat ki érvényes tanúsítványt",
                  "[ name_constraints ]"]
            counters: dict[str, int] = {}
            for typ, val in name_constraints:
                n = counters.get(typ, 0)
                counters[typ] = n + 1
                if typ == "IP":
                    net = ipaddress.ip_network(val)
                    val = f"{net.network_address}/{net.netmask}"
                L.append(f"permitted;{typ}.{n} = {_cnf_escape(val)}")
            L.append("")
    else:
        ku = "digitalSignature, keyEncipherment" if is_rsa else "digitalSignature"
        if kind == "server":
            eku = "serverAuth, clientAuth" if client_auth else "serverAuth"
            section = "server_cert"
        else:
            eku = "clientAuth"
            section = "client_cert"
        L += ["[ req_ext ]"]
        if sans:
            L.append("subjectAltName = @alt_names")
        L += ["", f"# Aláíráskor használt kiterjesztések (openssl x509 -req -extensions {section})",
              f"[ {section} ]",
              "basicConstraints = critical, CA:false",
              f"keyUsage = critical, {ku}",
              f"extendedKeyUsage = {eku}",
              "subjectKeyIdentifier = hash",
              "authorityKeyIdentifier = keyid, issuer"]
        if sans:
            L.append("subjectAltName = @alt_names")
        L.append("")
        if sans:
            L.append("[ alt_names ]")
            counters: dict[str, int] = {}
            for typ, val in sans:
                counters[typ] = counters.get(typ, 0) + 1
                L.append(f"{typ}.{counters[typ]} = {_cnf_escape(val)}")
            L.append("")
    return "\n".join(L)


def ext_section(kind: str) -> str:
    return {"root": "v3_ca", "intermediate": "v3_intermediate_ca",
            "server": "server_cert", "client": "client_cert"}[kind]


# --------------------------------------------------------------------------- generate

def _serial() -> str:
    return "0x" + format(secrets.randbits(127) | (1 << 120), "x")


def create(kind: str, form: dict) -> tuple[str, list[str]]:
    """Új root/intermediate/server/client cert generálása. Visszaad: (id, figyelmeztetések)."""
    if kind not in KINDS:
        raise CAError("Ismeretlen típus.")
    ensure_dirs()
    warnings: list[str] = []
    dn = _clean_dn(form)
    key_type = form.get("key_type") or "rsa2048"
    if key_type not in KEY_TYPES:
        raise CAError("Ismeretlen kulcstípus.")
    default_days = {"root": 3650, "intermediate": 1825, "server": 397, "client": 365}[kind]
    days = _clean_days(form, default_days)

    pathlen = None
    sans: list[tuple[str, str]] = []
    client_auth = False
    parent = None
    name_constraints: list[tuple[str, str]] = []
    if kind == "root":
        pathlen = _clean_pathlen(form)
    else:
        parent = load_item(form.get("parent_id") or "")
        if not parent or parent["kind"] not in CA_KINDS:
            raise CAError("Válassz kiállító CA-t.")
        if not parent["has_key"]:
            raise CAError("A kiválasztott CA-hoz nincs privát kulcs, nem tud aláírni.")
        pi = parent["info"]
        if kind == "intermediate":
            pathlen = _clean_pathlen(form)
            name_constraints = parse_name_constraints(form.get("name_constraints", ""))
            if pi["pathlen"] == 0:
                raise CAError("A kiválasztott CA pathlen:0, nem írhat alá újabb CA-t.")
            if pi["pathlen"] is not None and (pathlen is None or pathlen >= pi["pathlen"]):
                pathlen = pi["pathlen"] - 1
                warnings.append(f"A pathlen a szülő korlátja miatt {pathlen}-ra lett állítva.")
        if kind == "server":
            sans = parse_sans(form.get("sans", ""), dn["CN"], add_cn=True)
            if not sans:
                raise CAError("Szerver tanúsítványhoz legalább egy DNS név vagy IP cím kell.")
            client_auth = bool(form.get("client_auth"))
            if days > 825:
                warnings.append("Apple eszközök a 825 napnál hosszabb szerver certeket elutasítják.")
        elif kind == "client":
            sans = parse_sans(form.get("sans", ""))
            if dn.get("emailAddress") and ("email", dn["emailAddress"]) not in sans:
                sans.insert(0, ("email", dn["emailAddress"]))
        if kind in LEAF_KINDS:
            check_name_constraints(parent["id"], sans, dn["CN"])
        if _now() + dt.timedelta(days=days) > pi["not_after_dt"]:
            warnings.append(f"Az új tanúsítvány tovább lenne érvényes, mint a kiállító CA "
                            f"({pi['not_after']}); a lánc a CA lejártakor érvénytelen lesz.")

    item_id = _new_id(kind, dn["CN"])
    tmp = Path(tempfile.mkdtemp(prefix=".tmp-", dir=STORE))
    try:
        cnf = tmp / "openssl.cnf"
        cnf.write_text(build_config(kind, dn, key_type, sans=sans, pathlen=pathlen,
                                    client_auth=client_auth, name_constraints=name_constraints))
        os.chmod(tmp, 0o700)
        _, keyargs, md = KEY_TYPES[key_type]
        run_openssl(["genpkey", *keyargs, "-out", "key.pem"], cwd=tmp)
        os.chmod(tmp / "key.pem", 0o600)
        if kind == "root":
            run_openssl(["req", "-new", "-x509", "-config", "openssl.cnf", "-key", "key.pem",
                         "-days", str(days), f"-{md}", "-set_serial", _serial(),
                         "-extensions", "v3_ca", "-out", "cert.pem"], cwd=tmp)
        else:
            pdir = item_dir(parent["id"])
            run_openssl(["req", "-new", "-config", "openssl.cnf", "-key", "key.pem",
                         "-out", "csr.pem"], cwd=tmp)
            run_openssl(["x509", "-req", "-in", "csr.pem",
                         "-CA", str(pdir / "cert.pem"), "-CAkey", str(pdir / "key.pem"),
                         "-set_serial", _serial(), "-days", str(days), f"-{md}",
                         "-extfile", "openssl.cnf", "-extensions", ext_section(kind),
                         "-out", "cert.pem"], cwd=tmp)
        meta = {
            "id": item_id, "kind": kind, "source": "generated",
            "parent_id": parent["id"] if parent else None,
            "created": _now().isoformat(timespec="seconds"),
            "params": {**{k: dn.get(k, "") for k, _ in DN_FIELDS},
                       "email": dn.get("emailAddress", ""), "key_type": key_type,
                       "days": days, "pathlen": "" if pathlen is None else pathlen,
                       "sans": "\n".join(f"{t}:{v}" for t, v in sans
                                         if not (kind == "server" and v == dn["CN"])),
                       "client_auth": client_auth,
                       "name_constraints": "\n".join(v if t == "DNS" else f"{t}:{v}"
                                                     for t, v in name_constraints)},
        }
        _save_meta(tmp, meta)
        os.chmod(tmp, 0o755)
        tmp.rename(STORE / item_id)
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return item_id, warnings


# --------------------------------------------------------------------------- sign external CSR

def load_csr(data: bytes) -> x509.CertificateSigningRequest:
    data = data.strip()
    try:
        csr = (x509.load_pem_x509_csr(data) if data.startswith(b"-----")
               else x509.load_der_x509_csr(data))
    except Exception:
        raise CAError("Nem sikerült a CSR-t beolvasni (PEM vagy DER kell).")
    if not csr.is_signature_valid:
        raise CAError("A CSR aláírása érvénytelen (sérült vagy módosított CSR).")
    return csr


def csr_summary(data: bytes) -> dict:
    csr = load_csr(data)
    sans = []
    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        sans += [f"DNS:{v}" for v in san.get_values_for_type(x509.DNSName)]
        sans += [f"IP:{v}" for v in san.get_values_for_type(x509.IPAddress)]
        sans += [f"email:{v}" for v in san.get_values_for_type(x509.RFC822Name)]
        sans += [f"URI:{v}" for v in san.get_values_for_type(x509.UniformResourceIdentifier)]
    except x509.ExtensionNotFound:
        pass
    is_ca = False
    try:
        is_ca = csr.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        pass
    return {"subject": csr.subject.rfc4514_string(), "dn": name_fields(csr.subject),
            "cn": _attr(csr.subject, x509.oid.NameOID.COMMON_NAME),
            "key": key_description(csr.public_key()), "sans": sans, "requests_ca": is_ca}


def sign_csr(csr_data: bytes, form: dict) -> tuple[str, list[str]]:
    """Kívül készült CSR aláírása szerver vagy kliens certként (privát kulcs nélkül tárolódik)."""
    ensure_dirs()
    warnings: list[str] = []
    kind = form.get("kind") or "server"
    if kind not in LEAF_KINDS:
        raise CAError("CSR-ből csak szerver vagy mTLS kliens tanúsítvány adható ki.")
    csr = load_csr(csr_data)
    summary = csr_summary(csr_data)
    pub = csr.public_key()
    if isinstance(pub, rsa.RSAPublicKey) and pub.key_size < 2048:
        raise CAError("2048 bitnél rövidebb RSA kulcs nem írható alá.")
    if summary["requests_ca"]:
        warnings.append("A CSR CA:true-t kért; ez figyelmen kívül maradt, leaf cert készült.")

    parent = load_item(form.get("parent_id") or "")
    if not parent or parent["kind"] not in CA_KINDS:
        raise CAError("Válassz kiállító CA-t.")
    if not parent["has_key"]:
        raise CAError("A kiválasztott CA-hoz nincs privát kulcs, nem tud aláírni.")
    days = _clean_days(form, 397 if kind == "server" else 365)

    cn = summary["cn"]
    # SAN: a CSR-ben kértek (ha engedélyezett) + az űrlapon megadottak
    san_text = form.get("sans", "")
    if form.get("use_csr_sans"):
        san_text = "\n".join(summary["sans"]) + "\n" + san_text
    sans = parse_sans(san_text, cn, add_cn=(kind == "server" and bool(cn)))
    client_auth = False
    if kind == "server":
        if not sans:
            raise CAError("Szerver tanúsítványhoz legalább egy DNS név vagy IP cím kell "
                          "(a CSR-ben sincs használható SAN / CN).")
        client_auth = bool(form.get("client_auth"))
        if days > 825:
            warnings.append("Apple eszközök a 825 napnál hosszabb szerver certeket elutasítják.")
    check_name_constraints(parent["id"], sans, cn)
    if _now() + dt.timedelta(days=days) > parent["info"]["not_after_dt"]:
        warnings.append(f"Az új tanúsítvány tovább lenne érvényes, mint a kiállító CA "
                        f"({parent['info']['not_after']}).")

    name = cn or (sans[0][1] if sans else "csr")
    item_id = _new_id(kind, name)
    tmp = Path(tempfile.mkdtemp(prefix=".tmp-", dir=STORE))
    try:
        (tmp / "csr.pem").write_bytes(csr.public_bytes(serialization.Encoding.PEM))
        dn = {k: v for k, v in summary["dn"].items()}
        (tmp / "openssl.cnf").write_text(build_config(kind, dn, summary["key"], sans=sans,
                                                      client_auth=client_auth))
        pdir = item_dir(parent["id"])
        run_openssl(["x509", "-req", "-in", "csr.pem",
                     "-CA", str(pdir / "cert.pem"), "-CAkey", str(pdir / "key.pem"),
                     "-set_serial", _serial(), "-days", str(days), "-sha256",
                     "-extfile", "openssl.cnf", "-extensions", ext_section(kind),
                     "-out", "cert.pem"], cwd=tmp)
        _save_meta(tmp, {
            "id": item_id, "kind": kind, "source": "csr", "parent_id": parent["id"],
            "created": _now().isoformat(timespec="seconds"),
            "params": {"days": days, "client_auth": client_auth,
                       "sans": "\n".join(f"{t}:{v}" for t, v in sans if v != cn)},
        })
        os.chmod(tmp, 0o755)
        tmp.rename(STORE / item_id)
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return item_id, warnings


# --------------------------------------------------------------------------- import

def _pub_der(obj) -> bytes:
    return obj.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)


def _find_by_fingerprint(cert: x509.Certificate) -> dict | None:
    fp = cert.fingerprint(hashes.SHA256())
    for it in list_items():
        if load_cert(it["id"]).fingerprint(hashes.SHA256()) == fp:
            return it
    return None


def _find_issuer(cert: x509.Certificate, exclude: str | None = None) -> str | None:
    for it in list_cas():
        if it["id"] == exclude:
            continue
        ca = load_cert(it["id"])
        if ca.subject != cert.issuer:
            continue
        try:
            cert.verify_directly_issued_by(ca)
            return it["id"]
        except Exception:
            continue
    return None


def _relink_orphans() -> None:
    for it in list_items():
        if it["kind"] != "root" and not it.get("parent_id") and not it["info"]["self_signed"]:
            pid = _find_issuer(load_cert(it["id"]), exclude=it["id"])
            if pid:
                d = item_dir(it["id"])
                meta = json.loads((d / "meta.json").read_text())
                meta["parent_id"] = pid
                _save_meta(d, meta)


def _leaf_kind(c: x509.Certificate) -> str:
    """Nem-CA cert típusa az EKU alapján (EKU nélkül: SAN DNS/IP -> szerver, különben kliens)."""
    info = cert_info(c)
    if "serverAuth" in info["eku"]:
        return "server"
    if "clientAuth" in info["eku"]:
        return "client"
    return "server" if any(s.startswith(("DNS:", "IP:")) for s in info["sans"]) else "client"


def _load_cert_bundle(data: bytes, password: str | None):
    """PEM (több cert is) / DER / PKCS#12 -> (certek, p12-ből jövő kulcs vagy None)."""
    if b"-----BEGIN CERTIFICATE-----" in data:
        try:
            return x509.load_pem_x509_certificates(data), None
        except Exception:
            raise CAError("Nem sikerült a PEM tanúsítványt beolvasni.")
    try:
        return [x509.load_der_x509_certificate(data)], None
    except Exception:
        pass
    from cryptography.hazmat.primitives.serialization import pkcs12
    try:
        key, cert, extra = pkcs12.load_key_and_certificates(
            data, password.encode() if password else None)
    except ValueError:
        raise CAError("Nem sikerült beolvasni: PEM, DER vagy PKCS#12 kell. PKCS#12 esetén "
                      "ellenőrizd a jelszót (Kulcs / PKCS#12 jelszava mező).")
    certs = ([cert] if cert else []) + list(extra or [])
    if not certs:
        raise CAError("A PKCS#12 fájl nem tartalmaz tanúsítványt.")
    return certs, key


def import_ca(cert_data: bytes, key_data: bytes | None, password: str | None) -> tuple[list[str], list[str]]:
    """Tanúsítvány(ok) importálása: CA (root/intermediate) és sima szerver/kliens cert is,
    akár teljes lánc vagy PKCS#12, opcionális privát kulccsal."""
    ensure_dirs()
    certs, key = _load_cert_bundle(cert_data, password)

    if key_data and key_data.strip():
        pw = password.encode() if password else None
        try:
            key = serialization.load_pem_private_key(key_data, password=pw)
        except TypeError:
            raise CAError("A kulcs jelszóval védett, add meg a jelszót.")
        except ValueError:
            try:
                key = serialization.load_der_private_key(key_data, password=pw)
            except Exception:
                raise CAError("Nem sikerült a privát kulcsot beolvasni (rossz jelszó vagy formátum?).")

    key_target = None
    if key is not None:
        kp = key.public_key().public_bytes(serialization.Encoding.DER,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)
        matches = [c for c in certs if _pub_der(c) == kp]
        if not matches:
            raise CAError("A privát kulcs egyik megadott tanúsítványhoz sem tartozik.")
        key_target = matches[0]
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()) if key is not None else None

    # Sorrend: önaláírt CA-k, többi CA, végül a sima certek – így a gyerekek megtalálják a szülőt.
    def _order(c):
        is_ca = cert_info(c)["is_ca"]
        return 0 if (is_ca and c.subject == c.issuer) else 1 if is_ca else 2
    certs.sort(key=_order)
    imported, messages = [], []
    pending = list(certs)
    for _ in range(len(pending) + 1):
        if not pending:
            break
        rest = []
        for c in pending:
            existing = _find_by_fingerprint(c)
            cn = cert_info(c)["cn"]
            if existing:
                if c is key_target and not existing["has_key"]:
                    _write_private(item_dir(existing["id"]) / "key.pem", key_pem)
                    messages.append(f"'{cn}' már létezett, a privát kulcs hozzáadva.")
                    imported.append(existing["id"])
                else:
                    messages.append(f"'{cn}' már létezik, kihagyva.")
                continue
            self_signed = c.subject == c.issuer
            info = cert_info(c)
            # Az `openssl req -x509`-cel készült önaláírt szerver certek gyakran CA:TRUE-k;
            # valódi root CA-ban viszont nincs DNS/IP SAN -> ilyenkor sima certként kezeljük.
            is_ca = info["is_ca"] and not (
                self_signed and any(x.startswith(("DNS:", "IP:")) for x in info["sans"]))
            parent_id = None if self_signed else _find_issuer(c)
            if not self_signed and parent_id is None and any(
                    o.subject == c.issuer for o in pending if o is not c):
                rest.append(c)  # a szülő ugyanebben a csomagban van, később
                continue
            if is_ca:
                kind = "root" if self_signed else "intermediate"
            else:
                kind = _leaf_kind(c)
            item_id = _new_id(kind, cn)
            d = STORE / item_id
            d.mkdir()
            (d / "cert.pem").write_bytes(c.public_bytes(serialization.Encoding.PEM))
            if c is key_target:
                _write_private(d / "key.pem", key_pem)
            _save_meta(d, {"id": item_id, "kind": kind, "source": "imported",
                           "parent_id": parent_id,
                           "created": _now().isoformat(timespec="seconds"), "params": {}})
            imported.append(item_id)
            if self_signed and not is_ca:
                messages.append(f"'{cn}' önaláírt (nem CA által kiadott) tanúsítvány.")
            elif not self_signed and parent_id is None:
                messages.append(f"'{cn}' kiállítója nem található; ha később importálod a CA-t, "
                                f"automatikusan összekapcsolódnak.")
        if len(rest) == len(pending):
            break
        pending = rest
    _relink_orphans()
    return imported, messages


# --------------------------------------------------------------------------- views / export

def openssl_text(item_id: str, what: str) -> str:
    d = item_dir(item_id)
    if what == "cert":
        out = run_openssl(["x509", "-in", str(d / "cert.pem"), "-noout", "-text"])
    elif what == "csr":
        out = run_openssl(["req", "-in", str(d / "csr.pem"), "-noout", "-text"])
    else:
        raise CAError("Ismeretlen nézet.")
    return out.decode(errors="replace")


def read_file(item_id: str, name: str) -> bytes:
    allowed = {"cert.pem", "key.pem", "csr.pem", "openssl.cnf"}
    if name not in allowed:
        raise CAError("Ismeretlen fájl.")
    p = item_dir(item_id) / name
    if not p.is_file():
        raise CAError("A fájl nem létezik ehhez az elemhez.")
    return p.read_bytes()


def cert_der(item_id: str) -> bytes:
    return load_cert(item_id).public_bytes(serialization.Encoding.DER)


def fullchain(item_id: str) -> bytes:
    """Leaf + intermediate(ek), root nélkül (nginx / traefik / haproxy)."""
    return read_file(item_id, "cert.pem") + chain_pem(item_id, include_root=False)


def pkcs12(item_id: str, password: str, legacy: bool) -> bytes:
    d = item_dir(item_id)
    if not (d / "key.pem").is_file():
        raise CAError("Nincs privát kulcs ehhez a tanúsítványhoz.")
    if not password:
        raise CAError("PKCS#12 exporthoz jelszó kell.")
    cn = load_item(item_id)["info"]["cn"]
    with tempfile.TemporaryDirectory() as tmp:
        chainf = Path(tmp) / "chain.pem"
        chainf.write_bytes(chain_pem(item_id))
        args = ["pkcs12", "-export", "-inkey", str(d / "key.pem"), "-in", str(d / "cert.pem"),
                "-name", cn, "-passout", "env:P12PASS", "-out", str(Path(tmp) / "out.p12")]
        if chainf.stat().st_size:
            args += ["-certfile", str(chainf)]
        if legacy:
            args += ["-keypbe", "PBE-SHA1-3DES", "-certpbe", "PBE-SHA1-3DES", "-macalg", "sha1"]
        run_openssl(args, env={"P12PASS": password})
        return (Path(tmp) / "out.p12").read_bytes()


def zip_bundle(item_id: str) -> bytes:
    d = item_dir(item_id)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name in ("cert.pem", "key.pem", "csr.pem", "openssl.cnf", "meta.json"):
            if (d / name).is_file():
                z.write(d / name, name)
        ch = chain_pem(item_id)
        if ch:
            z.writestr("chain.pem", ch)
            z.writestr("fullchain.pem", fullchain(item_id))
    return buf.getvalue()


def backup_zip() -> bytes:
    """Teljes store mentése."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(STORE.rglob("*")):
            if p.is_file() and not p.relative_to(STORE).parts[0].startswith("."):
                z.write(p, p.relative_to(STORE))
    return buf.getvalue()


# --------------------------------------------------------------------------- offline key

def encrypted_key(item_id: str, password: str) -> bytes:
    """Privát kulcs AES-256-tal titkosított PEM-ként (offline tároláshoz)."""
    p = item_dir(item_id) / "key.pem"
    if not p.is_file():
        raise CAError("Nincs privát kulcs ehhez az elemhez.")
    if len(password or "") < 8:
        raise CAError("A jelszó legalább 8 karakter legyen.")
    return run_openssl(["pkey", "-in", str(p), "-aes256", "-passout", "env:KEYPASS"],
                       env={"KEYPASS": password})


def remove_key(item_id: str) -> None:
    """CA privát kulcs végleges eltávolítása (offline CA). Visszahozható: Import oldalon
    a cert + kulcs újraimportálásával."""
    it = load_item(item_id)
    if not it or it["kind"] not in CA_KINDS:
        raise CAError("Kulcs eltávolítása csak CA-nál lehetséges.")
    p = item_dir(item_id) / "key.pem"
    if not p.is_file():
        raise CAError("Ehhez a CA-hoz már nincs kulcs tárolva.")
    size = p.stat().st_size
    with open(p, "r+b") as f:  # felülírás törlés előtt
        f.write(secrets.token_bytes(size))
        f.flush()
        os.fsync(f.fileno())
    p.unlink()


# --------------------------------------------------------------------------- expiry

def expiring_items(days: int, include_expired_days: int = 7) -> list[dict]:
    """A `days` napon belül lejáró (vagy legfeljebb `include_expired_days` napja lejárt) certek.
    Kihagyja a már megújítottakat (azonos típus + CN + kiállító, későbbi lejárattal)."""
    items = list_items()
    out = []
    for it in items:
        dl = it["info"]["days_left"]
        if not (-include_expired_days <= dl <= days):
            continue
        renewed = any(o["id"] != it["id"] and o["kind"] == it["kind"]
                      and o["info"]["cn"] == it["info"]["cn"]
                      and o.get("parent_id") == it.get("parent_id")
                      and o["info"]["not_after_dt"] > it["info"]["not_after_dt"]
                      for o in items)
        if not renewed:
            out.append(it)
    out.sort(key=lambda i: i["info"]["not_after_dt"])
    return out


def metrics_text() -> str:
    """Prometheus text formátum."""
    def esc(v: str) -> str:
        return v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")
    lines = ["# HELP local_ca_cert_not_after_seconds Tanúsítvány lejárata (unix idő).",
             "# TYPE local_ca_cert_not_after_seconds gauge"]
    items = list_items()
    for it in items:
        lbl = (f'id="{esc(it["id"])}",cn="{esc(it["info"]["cn"])}",kind="{it["kind"]}",'
               f'source="{it["source"]}",has_key="{str(it["has_key"]).lower()}"')
        lines.append(f'local_ca_cert_not_after_seconds{{{lbl}}} {int(it["info"]["not_after_dt"].timestamp())}')
    lines += ["# HELP local_ca_certs_total Tárolt tanúsítványok száma típusonként.",
              "# TYPE local_ca_certs_total gauge"]
    for k in KINDS:
        lines.append(f'local_ca_certs_total{{kind="{k}"}} {sum(1 for i in items if i["kind"] == k)}')
    return "\n".join(lines) + "\n"
