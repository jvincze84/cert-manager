import os

from flask import (Flask, Response, abort, flash, redirect, render_template, request,
                   url_for)

import audit
import ca
import notify

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(32)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

DEFAULT_DN = {
    "C": os.environ.get("DEFAULT_C", ""), "ST": os.environ.get("DEFAULT_ST", ""),
    "L": os.environ.get("DEFAULT_L", ""), "O": os.environ.get("DEFAULT_O", ""),
    "OU": "", "CN": "",
}


@app.context_processor
def globals_():
    return {"KINDS": ca.KINDS, "KEY_TYPES": ca.KEY_TYPES, "DN_FIELDS": ca.DN_FIELDS,
            "ACTIONS": audit.ACTIONS}


def _download(data: bytes, filename: str, mimetype: str = "application/x-pem-file"):
    return Response(data, mimetype=mimetype,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.get("/")
def index():
    items = ca.list_items()
    by_parent: dict = {}
    for it in items:
        by_parent.setdefault(it.get("parent_id"), []).append(it)
    ids = {i["id"] for i in items}
    roots = [i for i in items if i["kind"] in ca.CA_KINDS
             and (not i.get("parent_id") or i["parent_id"] not in ids)]
    leaves = [i for i in items if i["kind"] in ca.LEAF_KINDS]
    leaves.sort(key=lambda i: i["created"], reverse=True)
    # régi, már megújított példányok (azonos típus + CN + kiállító, van későbbi lejáratú)
    superseded = {i["id"] for i in leaves if any(
        o["id"] != i["id"] and o["kind"] == i["kind"] and o["info"]["cn"] == i["info"]["cn"]
        and o.get("parent_id") == i.get("parent_id")
        and o["info"]["not_after_dt"] > i["info"]["not_after_dt"] for o in leaves)}
    ca_names = {i["id"]: i["info"]["cn"] for i in items if i["kind"] in ca.CA_KINDS}
    issuers = sorted({i.get("parent_id") or "" for i in leaves},
                     key=lambda p: (p == "", ca_names.get(p, "").lower()))
    cfg = notify.config()
    expiring = ca.expiring_items(cfg["days"])
    online_roots = [i for i in items if i["kind"] == "root" and i["has_key"]
                    and by_parent.get(i["id"])]
    return render_template("index.html", roots=roots, by_parent=by_parent, leaves=leaves,
                           expiring=expiring, notify_days=cfg["days"], online_roots=online_roots,
                           superseded=superseded, ca_names=ca_names, issuers=issuers)


@app.route("/new/<kind>", methods=["GET", "POST"])
def new(kind):
    if kind not in ca.KINDS:
        abort(404)
    cas = ca.list_cas(with_key_only=True)
    if kind == "intermediate":
        cas = [c for c in cas if c["info"]["pathlen"] != 0]
    if request.method == "POST":
        form = request.form.to_dict()
        try:
            item_id, warnings = ca.create(kind, form)
            audit.log("create", request, ca.load_item(item_id))
        except ca.CAError as e:
            flash(str(e), "error")
            return render_template("new.html", kind=kind, form=form, cas=cas), 400
        for w in warnings:
            flash(w, "warn")
        flash(f"{ca.KINDS[kind]} tanúsítvány létrehozva.", "ok")
        return redirect(url_for("item", item_id=item_id))

    # előtöltés: ?from=<id> (újrakiadás) vagy ?parent=<id>
    form = dict(DEFAULT_DN)
    src = ca.load_item(request.args.get("from", ""))
    if src and src["kind"] == kind:
        form.update({k: str(v) for k, v in src.get("params", {}).items()})
        form["client_auth"] = "1" if src["params"].get("client_auth") else ""
        form["parent_id"] = src.get("parent_id") or ""
        if src["source"] == "imported":
            form.update(src["info"]["dn"])
    elif request.args.get("parent"):
        form["parent_id"] = request.args["parent"]
    if kind != "root" and not form.get("parent_id") and cas:
        # alapértelmezés: a legutóbbi intermediate (leafnél), különben az első CA
        pref = [c for c in cas if c["kind"] == "intermediate"] if kind in ca.LEAF_KINDS else []
        form["parent_id"] = (pref or cas)[-1]["id"]
    if not (src and src["kind"] == kind):
        parent = ca.load_item(form.get("parent_id", ""))
        if parent:
            for k in ("C", "ST", "L", "O"):
                form[k] = form.get(k) or parent["info"]["dn"].get(k, "")
    return render_template("new.html", kind=kind, form=form, cas=cas)


def _csr_text(data: bytes) -> str:
    import subprocess
    p = subprocess.run(["openssl", "req", "-noout", "-text", "-inform",
                        "PEM" if data.strip().startswith(b"-----") else "DER"],
                       input=data, capture_output=True)
    return p.stdout.decode(errors="replace") or p.stderr.decode(errors="replace")


@app.route("/sign", methods=["GET", "POST"])
def sign():
    cas = ca.list_cas(with_key_only=True)
    form = {"kind": "server", "use_csr_sans": "1"}
    preview = csr_text = None
    if request.method == "POST":
        form = request.form.to_dict()
        f = request.files.get("csr_file")
        data = f.read() if f and f.filename else form.get("csr_pem", "").encode()
        if f and f.filename and data.strip().startswith(b"-----"):
            form["csr_pem"] = data.decode(errors="replace")  # fájlból is maradjon meg az űrlapon
        try:
            if not data.strip():
                raise ca.CAError("Add meg a CSR-t.")
            if form.get("action") == "preview":
                preview, csr_text = ca.csr_summary(data), _csr_text(data)
            else:
                item_id, warnings = ca.sign_csr(data, form)
                audit.log("sign_csr", request, ca.load_item(item_id))
                for w in warnings:
                    flash(w, "warn")
                flash("CSR aláírva, tanúsítvány kiadva.", "ok")
                return redirect(url_for("item", item_id=item_id))
        except ca.CAError as e:
            flash(str(e), "error")
            return render_template("sign.html", form=form, cas=cas), 400
    else:
        src = ca.load_item(request.args.get("from", ""))
        if src and src["has_csr"]:  # újra aláírás tárolt CSR-ből
            form.update({"csr_pem": ca.read_file(src["id"], "csr.pem").decode(),
                         "kind": src["kind"], "parent_id": src.get("parent_id") or "",
                         "days": str(src["params"].get("days", "")),
                         "client_auth": "1" if src["params"].get("client_auth") else "",
                         "sans": src["params"].get("sans", "")})
        elif request.args.get("parent"):
            form["parent_id"] = request.args["parent"]
    if not form.get("parent_id") and cas:
        pref = [c for c in cas if c["kind"] == "intermediate"]
        form["parent_id"] = (pref or cas)[-1]["id"]
    return render_template("sign.html", form=form, cas=cas, preview=preview, csr_text=csr_text)


@app.route("/import", methods=["GET", "POST"])
def import_():
    if request.method == "POST":
        cert = request.files.get("cert_file")
        cert_data = cert.read() if cert and cert.filename else request.form.get("cert_pem", "").encode()
        key = request.files.get("key_file")
        key_data = key.read() if key and key.filename else request.form.get("key_pem", "").encode()
        try:
            if not cert_data.strip():
                raise ca.CAError("Add meg a tanúsítványt.")
            ids, messages = ca.import_ca(cert_data, key_data, request.form.get("password"))
        except ca.CAError as e:
            flash(str(e), "error")
            return render_template("import.html"), 400
        for m in messages:
            flash(m, "warn")
        for i in ids:
            it = ca.load_item(i)
            audit.log("import", request, it, with_key=it["has_key"])
        if ids:
            flash(f"{len(ids)} tanúsítvány importálva.", "ok")
            return redirect(url_for("item", item_id=ids[-1]))
        return redirect(url_for("index"))
    return render_template("import.html")


@app.get("/item/<item_id>")
def item(item_id):
    it = ca.load_item(item_id)
    if not it:
        abort(404)
    try:
        cert_text = ca.openssl_text(item_id, "cert")
        csr_text = ca.openssl_text(item_id, "csr") if it["has_csr"] else ""
    except ca.CAError as e:
        cert_text, csr_text = str(e), ""
    files = {
        "cert": ca.read_file(item_id, "cert.pem").decode(),
        "csr": ca.read_file(item_id, "csr.pem").decode() if it["has_csr"] else "",
        "cnf": ca.read_file(item_id, "openssl.cnf").decode() if it["has_cnf"] else "",
    }
    chain = [ca.load_item(c) for c in ca.chain_ids(item_id)]
    return render_template("item.html", it=it, cert_text=cert_text, csr_text=csr_text,
                           files=files, chain=chain, children=ca.children_of(item_id),
                           history=audit.read(50, item_id=item_id))


@app.get("/item/<item_id>/key")
def view_key(item_id):
    """A privát kulcs megjelenítése (külön kérés, hogy naplózható legyen)."""
    it = ca.load_item(item_id)
    if not it or not it["has_key"]:
        abort(404)
    audit.log("view_key", request, it)
    return Response(ca.read_file(item_id, "key.pem"), mimetype="text/plain",
                    headers={"Cache-Control": "no-store"})


@app.get("/item/<item_id>/dl/<what>")
def download(item_id, what):
    it = ca.load_item(item_id)
    if not it:
        abort(404)
    base = ca._slug(it["info"]["cn"])
    try:
        if what == "cert":
            return _download(ca.read_file(item_id, "cert.pem"), f"{base}.crt")
        if what == "der":
            return _download(ca.cert_der(item_id), f"{base}.der", "application/pkix-cert")
        if what == "key":
            data = ca.read_file(item_id, "key.pem")
            audit.log("download_key", request, it)
            return _download(data, f"{base}.key")
        if what == "csr":
            return _download(ca.read_file(item_id, "csr.pem"), f"{base}.csr")
        if what == "cnf":
            return _download(ca.read_file(item_id, "openssl.cnf"), f"{base}.cnf", "text/plain")
        if what == "chain":
            return _download(ca.chain_pem(item_id), f"{base}-ca-chain.pem")
        if what == "fullchain":
            return _download(ca.fullchain(item_id), f"{base}-fullchain.pem")
        if what == "zip":
            data = ca.zip_bundle(item_id)
            if it["has_key"]:
                audit.log("download_zip", request, it)
            return _download(data, f"{base}.zip", "application/zip")
    except ca.CAError as e:
        flash(str(e), "error")
        return redirect(url_for("item", item_id=item_id))
    abort(404)


@app.post("/item/<item_id>/p12")
def download_p12(item_id):
    it = ca.load_item(item_id)
    if not it:
        abort(404)
    try:
        data = ca.pkcs12(item_id, request.form.get("password", ""), bool(request.form.get("legacy")))
    except ca.CAError as e:
        flash(str(e), "error")
        return redirect(url_for("item", item_id=item_id))
    audit.log("download_p12", request, it)
    return _download(data, f"{ca._slug(it['info']['cn'])}.p12", "application/x-pkcs12")


@app.post("/item/<item_id>/key-encrypted")
def download_key_encrypted(item_id):
    it = ca.load_item(item_id)
    if not it:
        abort(404)
    pw, pw2 = request.form.get("password", ""), request.form.get("password2", "")
    try:
        if pw != pw2:
            raise ca.CAError("A két jelszó nem egyezik.")
        data = ca.encrypted_key(item_id, pw)
    except ca.CAError as e:
        flash(str(e), "error")
        return redirect(url_for("item", item_id=item_id))
    audit.log("download_key_encrypted", request, it)
    return _download(data, f"{ca._slug(it['info']['cn'])}.enc.key")


@app.post("/item/<item_id>/remove-key")
def remove_key(item_id):
    it = ca.load_item(item_id)
    if not it:
        abort(404)
    try:
        if (request.form.get("confirm_cn") or "").strip() != it["info"]["cn"]:
            raise ca.CAError("A megerősítéshez pontosan a CA nevét (CN) kell beírni.")
        if not request.form.get("saved"):
            raise ca.CAError("Előbb mentsd el a kulcsot, és jelöld be, hogy megvan.")
        ca.remove_key(item_id)
    except ca.CAError as e:
        flash(str(e), "error")
        return redirect(url_for("item", item_id=item_id))
    audit.log("remove_key", request, it)
    flash("A privát kulcs véglegesen eltávolítva, a CA mostantól offline. Új aláíráshoz "
          "az Import oldalon add vissza a kulcsot (a cert + kulcs újraimportálásával).", "ok")
    return redirect(url_for("item", item_id=item_id))


@app.post("/item/<item_id>/delete")
def delete(item_id):
    it = ca.load_item(item_id)
    try:
        ca.delete_item(item_id)
        audit.log("delete", request, it)
    except ca.CAError as e:
        flash(str(e), "error")
        return redirect(url_for("item", item_id=item_id))
    flash("Törölve (a /data/trash könyvtárba került).", "ok")
    return redirect(url_for("index"))


@app.get("/backup.zip")
def backup():
    audit.log("backup", request)
    return _download(ca.backup_zip(), "local-ca-backup.zip", "application/zip")


@app.get("/audit")
def audit_page():
    action = request.args.get("action") or None
    entries = audit.read(1000, action=action)
    return render_template("audit.html", entries=entries, action=action)


@app.route("/notifications", methods=["GET", "POST"])
def notifications():
    if request.method == "POST":
        if request.form.get("action") == "test":
            errors = notify.send_test(request)
            flash("\n".join(errors) if errors else "Teszt értesítés elküldve.",
                  "error" if errors else "ok")
        else:
            r = notify.run_check(force=True, req=request)
            if r["errors"]:
                flash("Hiba küldéskor:\n" + "\n".join(r["errors"]), "error")
            elif r["sent"]:
                flash(f"Értesítés elküldve ({r['expiring']} tanúsítvány).", "ok")
            elif not notify.enabled():
                flash(f"{r['expiring']} lejáró tanúsítvány, de nincs értesítési csatorna beállítva.", "warn")
            else:
                flash("Nincs lejáró tanúsítvány, nem ment ki értesítés.", "ok")
        return redirect(url_for("notifications"))
    cfg = notify.config()
    return render_template("notifications.html", cfg=cfg, enabled=notify.enabled(cfg),
                           state=notify.load_state(), expiring=ca.expiring_items(cfg["days"]))


@app.get("/metrics")
def metrics():
    return Response(ca.metrics_text(), mimetype="text/plain; version=0.0.4")


@app.get("/healthz")
def healthz():
    return "ok"


ca.ensure_dirs()
notify.start_scheduler()
