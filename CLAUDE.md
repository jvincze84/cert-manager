# Local CA Manager

Self-hosted web UI for a private CA, running in Docker, for a home network. Python/Flask + the `openssl` CLI.
Everything is in **English**: UI, error/flash messages, code comments, docs, generated `openssl.cnf`
comments. (The app was originally Hungarian and translated in full; keep new text English.)
The user talks to Claude in Hungarian. Authentication is intentionally absent; a reverse proxy sits in front.

## Features

- Generate or import root and intermediate CAs (PEM/DER, whole chain, encrypted key, root without key).
- Import plain server/client certificates too (`import_ca`): PEM/DER/PKCS#12, fullchain + key. Type from the EKU
  (`_leaf_kind`); a self-signed cert with a DNS/IP SAN is a leaf even if CA:TRUE (`openssl req -x509` makes those).
  Certificates from other CAs (issuer not in the store) can be imported; their expiry is monitored.
- Server certs (SANs, wildcard, optional `clientAuth`) and mTLS client certs.
- Sign external CSRs (`/sign`), with preview and re-signing from the stored CSR.
- Main page: CA tree + "Issued certificates" table with a client-side filter (multi-word search with AND;
  type, status, issuer, source; hide renewed ones). Filter state lives in the URL query (`?q=…&kind=…`),
  the `/` key focuses the search box. Rows carry `data-*` attributes.
- Viewing (`openssl -text`, PEM, CSR, config, key; "Copy" buttons via the shared JS in `base.html`),
  downloads (crt, der, key, csr, cnf, fullchain, CA chain, p12, zip), full backup (`/backup.zip`),
  delete = move to `data/trash/`.
- Name Constraints on intermediate CAs (DNS / IP CIDR / email), checked before issuing
  (`check_name_constraints`, for every CA in the chain; also checks a hostname-like CN, like OpenSSL does).
- Offline CA key: encrypted export (`encrypted_key`) + permanent removal (`remove_key`, overwrite then
  delete). Restore by re-importing (the key is attached to the existing cert).
- Expiry monitoring: main page banner, daily webhook/ntfy notification (`notify.py`, background thread,
  once a day after `NOTIFY_HOUR`, state in `data/notify-state.json`), `/notifications` page, `/metrics`.
  Renewed certs (same kind + CN + parent, later expiry) are skipped (`expiring_items`).
- Audit log: `audit.py`, `data/audit.log` (JSON Lines) + stdout, `/audit` page, per-item history.
  The private key is not embedded in the item page; a separate `/item/<id>/key` request loads it (logged).

## Layout

```
app/ca.py          all business logic: storage, openssl calls, config building, import, CSR signing, export
app/app.py         Flask routes (thin layer; turns ca.CAError into flash messages; audit calls)
app/audit.py       audit log write/read; user from the proxy header (AUDIT_USER_HEADER); ACTIONS labels
app/notify.py      expiry notifications (webhook, ntfy), background scheduler
app/templates/     Jinja templates; _macros.html: status/type badges, CA tree
app/static/style.css  own CSS, no CDN / JS framework (works offline), light/dark mode
Dockerfile, docker-compose.yml, requirements.txt
.env.example       template for the local .env with every setting; .env is not in git
.gitignore, .gitattributes (LF line endings), .dockerignore
.github/workflows/docker.yml  image build via the user's reusable workflow (feature/** branches, v* tags)
scripts/release.sh annotated release tag + push (the user's script)
scripts/make_icons.py  copied from another project (pdf-manager, pymupdf); not used by this app yet
README.md          English docs (also pushed to Docker Hub by the workflow)
data/              live CA data (bind mount) – NOT source code, not in git
```

## Data model

Each item is a directory: `data/store/<kind>-<cn-slug>-<6 hex>/`
- `cert.pem`, `key.pem` (0600, unencrypted PKCS8; absent for CSR-signed items), `csr.pem`
  (absent for root CAs and imported items), `openssl.cnf` (absent for imported items), `meta.json`.
- `meta.json`: `id`, `kind` (`root|intermediate|server|client`), `source` (`generated|imported|csr`),
  `parent_id`, `created`, `params` (form values, for re-issuing).
- No database. Certificate data (expiry, SANs, …) is read from `cert.pem` on every load (`cert_info`).
  The chain follows `parent_id` (`chain_ids`).
- Generation happens in a `.tmp-*` directory, then `rename` on success, delete on failure (atomic).
- Older items in the user's `data/` have Hungarian comments in their `openssl.cnf`; that is fine, leave them.

## Conventions

- Generation and signing: **openssl CLI** (`run_openssl`), so the saved `openssl.cnf` reproduces the cert
  exactly. Parsing and verification: the `cryptography` library.
- Config sections: for the CSR `req_ext` / `v3_intermediate_ca_req`, for signing `v3_ca` /
  `v3_intermediate_ca` / `server_cert` / `client_cert` (`ext_section()`). Signing uses
  `openssl x509 -req -extfile openssl.cnf -extensions <section>`; extensions requested in the CSR are
  never copied (deliberate security decision).
- User values written into the config are escaped with `_cnf_escape()`; use it for new fields too.
- Serial: random 127-bit (`_serial()`). Default validity: root 3650, intermediate 1825, server 397,
  client 365 days. Warn for server certs over 825 days (Apple).
- Fullchain = leaf + intermediate(s), no root; "CA chain" includes the root.
- Frontend: plain JS, no framework. The app also runs over plain HTTP (behind a proxy / on the LAN), so
  do not rely only on secure-context APIs: `navigator.clipboard` does not exist there; copying falls back
  to `execCommand('copy')` (`copyText` in `base.html`). Use `textContent`, not `innerText`, to insert text
  (`innerText` turns line breaks into `<br>`, which are lost when copying).

## Git and docs

- `data/`, `.env` and all key/cert files (`*.pem`, `*.key`, `*.p12`, `*.zip`, …) are ignored
  (`.gitignore`). Check `git status` before committing that none of these slipped in.
- When a feature changes, update `README.md` and this file (Features, tested scenarios, future work).
- Commit/push only when the user asks. Releases: `scripts/release.sh` (the user runs it).

## Running

```bash
cp .env.example .env                  # all settings live here (compose reads it automatically)
mkdir -p data                         # the container runs as uid 1000 and must be able to write
docker compose up -d --build          # port 8485 by default (8080 is taken on this machine)
```

Environment variables: `SECRET_KEY`, `DEFAULT_C/ST/L/O`, `DATA_DIR` (default `/data`), `TZ`,
`NOTIFY_DAYS`, `NOTIFY_HOUR`, `NOTIFY_WEBHOOK_URL`, `NOTIFY_NTFY_URL`, `NOTIFY_NTFY_TOKEN`, `PUBLIC_URL`,
`AUDIT_USER_HEADER`, `NOTIFY_DISABLE_SCHEDULER` (for tests). Details: README.
`docker-compose.yml` takes them from `.env` with `${VAR:-default}` interpolation, so the container may get
empty strings: in the app an empty value must mean the default (`os.environ.get(...) or default`).
For a new setting: `.env.example` + `docker-compose.yml` + README. The user's own `.env` (real values,
`SECRET_KEY`) is not in git; do not overwrite it.

## Testing – IMPORTANT

`data/` holds **the user's real CAs** (e.g. `root-local-teszt-*`). Never test against the running instance
or that directory; an earlier test mixed test items into it. Run a second container with a throwaway
data directory:

```bash
docker build -t local-ca-manager:test .
T=$(mktemp -d) && chown 1000 "$T"
docker run -d --rm --name local-ca-test -p 127.0.0.1:18081:8080 -v "$T:/data" local-ca-manager:test
# ... curl tests against http://127.0.0.1:18081, verify with: openssl verify -CAfile root -untrusted int cert
docker stop local-ca-test
```

There is no automated test suite. So far, flows were replayed with curl:
- generation: root → intermediate → server and client cert, then `openssl verify`;
- import: external chain, encrypted key, wrong password, non-matching key, intermediate first then root;
- leaf import: fullchain + key without root, then root (linking), PKCS#12 (right/wrong password), cert
  without EKU, adding the key later, self-signed CA:TRUE server cert; fullchain / p12 export of imported leaves;
- CSR signing: PEM and DER, accepting SANs, CA:true request, weak key;
- PKCS#12 in both modes;
- Name Constraints: compliant and violating SAN / CN / CSR; as a control, hand-signed violating certs
  confirmed that `openssl verify` rejects at the same points;
- offline key: encrypted export, removal, signing with an offline root (rejected), re-import;
- notifications: webhook + ntfy receiver inside the test container (`python receiver.py` on 127.0.0.1:9999),
  `NOTIFY_HOUR=0` to test the scheduler, renewed cert filtering;
- audit: user and IP from the `X-Forwarded-User` / `X-Forwarded-For` headers;
- main page filter: the JS was run in a temporary `node:22-alpine` container with a minimal DOM stub
  (no node or browser on this machine); every filter and the URL state checked;
- English translation: every page rendered and the main flows replayed in the test container.

Python functions can be run inside the container: `docker exec <name> python -c "import ca; ..."`.

## Possible future work (not done)

- CRL / revocation (useful for mTLS: nginx `ssl_crl`), OCSP – part of the user's earlier
  "2. PKI best practice" request, not implemented yet; the user was told and has not decided
- CSRF protection (token or Origin check) – recommended, not done
- Container hardening (read_only, cap_drop, no-new-privileges) – recommended, not done
- Encrypted full backup (`/backup.zip` is currently unencrypted)
- Automated tests (pytest with a temporary `DATA_DIR`)
- ACME server (e.g. for automatic certificates in Traefik/Caddy)
- New README screenshot (the current one shows the old Hungarian UI)
