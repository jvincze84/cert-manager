# Local CA Manager

**English** | [Magyar](README.hu.md)

A small self-hosted web UI for running your own private certificate authority (home lab, internal
networks). It runs in Docker and uses Python/Flask plus the `openssl` CLI. There is no database:
every certificate is a directory of plain PEM files with the exact `openssl.cnf` used to create it.

> The user interface is in **Hungarian**.

## Quick start

```bash
cp .env.example .env     # set SECRET_KEY to a random string, adjust the other settings
mkdir -p data            # the container runs as uid 1000 and must be able to write here
docker compose up -d --build
# open http://<host>:8485  (change the port with CA_PORT in .env)
```

**There is no built-in authentication.** The app is meant to sit behind a reverse proxy that handles
auth (e.g. Authelia, oauth2-proxy, basic auth). Make the port reachable only from the proxy, for
example by binding it to localhost in `docker-compose.yml`: `"127.0.0.1:8485:8080"`.

## Features

- **Root and intermediate CA generation.** RSA 2048/3072/4096 or ECDSA P-256/P-384, configurable pathlen.
- **Import existing CAs.** PEM/DER, a whole chain at once, encrypted keys with a password. Issuer
  relationships are detected by signature verification, in any import order. A root can be imported
  without its key (offline root).
- **Server certificates.** SAN list (DNS, IP), wildcards (`*.home.arpa`), optional `clientAuth`.
- **mTLS client certificates.** `extendedKeyUsage = clientAuth`, optional e-mail/SAN, PKCS#12 export.
- **Sign external CSRs.** Upload a PEM/DER CSR, preview it, then issue a server or client certificate.
  Requested SANs can be accepted and extended. Other extensions in the CSR are never copied, by design.
  The private key stays with the requester. The stored CSR can be re-signed later.
- **Name Constraints.** Restrict an intermediate CA to namespaces (e.g. `home.arpa`, `192.168.0.0/16`,
  e-mail domains). Before issuing, the app checks that the names fit the constraints of the whole chain.
- **Offline CA key.** Download the CA key encrypted with AES-256, then remove it permanently from the
  server. Re-import the certificate and key to bring it back.
- **Import plain certificates.** Server and client certificates (PEM, DER, fullchain, PKCS#12), with or
  without a key. The type comes from the EKU, and the issuing CA is linked automatically. Certificates
  from other CAs (e.g. Let's Encrypt) can be added so their expiry is monitored.
- **Expiry monitoring.** A banner on the main page, a daily digest sent to a webhook
  (Slack/Discord/Mattermost/Home Assistant) and/or ntfy, and a Prometheus endpoint at `/metrics`.
  Certificates that have already been renewed are left out.
- **Audit log.** `data/audit.log` (JSON Lines, also written to stdout) and an `/audit` page. It records
  creation, signing, import, deletion, key views and downloads, backups and notifications. The user name
  comes from the reverse proxy headers.
- **Main page filter.** Search by name, SAN, issuer or serial, and filter by type, status, issuer and
  source. Renewed certificates can be hidden. The filter state is kept in the URL.
- **Viewing.** `openssl x509 -text` output, PEM, CSR, OpenSSL config and private key, each with a copy
  button.
- **Downloads.** `.crt`, `.der`, `.key`, `.csr`, `.cnf`, `fullchain` (leaf + intermediates, no root),
  `CA chain` (all issuers including the root), `.p12`, everything in one zip, or a backup of the whole store.
- **Re-issue.** Create a new certificate with the same parameters, for renewal.
- **Delete.** Items are moved to `data/trash/`, never removed permanently.

## Configuration (environment variables)

All settings are read from `.env` (see `.env.example`, which documents each one). An empty value
means the default.

| Variable | Meaning |
|---|---|
| `SECRET_KEY` | Flask session key (random string) |
| `CA_PORT` | Host port (default: 8485) |
| `DEFAULT_C/ST/L/O` | Default subject fields on the new root CA form |
| `TZ` | Time zone, used for the notification time (default: `UTC`, e.g. `Europe/Budapest`) |
| `NOTIFY_DAYS` | Notify about certificates expiring within this many days (default: 30) |
| `NOTIFY_HOUR` | Send the daily digest after this hour (default: 8) |
| `NOTIFY_WEBHOOK_URL` | JSON POST with `text`, `content`, `title` and `certs` fields |
| `NOTIFY_NTFY_URL`, `NOTIFY_NTFY_TOKEN` | ntfy topic URL (e.g. `https://ntfy.sh/topic`) and optional token |
| `PUBLIC_URL` | Public URL of the app, linked in notifications |
| `AUDIT_USER_HEADER` | Comma-separated header names for the user name (default: `X-Forwarded-User`, `Remote-User`, …) |

The audit log trusts the user headers without checking them. That is another reason to expose the app
only through the reverse proxy, and to have the proxy overwrite those headers.

## Storage

Each certificate lives in `data/store/<id>/`:

| File | Content |
|---|---|
| `cert.pem` | Certificate |
| `key.pem` | Private key (unencrypted, mode 0600; missing for CSR-signed or key-less items) |
| `csr.pem` | CSR (missing for root CAs and imported items) |
| `openssl.cnf` | The config used for generation, including the CSR and signing extensions |
| `meta.json` | Type, issuer, source and form parameters |

Also in `data/`: `audit.log`, `notify-state.json` (last notification run) and `trash/` (deleted items).

The saved config reproduces a certificate by hand. For example, for a server certificate:

```bash
openssl req -new -config openssl.cnf -key key.pem -out csr.pem
openssl x509 -req -in csr.pem -CA ca.pem -CAkey ca.key -days 397 \
  -extfile openssl.cnf -extensions server_cert -out cert.pem
```

**`data/` contains your CA private keys.** Back it up and protect it. It is excluded from git by `.gitignore`.

## Project layout

```
app/ca.py          business logic: storage, openssl calls, config building, import, CSR signing, export
app/app.py         Flask routes (thin layer)
app/audit.py       audit log
app/notify.py      expiry notifications and background scheduler
app/templates/     Jinja templates
app/static/        CSS (no CDN, no JS framework; works offline, light and dark mode)
```

## Development and testing

There is no automated test suite yet. Do not test against your real `data/` directory. Run a throwaway
container with a temporary data directory instead:

```bash
docker build -t local-ca-manager:test .
T=$(mktemp -d) && chown 1000 "$T"
docker run -d --rm --name local-ca-test -p 127.0.0.1:18081:8080 -v "$T:/data" local-ca-manager:test
# ... test at http://127.0.0.1:18081
docker stop local-ca-test
```
