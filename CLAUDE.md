# Local CA Manager

Webes saját CA kezelő Dockerben, otthoni hálózathoz. Python/Flask + `openssl` CLI.
A felület és a hibaüzenetek **magyarul** vannak, ezt tartsuk meg. Hitelesítés szándékosan nincs,
a szolgáltatás elé reverse proxy kerül.

## Funkciók

- Root és intermediate CA generálása vagy importálása (PEM/DER, teljes lánc, titkosított kulcs, root kulcs nélkül is).
- Sima szerver/kliens cert importja is (`import_ca`): PEM/DER/PKCS#12, fullchain + kulcs. Típus az EKU-ból
  (`_leaf_kind`); az önaláírt, DNS/IP SAN-os cert akkor is leaf, ha CA:TRUE (az `openssl req -x509` így készíti).
  Kívül kiadott cert (kiállító nincs a tárban) is importálható, a lejárata figyelve lesz.
- Szerver cert (SAN, wildcard, opcionális `clientAuth`) és mTLS kliens cert generálása.
- Kívül készült CSR aláírása (`/sign`), előnézettel és a tárolt CSR-ből újra aláírással.
- Főoldal: CA fa + „Kiadott tanúsítványok” táblázat kliens oldali szűrővel (kereső több szóra, ÉS
  kapcsolattal; típus, állapot, kiállító, forrás; megújított régiek elrejtése). A szűrő állapota az
  URL query-ben van (`?q=…&kind=…`), a `/` billentyű a keresőre ugrik. A sorok `data-*` attribútumokat kapnak.
- Megtekintés (`openssl -text`, PEM, CSR, config, kulcs; „Másolás” gombok a `base.html` közös JS-ével), letöltés (crt, der, key, csr, cnf, fullchain,
  CA lánc, p12, zip), teljes mentés (`/backup.zip`), törlés a `data/trash/` könyvtárba.
- Name Constraints az intermediate CA-n (DNS / IP CIDR / email), kiadás előtti ellenőrzéssel
  (`check_name_constraints`, a lánc összes CA-jára, a hostnévszerű CN-t is nézi, mint az OpenSSL).
- Offline CA kulcs: titkosított export (`encrypted_key`) + végleges eltávolítás (`remove_key`,
  felülírás után törlés). Visszahozás az importtal (meglévő certhez hozzáadja a kulcsot).
- Lejárat figyelés: főoldali sáv, napi értesítés webhook/ntfy (`notify.py`, háttérszál, naponta
  egyszer `NOTIFY_HOUR` után, állapot: `data/notify-state.json`), `/notifications` oldal, `/metrics`.
  A megújított certek (azonos kind + CN + parent, későbbi lejárat) kimaradnak (`expiring_items`).
- Audit napló: `audit.py`, `data/audit.log` (JSON Lines) + stdout, `/audit` oldal, elemenkénti
  előzmény. A privát kulcs nincs beágyazva az elem oldalába, külön `/item/<id>/key` kérés tölti be
  (naplózva).

## Szerkezet

```
app/ca.py          minden üzleti logika: tárolás, openssl hívások, config építés, import, CSR aláírás, export
app/app.py         Flask útvonalak (vékony réteg, a ca.CAError-t flash üzenetté alakítja, audit hívások)
app/audit.py       audit napló írás/olvasás, felhasználó a proxy fejlécből (AUDIT_USER_HEADER)
app/notify.py      lejárati értesítések (webhook, ntfy), háttér ütemező
app/templates/     Jinja sablonok; _macros.html: státusz/típus badge-ek, CA fa
app/static/style.css  saját CSS, nincs CDN/JS keretrendszer (offline is működik), világos/sötét mód
Dockerfile, docker-compose.yml, requirements.txt
.env.example       minta a helyi .env-hez, minden beállítással; a .env nincs a gitben
.gitignore, .gitattributes (LF sorvégek), .dockerignore
README.md          angol leírás (GitHubra);  README.hu.md  ugyanaz magyarul
CLAUDE.md          ez a fájl (magyarul)
data/              a CA-k élő adatai (bind mount) – NEM forráskód, nincs a gitben
```

## Adatmodell

Minden elem egy könyvtár: `data/store/<kind>-<cn-slug>-<6 hex>/`
- `cert.pem`, `key.pem` (0600, titkosítatlan PKCS8; CSR-ből kiadottnál nincs), `csr.pem`
  (root CA-nál és importált CA-nál nincs), `openssl.cnf` (importáltnál nincs), `meta.json`.
- `meta.json`: `id`, `kind` (`root|intermediate|server|client`), `source` (`generated|imported|csr`),
  `parent_id`, `created`, `params` (az űrlap értékei, az újrakiadáshoz).
- Nincs adatbázis. A tanúsítvány adatait (lejárat, SAN stb.) minden betöltéskor a `cert.pem`-ből
  olvassuk ki (`cert_info`). A lánc a `parent_id` mentén épül (`chain_ids`).
- Generálás egy `.tmp-*` könyvtárban történik, siker esetén `rename`, hiba esetén törlés (atomikus).

## Konvenciók

- Generálás és aláírás: **openssl CLI** (`run_openssl`), hogy a mentett `openssl.cnf` pontosan
  reprodukálja a certet. Beolvasás és ellenőrzés: `cryptography` könyvtár.
- A config szekciói: CSR-hez `req_ext` / `v3_intermediate_ca_req`, aláíráshoz `v3_ca` /
  `v3_intermediate_ca` / `server_cert` / `client_cert` (`ext_section()`). Az aláírás
  `openssl x509 -req -extfile openssl.cnf -extensions <szekció>` paranccsal történik, a CSR-ben kért
  kiterjesztéseket nem másoljuk át (szándékos biztonsági döntés).
- A configba kerülő felhasználói értékeket a `_cnf_escape()` escapeli; az új mezőknél is ezt kell használni.
- Sorozatszám: véletlen 127 bites (`_serial()`). Alapértelmezett érvényesség: root 3650, intermediate
  1825, szerver 397, kliens 365 nap. 825 napnál hosszabb szerver certnél figyelmeztetünk (Apple).
- Fullchain = leaf + intermediate(ek), root nélkül; a „CA lánc” a roottal együtt.
- Frontend: sima JS, keretrendszer nélkül. Az app sima HTTP-n is fut (proxy előtt / LAN-on), ezért
  ne támaszkodj csak secure context API-kra: a `navigator.clipboard` ott nem létezik, a másolás
  `execCommand('copy')` tartalékkal megy (`copyText` a `base.html`-ben). Szöveg beírásához `textContent`
  kell, nem `innerText` (az `<br>`-eket csinál a sortörésekből, és a másolásnál elvesznek).

## Git és dokumentáció

- A `data/`, a `.env` és minden kulcs/cert fájl (`*.pem`, `*.key`, `*.p12`, `*.zip` …) ki van zárva
  (`.gitignore`). Commit előtt `git status`-szal nézd meg, hogy ilyen ne kerüljön be.
- Funkció változásnál mindkét README-t frissítsd (`README.md` angol, `README.hu.md` magyar), és ezt a
  fájlt is (Funkciók, tesztelt esetek, továbbfejlesztések).
- Commit/push csak a felhasználó kérésére.

## Futtatás

```bash
cp .env.example .env                  # minden beállítás itt (a compose automatikusan beolvassa)
mkdir -p data                         # a konténer uid 1000-ként fut, írnia kell
docker compose up -d --build          # alapból a 8485-ös port (ezen a gépen a 8080 foglalt)
```

Környezeti változók: `SECRET_KEY`, `DEFAULT_C/ST/L/O`, `DATA_DIR` (alapból `/data`), `TZ`,
`NOTIFY_DAYS`, `NOTIFY_HOUR`, `NOTIFY_WEBHOOK_URL`, `NOTIFY_NTFY_URL`, `NOTIFY_NTFY_TOKEN`, `PUBLIC_URL`,
`AUDIT_USER_HEADER`, `NOTIFY_DISABLE_SCHEDULER` (teszthez). Részletek: README.
A `docker-compose.yml` ezeket `${VAR:-alap}` interpolációval a `.env`-ből veszi, így a konténer üres
stringet is kaphat: az appban az üres érték az alapértelmezést jelentse (`os.environ.get(...) or alap`).
Új beállításnál: `.env.example` + `docker-compose.yml` + mindkét README. A felhasználó saját `.env`-je
(valódi értékek, `SECRET_KEY`) nincs a gitben, ne írd felül.

## Tesztelés – FONTOS

A `data/` könyvtárban **a felhasználó valódi CA-i vannak** (pl. `root-local-teszt-*`). Teszteléskor
ne a futó példányt és ne ezt a könyvtárat használd; egy korábbi tesztnél ebből már volt keveredés.
Külön, eldobható adatkönyvtárral futtass egy második konténert:

```bash
docker build -t local-ca-manager:test .
T=$(mktemp -d) && chown 1000 "$T"
docker run -d --rm --name local-ca-test -p 127.0.0.1:18081:8080 -v "$T:/data" local-ca-manager:test
# ... curl tesztek a http://127.0.0.1:18081 címen, ellenőrzés: openssl verify -CAfile root -untrusted int cert
docker stop local-ca-test
```

Nincs automatizált tesztkészlet. Eddig curl-lel végigjátszott folyamatokkal teszteltünk:
- generálás: root → intermediate → szerver és kliens cert, majd `openssl verify`;
- import: kívül készült lánc, titkosított kulcs, rossz jelszó, nem egyező kulcs, előbb intermediate és utána root;
- leaf import: fullchain + kulcs root nélkül, majd root (összekapcsolás), PKCS#12 (jó/rossz jelszó), EKU nélküli
  cert, kulcs utólagos hozzáadása, önaláírt CA:TRUE szerver cert; importált leaf fullchain / p12 exportja;
- CSR aláírás: PEM és DER, SAN-ok átvétele, CA:true kérés, gyenge kulcs;
- PKCS#12 mindkét módban;
- Name Constraints: megfelelő és szabálysértő SAN / CN / CSR; kontrollként kézzel aláírt
  szabálysértő certekkel ellenőriztük, hogy az `openssl verify` ugyanott utasít el;
- offline kulcs: titkosított export, eltávolítás, aláírás offline roottal (elutasítva), visszaimport;
- értesítés: webhook + ntfy fogadó a tesztkonténeren belül (`python receiver.py` a 127.0.0.1:9999-en),
  `NOTIFY_HOUR=0` az ütemező teszteléséhez, megújított cert kiszűrése;
- audit: felhasználó és IP az `X-Forwarded-User` / `X-Forwarded-For` fejlécből;
- főoldali szűrő: a JS-t egy ideiglenes `node:22-alpine` konténerben futtattuk minimális DOM-utánzattal
  (itt nincs node és böngésző), minden szűrő és az URL állapot ellenőrizve.

Python függvény a konténerben is futtatható: `docker exec <név> python -c "import ca; ..."`.

## Lehetséges továbbfejlesztések (még nincsenek kész)

- CRL / visszavonás (mTLS-hez hasznos: nginx `ssl_crl`), OCSP – a felhasználó „2. PKI best practice”
  kérésének része volt, de még nem készült el; jeleztük neki, döntésére vár
- CSRF védelem (token vagy Origin ellenőrzés) – javasolt, még nincs kész
- Konténer szigorítás (read_only, cap_drop, no-new-privileges) – javasolt, még nincs kész
- Titkosított teljes mentés (`/backup.zip` most titkosítatlan)
- Automatizált tesztek (pytest, ideiglenes `DATA_DIR`-rel)
- ACME szerver (pl. Traefik/Caddy automatikus certigényléséhez)
