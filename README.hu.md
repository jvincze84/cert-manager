# Local CA Manager

[English](README.md) | **Magyar**

Saját CA kezelése webes felületen Docker konténerben. Python/Flask + `openssl` CLI.

## Indítás

```bash
cp .env.example .env     # SECRET_KEY: írd át egy random stringre, a többit igény szerint
mkdir -p data            # fontos: a konténer uid 1000-ként fut, legyen írható neki
docker compose up -d --build
# http://<host>:8485   (más port: CA_PORT a .env-ben)
```

Hitelesítés nincs: a szolgáltatás elé reverse proxy (auth-tal) kell, és a port csak a proxy felől
legyen elérhető (pl. `"127.0.0.1:8485:8080"` a `docker-compose.yml`-ben).

## Funkciók

- **Root CA / Intermediate CA generálás** – RSA 2048/3072/4096 vagy ECDSA P-256/P-384, pathlen megadható.
- **Meglévő CA import** – PEM/DER, akár teljes lánc egyben; titkosított kulcs jelszóval. A kiállítói
  kapcsolat aláírás-ellenőrzéssel automatikusan felismerődik (ha előbb az intermediate-et importálod,
  a root importjakor összekapcsolódnak). Root importálható kulcs nélkül is (offline root).
- **Szerver cert** – SAN lista (DNS, IP), wildcard (`*.home.arpa`), opcionálisan `clientAuth` is.
- **mTLS kliens cert** – `extendedKeyUsage = clientAuth`, opcionális e-mail / SAN, PKCS#12 export.
- **Külső CSR aláírása** – PEM/DER CSR feltöltése, előnézet, szerver vagy kliens cert kiadása.
  A CSR-ben kért SAN-ok átvehetők és kiegészíthetők, a CSR egyéb kiterjesztései nem kerülnek át.
  A privát kulcs a kérelmezőnél marad; a tárolt CSR-ből később újra aláírható.
- **Name Constraints** – az intermediate CA korlátozható névterekre (pl. `home.arpa`, `192.168.0.0/16`).
  Kiadás előtt az app ellenőrzi, hogy a cert nevei beleférnek-e a lánc korlátaiba.
- **Offline CA kulcs** – a CA kulcs AES-256-tal titkosítva letölthető, majd véglegesen eltávolítható a
  szerverről. Visszahozás: Import oldalon a cert + kulcs újraimportálásával.
- **Lejárat figyelése** – figyelmeztetés a főoldalon, napi értesítés webhookra (Slack/Discord/Mattermost/…)
  és/vagy ntfy-ra, Prometheus végpont (`/metrics`).
- **Audit napló** – `data/audit.log` (JSON Lines) és `/audit` oldal: létrehozás, aláírás, import, törlés,
  kulcs megtekintés/letöltés, mentés, értesítések. A felhasználó a reverse proxy fejlécéből jön.
- **Sima tanúsítvány import** – szerver/kliens cert is importálható (PEM, DER, fullchain, PKCS#12), kulccsal vagy
  anélkül. A típus az EKU alapján dől el, a kiállító CA automatikusan összekapcsolódik. Kívül kiadott certek
  (pl. Let's Encrypt) is felvehetők, hogy a lejáratuk figyelve legyen.
- **Főoldali szűrő** – kereső (név, SAN, kiállító, sorozatszám) és szűrés típusra, állapotra, kiállítóra,
  forrásra; a megújított régi certek elrejthetők. A szűrő állapota az URL-ben marad.
- **Megtekintés** – `openssl x509 -text` kimenet, PEM, CSR, OpenSSL config, privát kulcs (lenyitható),
  másolás gombokkal (sima HTTP-n is működik).
- **Letöltés** – `.crt`, `.der`, `.key`, `.csr`, `.cnf`, `fullchain` (cert + intermediate, root nélkül),
  `CA lánc` (kiállítók a roottal), `.p12`, minden egy zipben, illetve a teljes store mentése.
- **Újrakiadás** – új cert ugyanazokkal az adatokkal (megújításhoz).
- **Törlés** – a `data/trash/` könyvtárba mozgat, nem töröl véglegesen.

## Beállítások (környezeti változók)

Minden beállítás a `.env` fájlból jön (a `.env.example` mindegyiket elmagyarázza). Üres érték = alapértelmezés.

| változó | jelentés |
|---|---|
| `SECRET_KEY` | session kulcs (random string) |
| `CA_PORT` | a host port (alap: 8485) |
| `DEFAULT_C/ST/L/O` | a Root CA űrlap alapértékei |
| `TZ` | időzóna (az értesítés idejéhez), alap: `UTC`, pl. `Europe/Budapest` |
| `NOTIFY_DAYS` | ennyi napon belül lejáró certekről értesít (alap: 30) |
| `NOTIFY_HOUR` | naponta ennyi óra után küld (alap: 8) |
| `NOTIFY_WEBHOOK_URL` | JSON POST: `text`, `content`, `title`, `certs` mezőkkel |
| `NOTIFY_NTFY_URL`, `NOTIFY_NTFY_TOKEN` | ntfy topic URL (pl. `https://ntfy.sh/topic`) és opcionális token |
| `PUBLIC_URL` | az app címe, link az értesítésben |
| `AUDIT_USER_HEADER` | vesszővel elválasztott fejlécnevek a felhasználónévhez (alap: `X-Forwarded-User`, `Remote-User`, …) |

Az audit a `X-Forwarded-User` stb. fejléceknek feltétel nélkül hisz, ezért az app portja csak a
reverse proxy felől legyen elérhető, és a proxy írja felül ezeket a fejléceket.

## Tárolás

Minden tanúsítvány a `data/store/<id>/` könyvtárban van:

| fájl          | tartalom                                                                 |
|---------------|--------------------------------------------------------------------------|
| `cert.pem`    | tanúsítvány                                                              |
| `key.pem`     | privát kulcs (titkosítatlan, 0600)                                       |
| `csr.pem`     | CSR (root CA-nál nincs, mert közvetlenül önaláírt)                       |
| `openssl.cnf` | a generáláshoz használt config – a CSR és az aláírás kiterjesztései is   |
| `meta.json`   | típus, kiállító, űrlap paraméterek                                       |

Továbbá: `data/audit.log` (audit napló), `data/notify-state.json` (utolsó értesítés), `data/trash/` (törölt elemek).

A config alapján a cert kézzel is reprodukálható, pl. szerver certnél:

```bash
openssl req -new -config openssl.cnf -key key.pem -out csr.pem
openssl x509 -req -in csr.pem -CA ca.pem -CAkey ca.key -days 397 \
  -extfile openssl.cnf -extensions server_cert -out cert.pem
```

**A `data/` könyvtár tartalmazza a CA privát kulcsait – ennek megfelelően mentsd és védd.**
