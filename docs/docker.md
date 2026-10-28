# Running LIANA with Docker

The Docker image is the main way to run LIANA. It contains everything a test setup needs: the native LIANA binary,
the card engine kartos, the bundled card images, the test PKI (connector TLS identities, client certificates) and a
current TSL of the reference environment (RU). No JDK and no checkout of this repository are needed.

- [Image](#image)
- [Quick start](#quick-start)
- [Ports](#ports)
- [Configuration](#configuration)
- [Card images](#card-images)
- [TLS](#tls)
- [Docker Compose](#docker-compose)
- [Building the image yourself](#building-the-image-yourself)

The full reference of all settings is the German manual [handbuch.md](./handbuch.md); this page covers what you need
to run the image.

## Image

| | |
|---|---|
| Image | [`gematik1/liana`](https://hub.docker.com/r/gematik1/liana) on Docker Hub |
| Tags | the LIANA version (e.g. `0.7.17`, see [ReleaseNotes.md](../ReleaseNotes.md)) and `latest` |
| Platform | `linux/amd64` |
| User | 1001, working directory `/work` |
| Health check | built in (`GET /admin/ready` on the management port) |

On Apple Silicon add `--platform linux/amd64`; Docker runs the image under emulation, start-up then takes a few
seconds longer. Pin a version tag in test setups so that a new release does not change your tests unnoticed.

## Quick start

```bash
docker run --rm --name liana -p 8080:8080 -p 8443:8443 -p 9090:9090 gematik1/liana:latest
```

```bash
curl -s localhost:9090/admin/ready                 # {"ready":true}
curl -s localhost:8080/connector.sds               # service directory over HTTP
curl -sk https://localhost:8443/connector.sds      # the same over HTTPS
curl -o cs1.kon localhost:9090/admin/clients/CS1/config.kon   # client configuration (.kon) for the konnektor-client
```

Open the Control Center at http://localhost:9090/. Out of the box LIANA has two simulated card terminals: `KT-01`
with an eGK in slot 1 and an SMC-B in slot 2, `KT-02` empty. Mandant `M1`, client system `CS1` and workplace `WP1`
form the information model.

## Ports

| Port | Content |
|---|---|
| 8080 | connector services over HTTP: `/connector.sds`, SOAP under `/ws/*` |
| 8443 | the same services over HTTPS ([TLS](#tls)) |
| 9090 | management port, HTTP and HTTPS on the same port: Control Center `/`, Admin API `/admin/*` (no authentication), the management interface (KMS) of the vendor profile, CATS `/cats/{KT}` |

Inside the container the ports stay fixed; map them to whatever the client expects. Clients that know a vendor's
management port find the KMS through a port mapping:

| Vendor profile (`LIANA_VENDOR`) | Management port of the vendor | Mapping |
|---|---|---|
| `EHEX`, `SECUNET` (`/rest/mgmt`) | 8500 | `-p 8500:9090` |
| `KOCO`, `CGM` | 9443 | `-p 9443:9090` |
| `RISE` (`/api`) | 8443 | none, the RISE KMS also answers on the HTTPS port 8443 |

## Configuration

LIANA reads its settings from three layers; a later layer overrides an earlier one key by key:

1. the configuration built into the image,
2. a YAML file mounted at `/work/config/application.yaml`,
3. environment variables `LIANA_*`.

An environment variable is the key in upper case, with every `.` and `-` replaced by `_`:
`liana.tls.client-auth` becomes `LIANA_TLS_CLIENT_AUTH`, `liana.infrastructure.konnektor.gsmc-k.ak-aut` becomes
`LIANA_INFRASTRUCTURE_KONNEKTOR_GSMC_K_AK_AUT`. Lists are comma-separated. For anything with more structure (card
terminals, slots, the information model) use the YAML file.

```bash
docker run --rm -p 8080:8080 -p 8443:8443 -p 9090:9090 \
  -v ./liana.yaml:/work/config/application.yaml:ro \
  -e LIANA_VENDOR=EHEX \
  gematik1/liana:latest
```

The configuration is the boot state. Changes through the Admin API, the Control Center or the KMS take effect
immediately but are not saved; `POST /admin/reset` restores the configured state. Tests can therefore always start
from a known state.

Frequently used settings:

| Key (environment variable) | Default | Meaning |
|---|---|---|
| `liana.kon-export.url` (`LIANA_KON_EXPORT_URL`) | `http://localhost:8080` | address under which clients reach the HTTP port; goes into `connector.sds` and the `.kon` export. In a Docker network e.g. `http://liana:8080` |
| `liana.tls.url` (`LIANA_TLS_URL`) | `https://localhost:8443` | the same for the HTTPS port |
| `liana.env` (`LIANA_ENV`) | `ru` | environment `ru`, `tu` or `pu` in the `.kon` export |
| `liana.vendor` (`LIANA_VENDOR`) | `neutral` | vendor profile: `neutral`, `EHEX`, `SECUNET`, `KOCO`, `CGM`, `RISE`; selects the KMS and vendor-specific behaviour |
| `liana.infrastructure.terminals` | `KT-01`, `KT-02` | card terminals and the cards in their slots ([Card images](#card-images)) |
| `liana.infomodel` | `M1`, `CS1`, `WP1` | mandants, client systems and workplaces |
| `liana.soap.request-validation` (`LIANA_SOAP_REQUEST_VALIDATION`) | `log` | checks requests against XSD and soapAction: `off`, `log` (warning in the log), `reject` (SOAP fault) |
| `liana.trace.push-url` (`LIANA_TRACE_PUSH_URL`) | none | Tiger proxy that receives every card APDU, e.g. `http://host.docker.internal:6900` |
| `liana.pki.tsl-online.mode` (`LIANA_PKI_TSL_ONLINE_MODE`) | `off` | fetch the RU TSL at start: `background` (fall back to the bundled one), `enforce` (fail without one) |
| `liana.admin.port` (`LIANA_ADMIN_PORT`) | `9090` | management port inside the container |

## Card images

The image ships with a set of test cards in `/opt/liana/images`: `egk-valid`, `smcb-valid`, `hba-valid`,
`gsmckt-valid`, plus G2.0 cards, gSMC-K, gSMC-KT and a KVK in subfolders. `GET /admin/images` lists all of them with
name and ICCSN. A slot takes a file name (with or without `.xml`), an ICCSN or an absolute path.

Put cards into slots in the YAML file:

```yaml
liana:
  infrastructure:
    terminals:
      KT-01:
        type: fake
        slot-count: 3
        slots:
          1: egk-valid
          2: smcb-valid
          3: hba-valid
```

Your own card images (gematik XML format) are mounted as files into `/opt/liana/images` and then used by name:

```bash
docker run --rm -p 8080:8080 -p 9090:9090 \
  -v ./my-egk.xml:/opt/liana/images/my-egk.xml:ro \
  gematik1/liana:latest
curl -X PUT localhost:9090/admin/terminals/KT-02/slots/1 -H 'Content-Type: application/json' -d '{"image":"my-egk"}'
```

## TLS

LIANA serves the connector interface over HTTPS on port 8443, with the same services as on 8080. TLS follows
gemSpec_Krypt: TLS 1.2 only, ECDHE-ECDSA and ECDHE-RSA with AES-GCM or AES-CBC, curves P-256, P-384,
brainpoolP256r1 and brainpoolP384r1. The management port 9090 answers TLS with the same server identity, without
client authentication.

All certificates are test certificates (`TEST-ONLY`, `NOT-VALID`) issued by the LIANA test CA
[`support/pki/server/komp-ca.pem`](../support/pki/server/komp-ca.pem). Clients that verify the server trust this CA;
the `.kon` export carries it as `trustStore`.

### Settings

| Key (environment variable) | Default | Meaning |
|---|---|---|
| `liana.tls.mandatory` (`LIANA_TLS_MANDATORY`) | `false` | ANCL_TLS_MANDATORY: `true` rejects service calls over HTTP with 403 |
| `liana.tls.dvd-open` (`LIANA_TLS_DVD_OPEN`) | `true` | ANCL_DVD_OPEN: `connector.sds` stays reachable over HTTP even with `mandatory` |
| `liana.tls.client-auth` (`LIANA_TLS_CLIENT_AUTH`) | `false` | ANCL_CAUT_MANDATORY with certificate: the handshake needs a client certificate from `client-certs` |
| `liana.tls.client-certs` (`LIANA_TLS_CLIENT_CERTS`) | CS1, P-256 and brainpoolP256r1 | ANCL_CCERT_LIST: accepted client certificates as PEM files; LIANA checks list membership and expiry |
| `liana.tls.ecc-for-client-systems` (`LIANA_TLS_ECC_FOR_CLIENT_SYSTEMS`) | `true` | TLS_USE_ECC_FOR_CS: `false` switches to the RSA identity |
| `liana.infrastructure.konnektor.gsmc-k.ak-aut` (`LIANA_INFRASTRUCTURE_KONNEKTOR_GSMC_K_AK_AUT`) | P-256 identity | server identity ID.AK.AUT as PKCS#12 |
| `liana.infrastructure.konnektor.gsmc-k.ak-aut-rsa` (`LIANA_INFRASTRUCTURE_KONNEKTOR_GSMC_K_AK_AUT_RSA`) | RSA-2048 identity | server identity when `ecc-for-client-systems` is `false` |
| `liana.infrastructure.konnektor.gsmc-k.password` (`LIANA_INFRASTRUCTURE_KONNEKTOR_GSMC_K_PASSWORD`) | `liana` | password of the PKCS#12 files |
| `liana.kon-export.credentials` | `basic` | `type: pkcs12` with `keystore` and `password` puts a client certificate into the `.kon` export |

`GET /admin/tls` shows the current state: identity, fingerprint, accepted client certificates, cipher suites. The KMS
of the vendor profile can change these settings at runtime, as on a real connector.

### Identities in the image

| File | Use |
|---|---|
| `/opt/liana/pki/server/ak-aut-p256.p12` | ID.AK.AUT on NIST P-256 (default; works with every Java and curl client) |
| `/opt/liana/pki/server/ak-aut-bp256.p12` | ID.AK.AUT on brainpoolP256r1, as on a real gSMC-K; the client needs Brainpool support (e.g. BouncyCastle JSSE) |
| `/opt/liana/pki/server/ak-aut-rsa.p12` | ID.AK.AUT RSA-2048 |
| `/opt/liana/pki/clients/cs1-p256.pem`, `cs1-bp256.pem` | client certificates of CS1 (ANCL_CCERT_LIST) |

The matching client keys are in the repository: [`support/pki/clients/cs1-p256.p12`](../support/pki/clients/) and
`cs1-bp256.p12`, password `liana`.

### Examples

Brainpool server identity, like a real connector:

```bash
docker run --rm -p 8443:8443 -p 9090:9090 \
  -e LIANA_INFRASTRUCTURE_KONNEKTOR_GSMC_K_AK_AUT=/opt/liana/pki/server/ak-aut-bp256.p12 \
  gematik1/liana:latest
```

RSA server identity, HTTP refused for the services:

```bash
docker run --rm -p 8080:8080 -p 8443:8443 -p 9090:9090 \
  -e LIANA_TLS_ECC_FOR_CLIENT_SYSTEMS=false -e LIANA_TLS_MANDATORY=true \
  gematik1/liana:latest
```

TLS with client authentication and a `.kon` export that contains the client certificate. `liana.yaml`:

```yaml
liana:
  tls:
    url: https://localhost:8443
    mandatory: true
    client-auth: true
  kon-export:
    url: https://localhost:8443
    credentials:
      type: pkcs12
      keystore: /opt/liana/pki/clients/cs1-p256.p12
      password: liana
```

```bash
docker run --rm -p 8080:8080 -p 8443:8443 -p 9090:9090 \
  -v ./liana.yaml:/work/config/application.yaml:ro \
  -v ./support/pki/clients/cs1-p256.p12:/opt/liana/pki/clients/cs1-p256.p12:ro \
  gematik1/liana:latest

curl --cacert support/pki/server/komp-ca.pem https://localhost:8443/connector.sds   # handshake fails: no client certificate
curl --cacert support/pki/server/komp-ca.pem --cert-type P12 --cert support/pki/clients/cs1-p256.p12:liana \
  https://localhost:8443/connector.sds                                               # 200
curl -o cs1.kon localhost:9090/admin/clients/CS1/config.kon                          # with client certificate and trustStore
```

The keystore for the `.kon` export is the one file not in the image, hence the second mount.

Your own identity: mount a PKCS#12 file (key and certificate chain) and point `ak-aut` at it. Client certificates of
your client systems go into `client-certs` as PEM files:

```bash
openssl pkcs12 -export -inkey server.key -in server.pem -out pki/server.p12 -passout pass:liana

docker run --rm -p 8443:8443 -p 9090:9090 \
  -v ./pki:/opt/liana/pki/own:ro \
  -e LIANA_INFRASTRUCTURE_KONNEKTOR_GSMC_K_AK_AUT=/opt/liana/pki/own/server.p12 \
  -e LIANA_TLS_CLIENT_AUTH=true \
  -e LIANA_TLS_CLIENT_CERTS=/opt/liana/pki/own/ps1.pem,/opt/liana/pki/own/ps2.pem \
  gematik1/liana:latest
```

One password applies to all PKCS#12 files of `gsmc-k` (`ak-aut`, `ak-aut-rsa`, `sak-aut`); the bundled ones use
`liana`. Protect your own file with `liana` as well, or replace all three and set `password`. A file that does not
open with the password stops LIANA at start-up.

## Docker Compose

```yaml
services:
  liana:
    image: gematik1/liana:0.7.17
    platform: linux/amd64
    ports:
      - "8080:8080"
      - "8443:8443"
      - "9090:9090"
    environment:
      LIANA_KON_EXPORT_URL: http://liana:8080
      LIANA_TLS_URL: https://liana:8443
    volumes:
      - ./liana.yaml:/work/config/application.yaml:ro
    healthcheck:
      test: ["CMD", "./application", "health"]
      interval: 5s
      start_period: 60s

  primary-system:
    image: my/primary-system
    depends_on:
      liana:
        condition: service_healthy
```

Inside the Compose network the other containers reach LIANA as `liana`; the two URLs make `connector.sds` and the
`.kon` export point there instead of `localhost`. `./application health` exits with 0 once LIANA is ready. If you
change the management port, set `LIANA_ADMIN_PORT` as well, the health check reads it.

## Building the image yourself

From a checkout of this repository, without a local JDK:

```bash
docker build -t liana:dev .            # JVM image, same runtime contract as the released image
docker run --rm -p 8080:8080 -p 8443:8443 -p 9090:9090 liana:dev
```

The released image is the native build (`liana-app/src/main/docker/Dockerfile.native-micro` after
`./mvnw package -Dnative`); see the section Docker in [handbuch.md](./handbuch.md).
