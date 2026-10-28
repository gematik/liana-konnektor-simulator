<img align="right" width="250" height="47" src="https://raw.githubusercontent.com/gematik/gematik.github.io/master/Gematik_Logo_Flag_With_Background.png" /> <br />

# Release Notes liana-konnektor-simulator

## Release 0.7.22 (2026-10-28)

### other

- The exclusion list for the license header check (.dependencyLicenses) is published, so the bundled third-party code in liana-app gui/vendor passes the check on GitHub

## Release 0.7.21 (2026-10-28)

### other

- Internal documentation of the release process (order of the release and publish jobs, checks, recovery)

## Release 0.7.20 (2026-10-28)

### other

- README and manual name the Maven Central coordinates of konnektor-client (de.gematik.liana:konnektor-client, with liana-contract)

## Release 0.7.19 (2026-10-28)

### other

- The README starts with the published Docker image; the new page docs/docker.md describes running it: ports, configuration through YAML and environment variables, own card images, TLS (server identities, mandatory TLS, client certificates, .kon export with client certificate) and Docker Compose

## Release 0.7.18 (2026-10-27)

### fixed

- Publication: the DockerHub push logs in with the write token of the gematik1 organisation

## Release 0.7.17 (2026-10-27)

### added

- The container image carries the labels of the gematik Docker guideline (vendor, maintainer, app, repository, commit and version)

## Release 0.7.16 (2026-10-27)

### other

- Publication in two steps: a release builds and tests the sources once more, tags them and opens the pull request on GitHub; after the merge, the container image and the Maven Central artifacts are built from the GitHub sources only

## Release 0.7.15 (2026-10-26)

### other

- Release pipeline: a release builds the native image, publishes it with its version as tag and tags the sources, as the basis for the publication on GitHub, DockerHub and Maven Central

## Release 0.7.14 (2026-10-26)

### added

- konnektor-client and liana-contract are prepared for Maven Central: the POMs carry description, developers, scm and issue management, the build attaches sources and javadoc jars, and the profile `external` signs the artifacts and bundles both modules for Central (without the parent POM)

## Release 0.7.13 (2026-10-26)

### changed

- Beans with constructor injection (admin, KMS, CATS, robot and TLS servers, configuration check) are `@Singleton` instead of `@ApplicationScoped`: without a client proxy Quarkus no longer rewrites their bytecode, so the test coverage counts them (they were measured with 0 % before)

### other

- Security hotspots without impact on a simulator are suppressed with a reason: the masked password in `toString()` of the konnektor-client credentials, the self-test keystore password, regular expressions on configured URLs and bundled schemas

## Release 0.7.12 (2026-10-26)

### fixed

- Flaky tests of the admin event stream: the body of a refused stream (503) is no longer lost, and the latency check of a card insertion no longer counts the client's first request

## Release 0.7.11 (2026-10-26)

### changed

- konnektor-client: the URI constants are named `Signing.CADES_URI`, `Signing.PADES_URI`, `Signing.XADES_URI` and `Authentication.ECDSA_URI`, so they no longer clash with the methods of the same name
- Findings of the SonarQube analysis cleared: members differing only in case renamed, tests without assertions completed; security findings without impact on a simulator (test passwords, test keys, unauthenticated Ereignissenke) are suppressed with a reason

## Release 0.7.10 (2026-10-26)

### security

- Quarkus 3.33.4.1 with Vert.x 4.5.35; jackson-databind 2.21.8 (CVE-2026-110879), Parsson 1.1.8 (CVE-2026-9563) and ASM 9.11.1 (CVE-2026-110257 to CVE-2026-110263, CVE-2026-112046) ahead of the Quarkus BOM

## Release 0.7.9 (2026-10-26)

### fixed

- Flaky test of the delayed CATS card insertion on slow CI agents: the check point now follows from measured times instead of fixed waits

## Release 0.7.8 (2026-10-26)

### changed

- Comments in Maven POMs, configuration (`application.yaml`, Testhub YAMLs), XML resources, test data and stylesheets in English; terms defined by the gematik specifications (e.g. KVNR, Onlineprüfung, Prüfungsnachweis, Fachmodul, Aufrufkontext, Komfortsignatur, Clientsystem) stay German in all comments
- The license check of runtime dependencies also covers the LIANA application (Docker and native image) and runs on every build; BSD-2-Clause and MIT-0 added to the allowlist
- Tests depending on the non-public KMS client are no longer published
- CONTRIBUTING.md describes the formatting check

## Release 0.7.7 (2026-10-23)

### changed

- Java sources formatted with Google Java Format (Spotless); the build checks the formatting, `./mvnw spotless:apply` fixes it
- Unused imports removed

## Release 0.7.6 (2026-10-23)

### changed

- Code comments and Javadoc in English (Java, JavaScript, Python, shell scripts and Dockerfiles); literal quotes from German specifications and test suites stay German

## Release 0.7.5 (2026-10-23)

### added

- Test coverage with JaCoCo for unit and integration tests of all modules, aggregated report in `liana-coverage/target/site/jacoco-aggregate`
- SonarQube analysis in the CI pipeline, fed with the aggregated coverage report

## Release 0.7.4 (2026-10-23)

### security

- Health professional card (HBA) images `hba-valid` and `g20/hba-g20` replaced by newly issued test cards whose certificates are revoked in the OCSP of the TI reference environment, so publishing their private keys grants nothing

## Release 0.7.3 (2026-10-23)

### added

- LIANA, a simulator for the parts of the TI connector (Konnektor) needed by the TI 2.0 Testhub for PoPP, ZETA and VSDM2
- Connector services via HTTP and HTTPS: service directory (`connector.sds`), card, card terminal, event, certificate, signature, encryption and verification services, VSDM ReadVSD
- Card access through the card engine kartos, with simulated card terminals and eHealth card terminals via SICCT
- Event notification of client systems via CETP
- Control Center (web UI) and Admin API on the management port to insert and remove cards, inject faults, script PIN entries and manage the information model
- Management interfaces (KMS) for several connector vendor profiles
- Docker images (JVM and native)
- Java 17 client libraries `konnektor-client`, `liana-contract` and `liana-control-client`, plus a conformance suite to run against any connector
- LICENSE (Apache 2.0), SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md and this file for the publication on GitHub
- Apache 2.0 license header in every source file; the build fails on a missing header (`license.header.txt`)
- License texts of Preact (MIT) and htm (Apache 2.0) next to the bundled `preact-htm.js` of the Control Center
- License declaration in the parent POM, inherited by all modules
- License notices of the Rust crates linked into kartos (`tools/kartos/THIRD-PARTY-NOTICES.txt`), also in the Docker images under `/opt/liana/licenses/kartos/`
- OWASP Dependency Check as Maven profile `owasp`, fails on critical findings (CVSS 9 and above)

### changed

- README in English; the detailed German manual moved to `docs/handbuch.md`
- Test data recorded from or signed by connector vendor products moved to `support/vendor/`, including the trace `popp-kon-tu`; tests using it carry the JUnit tag `vendor-data` and are skipped when the folder is missing
- Docker build context described as allowlist
- `konnektor-client/CHANGELOG.md` removed; all changes are listed in this file
- Manual without instructions that need gematik-internal access (image registry, Maven repository, CI)
- Tests using `tiger-cats-extensions` moved to `liana-trace-tests/src/test-cats/java` and only run when that folder exists
- Card image `smcb-valid` is now the public SMC-B 80276883110000168650 from gematik/ti2.0-testhub (Praxis Münchhausen-Hohenfels), with PIN.SMC set to 123456
