<img align="right" width="250" height="47" src="https://raw.githubusercontent.com/gematik/gematik.github.io/master/Gematik_Logo_Flag_With_Background.png"/> <br/>

# liana-konnektor-simulator

<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#release-notes">Release Notes</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>

## About The Project

<p align="center">
  <img src="docs/img/liana-logo.svg" alt="LIANA" width="338">
</p>

LIANA simulates the part of the TI connector (Konnektor) that the TI 2.0 Testhub needs for **PoPP**, **ZETA** and
**VSDM2**: card access, eventing and the information model. Its external communication is verified against golden
traces recorded from real systems.

LIANA is meant for test teams and for developers of primary systems (Primärsysteme) who need a connector they can
control: insert and remove cards, inject faults, script PIN entries and inspect every request, without hardware.

- Connector services via HTTP (8080) and HTTPS (8443): `connector.sds` and the SOAP services under `/ws/*`
- Management port 9090: Control Center (web UI), Admin API (`/admin/*`), vendor management interfaces (KMS)
- Cards are simulated by the card engine kartos, terminals either as simulated terminals or as eHealth card
  terminals via SICCT
- Java 17 client libraries for primary systems and test suites: `konnektor-client`, `liana-contract`,
  `liana-control-client`

### Release Notes

See [ReleaseNotes.md](./ReleaseNotes.md) for all information regarding the (newest) releases.

## Getting Started

### Prerequisites

- Docker to run LIANA, or Java 21 to build and run it from source
- Java 17 or later to use the client libraries

### Installation

The main way to run LIANA is the Docker image [`gematik1/liana`](https://hub.docker.com/r/gematik1/liana). It
contains the card engine kartos, test cards, the test PKI and a current TSL, so nothing else is needed:

```bash
docker run --rm --name liana -p 8080:8080 -p 8443:8443 -p 9090:9090 gematik1/liana:latest
curl -s localhost:9090/admin/ready   # {"ready":true}
```

The image is built for `linux/amd64`; on Apple Silicon add `--platform linux/amd64`. Configuration (YAML file or
environment variables), your own card images, TLS with client certificates and a Docker Compose example are
described in [docs/docker.md](./docs/docker.md).

To build from source, either build the image yourself (no local JDK needed) or use Maven:

```bash
docker build -t liana:dev .
./mvnw verify          # build and run the tests
./mvnw quarkus:dev     # start LIANA in development mode
```

The connector client is on Maven Central (it brings `liana-contract` with the WSDL and XSD files along); use the
version of the LIANA release:

```xml
<dependency>
  <groupId>de.gematik.liana</groupId>
  <artifactId>konnektor-client</artifactId>
  <version>0.7.17</version>
</dependency>
```

The client for the Admin API, `liana-control-client`, is not published yet; install it into the local Maven
repository with:

```bash
./mvnw install -pl liana-control-client -am -DskipTests
```

## Usage

Open the Control Center at http://localhost:9090/ to see terminals, cards, subscriptions, TLS settings and the
system log.

Read the certificate of the SMC-B from LIANA with the connector client:

```bash
curl -o praxis.kon localhost:9090/admin/clients/CS1/config.kon
```

```java
try (Konnektor kon = Konnektor.fromKon(Path.of("praxis.kon"))) {
    Card smcb = kon.cards().ofType("SM-B").get(0);
    System.out.println(kon.card(smcb).certificate("C.AUT").asPem());
}
```

Control LIANA from a test through the Admin API:

```java
LianaControl liana = LianaControl.connect("http://localhost:9090");
liana.awaitReady(Duration.ofSeconds(30));
liana.insertCard("KT-02", 1, "egk-valid");
liana.setFault("KT-01", 1, Fault.statusWord("6A82").commandPrefix("00B0").count(1));
liana.reset();
```

For more examples or in-depth documentation, please refer to:

- [docs/docker.md](./docs/docker.md): running the Docker image: ports, configuration, card images, TLS, Compose
- [docs/handbuch.md](./docs/handbuch.md): the full manual (German): ports, Admin API, KMS, TLS, Docker
  configuration, card images, Testhub setups
- [docs/architektur.md](./docs/architektur.md): architecture diagram
- [konnektor-client/examples](./konnektor-client/examples): client examples

## Contributing

If you want to contribute, please check our [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

Copyright 2026 gematik GmbH

Apache License, Version 2.0

See the [LICENSE](./LICENSE) for the specific language governing permissions and limitations under the License

Third-party components shipped in this repository come with their own license texts:
[kartos](./tools/kartos/LICENSE) and its [Rust dependencies](./tools/kartos/THIRD-PARTY-NOTICES.txt),
[Preact and htm](./liana-app/src/main/resources/gui/vendor/) in the Control Center.

## Additional Notes and Disclaimer from gematik GmbH

1. Copyright notice: Each published work result is accompanied by an explicit statement of the license conditions for
   use. These are regularly typical conditions in connection with open source or free software. Programs
   described/provided/linked here are free software, unless otherwise stated.
2. Permission notice: Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
   associated documentation files (the "Software"), to deal in the Software without restriction, including without
   limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
   Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
    1. The copyright notice (Item 1) and the permission notice (Item 2) shall be included in all copies or substantial
       portions of the Software.
    2. The software is provided "as is" without warranty of any kind, either express or implied, including, but not
       limited to, the warranties of fitness for a particular purpose, merchantability, and/or non-infringement. The
       authors or copyright holders shall not be liable in any manner whatsoever for any damages or other claims arising
       from, out of or in connection with the software or the use or other dealings with the software, whether in an
       action of contract, tort, or otherwise.
    3. The software is the result of research and development activities, therefore not necessarily quality assured and
       without the character of a liable product. For this reason, gematik does not provide any support or other user
       assistance (unless otherwise stated in individual cases and without justification of a legal obligation).
       Furthermore, there is no claim to further development and adaptation of the results to a more current state of
       the art.
3. Gematik may remove published results temporarily or permanently from the place of publication at any time without
   prior notice or justification.
4. Please note: Parts of this code may have been generated using AI-supported technology. Please take this into account,
   especially when troubleshooting, for security analyses and possible adjustments.

## Contact

We take open source license compliance very seriously. We are always striving to achieve compliance at all times and to
improve our processes.
This software is currently being tested to ensure its technical quality and legal compliance. Your feedback is highly
valued.
If you find any issues or have any suggestions or comments, or if you see any other ways in which we can improve, please
reach out to: tiger@gematik.de
