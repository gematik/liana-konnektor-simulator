# syntax=docker/dockerfile:1
# Dev image (LIANA-14): JVM mode, buildable without a local JDK/Maven.
# Build: docker build -t liana:dev .   The release artifact remains the native image (liana-app/src/main/docker/Dockerfile.native-micro).
# Runtime contract as for native: /work, config/application.yaml, /opt/liana/images, /opt/liana/pki, /opt/liana/bin/kartos, ports 8080/8443 (HTTPS)/9090 (management: Admin API, KMS and CATS, HTTP and HTTPS), user 1001.

FROM eclipse-temurin:21-jdk AS build
WORKDIR /src
COPY mvnw pom.xml license.header.txt ./
COPY .mvn/wrapper/maven-wrapper.properties .mvn/wrapper/
COPY liana-kern/pom.xml liana-kern/
COPY liana-adapter-fake-terminal/pom.xml liana-adapter-fake-terminal/
COPY liana-adapter-sicct/pom.xml liana-adapter-sicct/
COPY liana-adapter-cetp/pom.xml liana-adapter-cetp/
COPY liana-adapter-sds/pom.xml liana-adapter-sds/
COPY liana-adapter-soap/pom.xml liana-adapter-soap/
COPY liana-adapter-vsdm/pom.xml liana-adapter-vsdm/
COPY liana-app/pom.xml liana-app/
COPY liana-trace-tests/pom.xml liana-trace-tests/
# Client modules (decision-016) only as POM so that the reactor is complete; liana-contract with content, the
# request validation needs the schemas (LIANA-48)
COPY liana-contract/pom.xml liana-contract/
COPY konnektor-client/pom.xml konnektor-client/
COPY liana-control-client/pom.xml liana-control-client/
COPY konnektor-client-conformance/pom.xml konnektor-client-conformance/
COPY liana-coverage/pom.xml liana-coverage/
COPY liana-kern/src/main liana-kern/src/main
COPY liana-adapter-fake-terminal/src/main liana-adapter-fake-terminal/src/main
COPY liana-adapter-sicct/src/main liana-adapter-sicct/src/main
COPY liana-adapter-cetp/src/main liana-adapter-cetp/src/main
COPY liana-adapter-sds/src/main liana-adapter-sds/src/main
COPY liana-adapter-soap/src/main liana-adapter-soap/src/main
COPY liana-adapter-vsdm/src/main liana-adapter-vsdm/src/main
COPY liana-contract/src/main liana-contract/src/main
COPY support/schemas support/schemas
# konnektor-client (test scope of liana-app, via -am in the reactor) generates its JAXB bindings from the schemas
COPY konnektor-client/src/main/xjb konnektor-client/src/main/xjb
COPY liana-app/src/main liana-app/src/main
# Maven repo and wrapper distribution in the BuildKit cache: a rebuild after a code change downloads nothing again.
RUN --mount=type=cache,target=/root/.m2 \
    ./mvnw -B -q package -pl liana-app -am -Dmaven.test.skip=true

# Fresh TSL (LIANA-180): fetches the RU TSL, on error or an older SequenceNumber the checked-in copy; never
# fails. TSL_REFRESH (CI: build number) forces a new fetch, otherwise the build cache applies. Source and SequenceNumber
# appear in the build log (--progress=plain).
FROM registry.access.redhat.com/ubi9/ubi-minimal AS tsl
ARG TSL_URL=https://download-ref.tsl.ti-dienste.de/ECC/ECC-RSA_TSL-ref.xml
ARG TSL_REFRESH=
COPY support/pki/tsl/ECC-RSA_TSL-ref.xml /tsl/baseline.xml
COPY tools/pki/tsl-fetch.sh /tsl/tsl-fetch.sh
RUN echo "TSL_REFRESH=${TSL_REFRESH}" && sh /tsl/tsl-fetch.sh /tsl/baseline.xml /tsl/out/ECC-RSA_TSL-ref.xml "$TSL_URL"

FROM eclipse-temurin:21-jre
ARG TARGETARCH
WORKDIR /work/
RUN chown 1001:root /work && chmod g+rwX /work
COPY --from=build --chown=1001:root /src/liana-app/target/quarkus-app /work/quarkus-app
COPY --chown=1001:root support/images /opt/liana/images
COPY --chown=1001:root --from=tsl /tsl/out/ECC-RSA_TSL-ref.xml /opt/liana/pki/
COPY --chown=1001:root support/pki/tsl/BNetzA-VL.xml /opt/liana/pki/
ENV LIANA_PKI_TSL=/opt/liana/pki/ECC-RSA_TSL-ref.xml \
    LIANA_PKI_BNETZA_VL=/opt/liana/pki/BNetzA-VL.xml
# Konnektor TLS (LIANA-58): ID.AK.AUT and ANCL_CCERT_LIST from the test PKI, without the CA key
COPY --chown=1001:root support/pki/server/ak-aut-p256.p12 support/pki/server/ak-aut-bp256.p12 support/pki/server/ak-aut-rsa.p12 support/pki/server/sak-aut-bp256.p12 /opt/liana/pki/server/
COPY --chown=1001:root support/pki/clients/cs1-p256.pem support/pki/clients/cs1-bp256.pem /opt/liana/pki/clients/
ENV LIANA_INFRASTRUCTURE_KONNEKTOR_GSMC_K_AK_AUT=/opt/liana/pki/server/ak-aut-p256.p12 \
    LIANA_INFRASTRUCTURE_KONNEKTOR_GSMC_K_AK_AUT_RSA=/opt/liana/pki/server/ak-aut-rsa.p12 \
    LIANA_INFRASTRUCTURE_KONNEKTOR_GSMC_K_SAK_AUT=/opt/liana/pki/server/sak-aut-bp256.p12 \
    LIANA_TLS_CLIENT_CERTS=/opt/liana/pki/clients/cs1-p256.pem,/opt/liana/pki/clients/cs1-bp256.pem
COPY --chown=1001:root tools/kartos/kartos-linux-${TARGETARCH} /opt/liana/bin/kartos
COPY --chown=1001:root tools/kartos/LICENSE tools/kartos/THIRD-PARTY-NOTICES.txt /opt/liana/licenses/kartos/

EXPOSE 8080 8443 9090
USER 1001
# Readiness via GET /admin/ready (LIANA-107), queried by the binary itself: the base image lacks curl, wget and grep.
# Admin port from LIANA_ADMIN_PORT, otherwise 9090. Generous start period for amd64 under emulation.
HEALTHCHECK --interval=5s --timeout=5s --start-period=60s --retries=3 CMD ["java", "-XX:TieredStopAtLevel=1", "-jar", "quarkus-app/quarkus-run.jar", "health"]

ENTRYPOINT ["java", "-Dquarkus.http.host=0.0.0.0", "-jar", "quarkus-app/quarkus-run.jar"]
