/*
 * Copyright 2026 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */
package de.gematik.liana.crypto;

import static de.gematik.liana.crypto.ReplaySigner.Issuer.FOREIGN_KEY;
import static de.gematik.liana.crypto.ReplaySigner.Issuer.UNKNOWN_CA;
import static de.gematik.liana.crypto.ReplaySigner.Profile.poppService;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.gematik.liana.crypto.ReplaySigner.Profile;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * TUC_KON_037 for the signer of a SignedScenario (TAB_KON_271 step 2) against the RU TSL from
 * {@code support/pki/tsl/} and the imported replay CA.
 */
class ScenarioSignerCheckTest {

  static final Path TSL = Path.of("support/pki/tsl/ECC-RSA_TSL-ref.xml");
  static final Path REPLAY_CA = Path.of("support/pki/replay/replay-ca.pem");

  private static ScenarioSignerCheck check;

  @BeforeAll
  static void trustSpace() {
    if (Security.getProvider(CryptoProviders.BC) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    check = new ScenarioSignerCheck(TrustSpace.load(TSL, List.of(REPLAY_CA)), Clock.systemUTC());
  }

  /** Certificates from {@code support/pki/popp/} (SOURCE.md). */
  private static X509Certificate popp(String file) throws Exception {
    return (X509Certificate)
        CertificateFactory.getInstance("X.509")
            .generateCertificate(
                new ByteArrayInputStream(Files.readAllBytes(Path.of("support/pki/popp", file))));
  }

  private static ConnectorError error(X509Certificate signer) {
    return assertThrows(ConnectorException.class, () -> check.check(signer)).error();
  }

  private static ConnectorError error(Profile profile) throws Exception {
    return error(ReplaySigner.issue(profile).certificate());
  }

  @Nested
  @DisplayName("Signer der PoPP-Services, Aussteller aus der TSL")
  class Tsl {

    @Test
    @DisplayName(
        "TUC_KON_037: PoPP-Service der TU (popp-kon-tu, GEM.KOMP-CA55, oid_popp) ist gültig")
    void tu() throws Exception {
      assertDoesNotThrow(() -> check.check(popp("tu-apdu-sig-oid_popp.pem")));
    }

    @Test
    @DisplayName(
        "TUC_KON_037: PoPP-Service des Testhubs und der Konnektor-Testsuite (GEM.KOMP-CA61, oid_popp) ist gültig")
    void testhub() throws Exception {
      assertDoesNotThrow(() -> check.check(popp("bridge-oid_popp.pem")));
    }

    @Test
    @DisplayName(
        "TAB_KON_272 4700: Token-Signer des PoPP-Service (oid_popp-token), wie EE_KON_POPP_FF_013")
    void poppToken() throws Exception {
      assertEquals(ConnectorError.CERT_ROLE, error(popp("bridge-oid_popp-token.pem")));
    }

    @Test
    @DisplayName(
        "TAB_KON_272 4700: TI-Gateway-Zugangsmodul (oid_tigw_zugm, C.FD.OSIG), wie EE_KON_POPP_FF_016 – "
            + "die Rolle geht vor dem Zertifikatstyp")
    void tigw() throws Exception {
      assertEquals(ConnectorError.CERT_ROLE, error(popp("bridge-oid_tigw_zugm.pem")));
    }
  }

  @Nested
  @DisplayName(
      "Signer der Replay-CA (CERT_IMPORTED_CA_LIST), je eine Abweichung vom Profil des PoPP-Service")
  class Imported {

    @Test
    @DisplayName(
        "TUC_KON_037 1a: Profil des PoPP-Service (C.ZD.SIG, nonRepudiation, oid_popp) ist gültig")
    void profil() throws Exception {
      assertDoesNotThrow(() -> check.check(ReplaySigner.issue(poppService()).certificate()));
      assertDoesNotThrow(() -> check.check(ReplaySigner.signer().certificate()));
    }

    @Test
    @DisplayName("TUC_PKI_018 1 → 1021: abgelaufen")
    void abgelaufen() throws Exception {
      assertEquals(
          ConnectorError.CERTIFICATE_NOT_VALID_TIME,
          error(poppService().expiredAt(Instant.now().minusSeconds(60))));
    }

    @Test
    @DisplayName("TUC_PKI_018 2a → 1016: KeyUsage digitalSignature statt nonRepudiation")
    void keyUsage() throws Exception {
      assertEquals(
          ConnectorError.WRONG_KEYUSAGE,
          error(poppService().withKeyUsage(KeyUsage.digitalSignature)));
    }

    @Test
    @DisplayName("TUC_PKI_003 → 1027: Aussteller weder in der TSL noch importiert")
    void unbekannteCa() throws Exception {
      assertEquals(ConnectorError.CA_CERT_MISSING, error(poppService().issuedBy(UNKNOWN_CA)));
    }

    @Test
    @DisplayName(
        "TUC_PKI_004 → 1024: Name der Replay-CA, aber von einem fremden Schlüssel signiert")
    void mathematik() throws Exception {
      assertEquals(
          ConnectorError.CERTIFICATE_NOT_VALID_MATH, error(poppService().issuedBy(FOREIGN_KEY)));
    }

    @Test
    @DisplayName("TAB_KON_272 4700: Rolle oid_popp-token statt oid_popp")
    void rolle() throws Exception {
      assertEquals(
          ConnectorError.CERT_ROLE, error(poppService().withRole(ReplaySigner.OID_POPP_TOKEN)));
    }

    @Test
    @DisplayName(
        "TUC_PKI_018 9 → 1018: Rolle oid_popp, aber Zertifikatstyp C.FD.OSIG statt C.ZD.SIG")
    void zertifikatstyp() throws Exception {
      assertEquals(
          ConnectorError.CERT_TYPE_MISMATCH,
          error(poppService().withPolicy(ReplaySigner.OID_FD_OSIG)));
    }
  }
}
