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

import static de.gematik.liana.crypto.ScenarioSignerCheckTest.REPLAY_CA;
import static de.gematik.liana.crypto.ScenarioSignerCheckTest.TSL;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TrustSpaceTest {

  private static TrustSpace trustSpace;

  @BeforeAll
  static void load() {
    if (Security.getProvider(CryptoProviders.BC) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    trustSpace = TrustSpace.load(TSL, List.of(REPLAY_CA));
  }

  private static X509Certificate popp(String file) throws Exception {
    return (X509Certificate)
        CertificateFactory.getInstance("X.509")
            .generateCertificate(
                new ByteArrayInputStream(Files.readAllBytes(Path.of("support/pki/popp", file))));
  }

  @Test
  @DisplayName(
      "TUC_PKI_013: CA-Zertifikate aus TSPService CA/PKC der RU-TSL, Kopfdaten für das Log")
  void tsl() {
    TrustSpace.TslInfo info = trustSpace.tsl();
    assertEquals("10713", info.sequenceNumber());
    assertEquals("2026-10-31T06:55:22Z", info.nextUpdate());
    assertTrue(info.caCount() > 50, info.caCount() + " CA-Zertifikate");
    assertEquals(1, trustSpace.importedCount());
  }

  @Test
  @DisplayName(
      "TUC_PKI_003: Aussteller über Name und AuthorityKeyIdentifier – GEM.KOMP-CA55 und -CA61 aus der TSL")
  void ausstellerAusTsl() throws Exception {
    var tu = trustSpace.issuerOf(popp("tu-apdu-sig-oid_popp.pem")).orElseThrow();
    assertEquals(TrustSpace.Source.TSL, tu.source());
    assertTrue(
        tu.certificate().getSubjectX500Principal().getName().contains("GEM.KOMP-CA55 TEST-ONLY"));
    var testhub = trustSpace.issuerOf(popp("bridge-oid_popp.pem")).orElseThrow();
    assertTrue(
        testhub
            .certificate()
            .getSubjectX500Principal()
            .getName()
            .contains("GEM.KOMP-CA61 TEST-ONLY"));
  }

  @Test
  @DisplayName("TUC_KON_037 1a: Aussteller aus CERT_IMPORTED_CA_LIST")
  void ausstellerImportiert() throws Exception {
    assertEquals(
        TrustSpace.Source.IMPORTED,
        trustSpace.issuerOf(ReplaySigner.signer().certificate()).orElseThrow().source());
  }

  @Test
  @DisplayName("Fehlende oder kaputte TSL bricht den Start ab")
  void kaputteTsl(@TempDir Path dir) throws Exception {
    assertThrows(
        IllegalStateException.class, () -> TrustSpace.load(dir.resolve("fehlt.xml"), List.of()));
    Path empty = Files.writeString(dir.resolve("leer.xml"), "<TrustServiceStatusList/>");
    assertThrows(IllegalStateException.class, () -> TrustSpace.load(empty, List.of()));
    Path broken = Files.writeString(dir.resolve("kaputt.xml"), "<TrustServiceStatusList>");
    assertThrows(IllegalStateException.class, () -> TrustSpace.load(broken, List.of()));
  }
}
