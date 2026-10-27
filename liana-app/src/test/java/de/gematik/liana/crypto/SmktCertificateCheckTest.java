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

import static de.gematik.liana.crypto.ScenarioSignerCheckTest.TSL;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * TUC_KON_050 step 3: TUC_KON_037 for the KT certificate C.SMKT.AUT ({@code policyList =
 * oid_smkt_aut}, {@code intendedExtendedKeyUsage = id-kp-serverAuth}, {@code validationMode =
 * NONE}) against the TSL.
 */
class SmktCertificateCheckTest {

  static final Clock TODAY = Clock.fixed(Instant.parse("2026-10-10T12:00:00Z"), ZoneOffset.UTC);
  private static TrustSpace trustSpace;

  @BeforeAll
  static void load() {
    if (Security.getProvider(CryptoProviders.BC) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    trustSpace = TrustSpace.load(TSL, List.of());
  }

  /** The certificate from EF {@code efId} of a card image under {@code support/images/}. */
  static X509Certificate fromImage(String image, String efId) throws Exception {
    String xml = Files.readString(Path.of("support/images", image));
    Matcher m =
        Pattern.compile(
                "<child id=\"" + Pattern.quote(efId) + "\".*?id=\"body\">([0-9A-F]+)<",
                Pattern.DOTALL)
            .matcher(xml);
    assertTrue(m.find(), efId + " in " + image);
    return (X509Certificate)
        CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(HexFormat.of().parseHex(m.group(1))));
  }

  private static void assertRejected(String expected, Executable check) {
    CertificateException e = assertThrows(CertificateException.class, check);
    assertTrue(e.getMessage().contains(expected), e.getMessage());
  }

  @Test
  @DisplayName(
      "TUC_KON_050 Schritt 3: C.SMKT.AUT der gsmckt-valid (GEM.KOMP-CA51, oid_smkt_aut, serverAuth) besteht")
  void gueltig() throws Exception {
    X509Certificate smkt = fromImage("gsmckt-valid.xml", "EF.C.SMKT.AUT2.XXXX");
    SmktCertificateCheck check = SmktCertificateCheck.of(trustSpace, TODAY);
    assertDoesNotThrow(() -> check.check(smkt));
    assertDoesNotThrow(() -> check.checkServerTrusted(new X509Certificate[] {smkt}, "ECDHE_ECDSA"));
  }

  @Test
  @DisplayName(
      "TUC_PKI_018 Gültigkeitszeitraum: nach dem 18.07.2028 ist das KT-Zertifikat abgelaufen")
  void abgelaufen() throws Exception {
    X509Certificate smkt = fromImage("gsmckt-valid.xml", "EF.C.SMKT.AUT2.XXXX");
    Clock later = Clock.fixed(Instant.parse("2028-07-20T00:00:00Z"), ZoneOffset.UTC);
    assertRejected(
        "zeitlich ungültig", () -> SmktCertificateCheck.of(trustSpace, later).check(smkt));
  }

  @Test
  @DisplayName(
      "Fremdzertifikat: ID.AK.AUT von LIANAs eigener Komp-CA hat serverAuth, ihr Aussteller steht aber nicht "
          + "in der TSL")
  void ausstellerUnbekannt() throws Exception {
    X509Certificate foreign =
        (X509Certificate)
            CertificateFactory.getInstance("X.509")
                .generateCertificate(
                    Files.newInputStream(Path.of("support/pki/server/ak-aut-bp256.pem")));
    assertRejected(
        "weder in der TSL", () -> SmktCertificateCheck.of(trustSpace, TODAY).check(foreign));
  }

  @Test
  @DisplayName(
      "Fremdzertifikat: C.HCI.AUT der smcb-valid stammt aus der TSL, ist aber kein C.SMKT.AUT")
  void keinKtZertifikat() throws Exception {
    X509Certificate hci = fromImage("smcb-valid.xml", "EF.C.HCI.AUT.E256");
    CertificateException e =
        assertThrows(
            CertificateException.class,
            () -> SmktCertificateCheck.of(trustSpace, TODAY).check(hci));
    assertTrue(
        e.getMessage().contains("serverAuth") || e.getMessage().contains("oid_smkt_aut"),
        e.getMessage());
  }

  @Test
  @DisplayName("Ohne Zertifikat kein Handshake; Client-Zertifikate prüft die KT-Prüfung nicht")
  void randfaelle() {
    SmktCertificateCheck check = SmktCertificateCheck.of(trustSpace, TODAY);
    assertThrows(
        CertificateException.class,
        () -> check.checkServerTrusted(new X509Certificate[0], "ECDHE_ECDSA"));
    assertThrows(
        CertificateException.class,
        () -> check.checkClientTrusted(new X509Certificate[0], "ECDHE_ECDSA"));
  }
}
