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
package de.gematik.liana.soap;

import static de.gematik.liana.soap.EventServiceTest.bodyElement;
import static de.gematik.liana.soap.EventServiceTest.getCards;
import static de.gematik.liana.soap.EventServiceTest.xpath;
import static de.gematik.liana.soap.SignDocumentKartosIT.post;
import static de.gematik.liana.soap.SignDocumentKartosIT.signDocument;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.TestPorts;
import de.gematik.liana.crypto.XadesSignatures;
import de.gematik.liana.kern.signature.SignatureVerifier.Signer;
import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.time.Clock;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

/**
 * XAdES from the built artifact (LIANA-112.09, decision-023): with {@code -Dnative} against the
 * native image, i.e. JSR 105 with the card provider, XPath for XPathFirstChildOf (reflection,
 * {@code crypto.XPathFunctions}), Latin-9 and the NFD schema; otherwise against {@code
 * quarkus-run.jar}. hba-valid in KT-01/3, the simulated PIN pad enters PIN.QES.
 */
@QuarkusIntegrationTest
@TestProfile(XadesIT.Profile.class)
class XadesIT {

  public static class Profile implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return TestPorts.config("liana.infrastructure.terminals.KT-01.slots.3", "hba-valid");
    }
  }

  private static final Path XADES = Path.of("support/signatures/xades");
  private static final Path SIGNED = Path.of("support/vendor/signatures/xades");
  static final String NFDM =
      "<ns3:SignatureType>urn:ietf:rfc:3275</ns3:SignatureType>"
          + "<ns3:SignaturePlacement WhichDocument=\"DokumentID\" CreateEnvelopedSignature=\"false\">"
          + "<ns3:XPathFirstChildOf>/*[local-name()='NFD_Document']/*[local-name()='SignatureArzt']"
          + "</ns3:XPathFirstChildOf></ns3:SignaturePlacement><sp:GenerateUnderSignaturePolicy "
          + "xmlns:sp=\"urn:oasis:names:tc:dss-x:1.0:profiles:SignaturePolicy:schema#\"><sp:SignaturePolicyIdentifier>"
          + "urn:gematik:fa:sak:nfdm:r1:v1</sp:SignaturePolicyIdentifier></sp:GenerateUnderSignaturePolicy>";

  @BeforeAll
  static void bouncyCastle() {
    // the test verifies the signature itself, with BC like LIANA (brainpool)
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  private static String hba() throws Exception {
    String xml =
        given()
            .contentType("text/xml; charset=utf-8")
            .header("SOAPAction", "\"http://ws.gematik.de/conn/EventService/v7.2#GetCards\"")
            .body(
                getCards(
                    "M1",
                    "CS1",
                    "WP1",
                    "<ns5:CtId>KT-01</ns5:CtId><ns5:CardType>HBA</ns5:CardType>"))
            .post("/ws/EventService")
            .then()
            .statusCode(200)
            .extract()
            .asString();
    return xpath(bodyElement(xml), "//*[local-name()='Card'][1]/*[local-name()='CardHandle']");
  }

  @Test
  @DisplayName(
      "TIP1-A_5538 XAdES unter NFDM mit dem HBA aus dem Artefakt: OK, Signatur in SignatureArzt gültig, "
          + "Dokument bleibt ISO-8859-15")
  void nfdmAusDemArtefakt() throws Exception {
    byte[] nfd = Files.readAllBytes(XADES.resolve("NFDM_Beispiel_1.4.xml"));
    String body =
        signDocument(
                hba(),
                "NAT-X01",
                NFDM,
                "<ns2:Base64XML>" + Base64.getEncoder().encodeToString(nfd) + "</ns2:Base64XML>",
                false)
            .replace(
                "<ns4:Document ID=\"DokumentID\" ",
                "<ns4:Document ID=\"DokumentID\" RefURI=\"#Notfalldaten\" ");
    Element response = post(body, 200);
    assertEquals("OK", xpath(response, "//*[local-name()='Status']/*[local-name()='Result']"));
    byte[] signed =
        Base64.getDecoder()
            .decode(
                xpath(
                    response,
                    "//*[local-name()='DocumentWithSignature']/*[local-name()='Base64XML']"));
    assertTrue(new String(signed, 0, 80, StandardCharsets.US_ASCII).contains("ISO-8859-15"));
    List<Signer> signers = new XadesSignatures(Clock.systemUTC()).verify(signed);
    assertEquals(1, signers.size());
    assertEquals(List.of(), signers.get(0).problems());
  }

  @Test
  @Tag("vendor-data")
  @DisplayName("TIP1-A_5505 TUC_KON_162 aus dem Artefakt: NFD-Signatur von KOCO (ECC) → OK, VALID")
  void verifyAusDemArtefakt() throws Exception {
    String document =
        "<ns4:Document ID=\"DocumentID\"><ns2:Base64XML>"
            + Base64.getEncoder()
                .encodeToString(Files.readAllBytes(SIGNED.resolve("IOP-ECC/nfdm.koco.ecc.xml.sig")))
            + "</ns2:Base64XML></ns4:Document>";
    Element response =
        VerifyDocumentTest.post(
            VerifyDocumentTest.verifyDocument(document, null, null, null, false), 200);
    assertEquals("VALID", xpath(response, "//*[local-name()='HighLevelResult']"));
  }
}
