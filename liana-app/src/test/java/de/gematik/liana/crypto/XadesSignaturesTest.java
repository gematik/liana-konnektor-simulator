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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import de.gematik.liana.kern.event.SystemLog;
import de.gematik.liana.kern.signature.SignatureVerifier.Signer;
import de.gematik.liana.kern.signature.XmlSignatures;
import de.gematik.liana.kern.vendor.PeerDeviations;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * XAdES with JSR 105 (decision-023, LIANA-112.09) with Konnektor-QES files under {@code
 * support/signatures/xades} (originals) and {@code support/vendor/signatures/xades} (vendor
 * signatures): vendor NFD signatures (KUC_1607_009/010/014, 208/209/213), signing under the NFDM
 * policy, TUC_KON_080 (A) and Latin-9.
 */
class XadesSignaturesTest {

  static final Path XADES = Path.of("support/signatures/xades");
  static final Path SIGNED = Path.of("support/vendor/signatures/xades");
  private static final Instant NOW = Instant.parse("2026-10-19T12:00:00Z");
  private static final XadesSignatures XML = new XadesSignatures(Clock.fixed(NOW, ZoneOffset.UTC));
  private static final String SIGNATURE_ARZT =
      "/*[local-name()='NFD_Document']/*[local-name()='SignatureArzt']";
  private static CmsVerifier verifier;

  @BeforeAll
  static void load() {
    if (Security.getProvider(CryptoProviders.BC) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    verifier =
        new CmsVerifier(
            TrustSpace.load(
                ScenarioSignerCheckTest.TSL, List.of(), Path.of("support/pki/tsl/BNetzA-VL.xml")),
            new PeerDeviations(false, new SystemLog(Clock.systemUTC(), 100)),
            Clock.systemUTC());
  }

  private static byte[] read(String file) throws Exception {
    return Files.readAllBytes(XADES.resolve(file));
  }

  private static byte[] readSigned(String file) throws Exception {
    return Files.readAllBytes(SIGNED.resolve(file));
  }

  static Stream<String> interop() {
    return Stream.of(
        "IOP-ECC/nfdm.koco.ecc.xml.sig",
        "IOP-ECC/nfdm.rise.ecc.xml.sig",
        "IOP-ECC/nfdm.secu.ecc.xml.sig",
        "sig.NFDM_Beispiel_1.4.koco.4.2.1.20.NFDM.xml",
        "sig.NFDM_Beispiel_1.4.rise.2.0.12.NFDM.xml",
        "sig.NFDM_Beispiel_1.4.secu.4.10.1.NFDM.xml");
  }

  @Tag("vendor-data")
  @ParameterizedTest
  @MethodSource("interop")
  @DisplayName(
      "TIP1-A_5505 TUC_KON_162, TIP1-A_5538: NFD-Signaturen der Hersteller (ECC und RSASSA-PSS) gültig, "
          + "Zertifikat qualifiziert und gültig, Richtlinie NFDM, Dokument valide gegen das NFD-Schema")
  void interopValid(String file) throws Exception {
    byte[] document = readSigned(file);
    List<Signer> signers = XML.verify(document);
    assertEquals(1, signers.size());
    List<String> problems = new ArrayList<>();
    for (Signer signer : signers) {
      assertTrue(signer.qualified());
      signer.problems().forEach(p -> problems.add(p.error().code() + " " + p.detail()));
      verifier
          .checkCertificate(
              signer.certificate(), signer.qualified(), signer.signingTime().orElseThrow())
          .ifPresent(p -> problems.add(p.error().code() + " " + p.detail()));
    }
    assertEquals(List.of(), problems);
    assertEquals(XmlSignatures.NFDM_POLICY, XML.signaturePolicy(document));
    XML.validate(document, XmlSignatures.NFDM_POLICY);
  }

  @Test
  @Tag("vendor-data")
  @DisplayName("TUC_KON_162: ein Zeichen im signierten Element verändert → 4115")
  void manipulated() throws Exception {
    String text =
        new String(readSigned("IOP-ECC/nfdm.koco.ecc.xml.sig"), StandardCharsets.ISO_8859_1)
            .replace("<Vorname>Sarah</Vorname>", "<Vorname>Sahra</Vorname>");
    List<Signer> signers = XML.verify(text.getBytes(StandardCharsets.ISO_8859_1));
    assertEquals(
        ConnectorError.DOCUMENT_SIGNATURE_INVALID, signers.get(0).problems().get(0).error());
  }

  private static XmlSignatures.Request request(byte[] document, PadesSignaturesTest.Key key) {
    return new XmlSignatures.Request(
        document,
        key.certificate(),
        "shortText",
        "#Notfalldaten",
        SIGNATURE_ARZT,
        XmlSignatures.NFDM_POLICY);
  }

  @Test
  @DisplayName(
      "TIP1-A_5538, TIP1-A_5402: XAdES-EPES unter NFDM als erstes Kind von SignatureArzt, Referenz "
          + "#Notfalldaten, SigningTime = Systemzeit, SigPolicyId, ShortText in DataObjectFormat; ISO-8859-15 bleibt, "
          + "das Dokument bleibt valide gegen das NFD-Schema")
  void sign() throws Exception {
    PadesSignaturesTest.Key key = PadesSignaturesTest.Key.generate();
    byte[] signed = XML.sign(request(read("NFDM_Beispiel_1.4.xml"), key), key.signHash());

    assertTrue(
        new String(signed, 0, 80, StandardCharsets.US_ASCII).contains("encoding=\"ISO-8859-15\""));
    List<Signer> signers = XML.verify(signed);
    assertEquals(1, signers.size());
    assertEquals(List.of(), signers.get(0).problems());
    assertEquals(Optional.of(NOW), signers.get(0).signingTime());
    assertArrayEquals(key.certificate(), signers.get(0).certificate());
    assertEquals(XmlSignatures.NFDM_POLICY, XML.signaturePolicy(signed));
    XML.validate(signed, XmlSignatures.NFDM_POLICY);

    Document document = XmlCodec.parse(signed);
    Element arzt = (Element) document.getElementsByTagNameNS("*", "SignatureArzt").item(0);
    Element signature = (Element) arzt.getFirstChild();
    assertEquals("Signature", signature.getLocalName());
    assertEquals(
        "#Notfalldaten",
        ((Element) signature.getElementsByTagNameNS(XadesSignatures.DS, "Reference").item(0))
            .getAttribute("URI"));
    assertEquals(
        "shortText",
        signature
            .getElementsByTagNameNS(XadesSignatures.XADES, "Description")
            .item(0)
            .getTextContent());
    // umlaut from the original (Latin-9) unchanged
    assertTrue(new String(signed, StandardCharsets.ISO_8859_1).contains("Müller-Holzscheit"));
  }

  @Test
  @DisplayName(
      "TUC_KON_159 Schritt 5: OCSP-Antwort in RevocationValues/OCSPValues, die Signatur bleibt gültig")
  void embedOcsp() throws Exception {
    PadesSignaturesTest.Key key = PadesSignaturesTest.Key.generate();
    byte[] signed = XML.sign(request(read("NFDM_Beispiel_1.4.xml"), key), key.signHash());
    byte[] ocsp = {0x30, 0x03, 0x0a, 0x01, 0x00};
    byte[] embedded = XML.embedOcsp(signed, SIGNATURE_ARZT, ocsp);

    assertEquals(List.of(), XML.verify(embedded).get(0).problems());
    Document document = XmlCodec.parse(embedded);
    assertEquals(
        "MAMKAQA=",
        document
            .getElementsByTagNameNS(XadesSignatures.XADES, "EncapsulatedOCSPValue")
            .item(0)
            .getTextContent());
    assertEquals(
        "UnsignedSignatureProperties",
        document
            .getElementsByTagNameNS(XadesSignatures.XADES, "RevocationValues")
            .item(0)
            .getParentNode()
            .getLocalName());
  }

  @Test
  @DisplayName("TUC_KON_166 Schritt 3: Signaturwert der Karte passt nicht → 4120")
  void cardSignatureInvalid() throws Exception {
    PadesSignaturesTest.Key key = PadesSignaturesTest.Key.generate();
    PadesSignaturesTest.Key other = PadesSignaturesTest.Key.generate();
    ConnectorException e =
        assertThrows(
            ConnectorException.class,
            () -> XML.sign(request(read("NFDM_Beispiel_1.4.xml"), key), other.signHash()));
    assertEquals(ConnectorError.CARD_SIGNATURE_INVALID, e.error());
  }

  @Test
  @DisplayName(
      "SignaturePlacement: XPathFirstChildOf ohne Treffer, RefURI ohne Element, Signatur im signierten "
          + "Element → 4111")
  void placementInvalid() throws Exception {
    PadesSignaturesTest.Key key = PadesSignaturesTest.Key.generate();
    byte[] nfd = read("NFDM_Beispiel_1.4.xml");
    for (XmlSignatures.Request request :
        List.of(
            new XmlSignatures.Request(
                nfd,
                key.certificate(),
                null,
                "#Notfalldaten",
                "/*[local-name()='X']",
                XmlSignatures.NFDM_POLICY),
            new XmlSignatures.Request(
                nfd,
                key.certificate(),
                null,
                "#Unbekannt",
                SIGNATURE_ARZT,
                XmlSignatures.NFDM_POLICY),
            new XmlSignatures.Request(
                nfd,
                key.certificate(),
                null,
                "#Notfalldaten",
                "/*[local-name()='NFD_Document']/*[local-name()='Notfalldaten']",
                XmlSignatures.NFDM_POLICY))) {
      ConnectorException e =
          assertThrows(ConnectorException.class, () -> XML.sign(request, key.signHash()));
      assertEquals(ConnectorError.INVALID_SIGNATURE_TYPE, e.error(), request.xPathFirstChildOf());
    }
  }

  @Test
  @DisplayName(
      "TUC_KON_080 (A): nicht wohlgeformt (PDF als XML, KUC_1604_011) und doppelte ID → 4022, gegen das "
          + "NFD-Schema nicht valide → 4023")
  void validate() throws Exception {
    byte[] pdf = Files.readAllBytes(Path.of("support/signatures/pades/pdf45k_PDFA-1B.pdf"));
    assertEquals(
        ConnectorError.XML_NOT_WELL_FORMED,
        assertThrows(ConnectorException.class, () -> XML.validate(pdf, null)).error());
    byte[] twice = "<a><b ID=\"x\"/><c ID=\"x\"/></a>".getBytes(StandardCharsets.UTF_8);
    assertEquals(
        ConnectorError.XML_NOT_WELL_FORMED,
        assertThrows(ConnectorException.class, () -> XML.validate(twice, null)).error());
    XML.validate("<a><b ID=\"x\"/><c ID=\"y\"/></a>".getBytes(StandardCharsets.UTF_8), null);
    byte[] invalid =
        new String(read("NFDM_Beispiel_1.4.xml"), StandardCharsets.ISO_8859_1)
            .replace("<Geschlecht>W</Geschlecht>", "<Unbekannt>W</Unbekannt>")
            .getBytes(StandardCharsets.ISO_8859_1);
    assertEquals(
        ConnectorError.XML_NOT_VALID,
        assertThrows(
                ConnectorException.class, () -> XML.validate(invalid, XmlSignatures.NFDM_POLICY))
            .error());
    XML.validate(read("NFDM_Beispiel_1.4.xml"), XmlSignatures.NFDM_POLICY);
  }

  @Test
  @DisplayName(
      "decision-023: Latin-9 selbst, die acht Zeichen außerhalb von ISO-8859-1 hin und zurück, Zeichen "
          + "außerhalb von Latin-9 als Zeichenreferenz")
  void latin9() {
    String text = "€ŠšŽžŒœŸ äöü";
    byte[] encoded = XmlCodec.encodeLatin9(text);
    assertArrayEquals(text.getBytes(java.nio.charset.Charset.forName("ISO-8859-15")), encoded);
    assertEquals(text, XmlCodec.decodeLatin9(encoded));
    assertEquals(
        "&#x3A9;&#xA4;", new String(XmlCodec.encodeLatin9("Ω¤"), StandardCharsets.US_ASCII));
    assertFalse(XmlCodec.latin9("ISO-8859-1"));
    assertTrue(XmlCodec.latin9("iso-8859-15"));
  }
}
