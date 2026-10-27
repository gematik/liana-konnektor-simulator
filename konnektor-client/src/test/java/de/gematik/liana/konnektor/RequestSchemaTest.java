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
package de.gematik.liana.konnektor;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Pattern;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.SchemaFactory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;
import org.w3c.dom.ls.LSInput;

/**
 * LIANA-136: every request of the signature, encryption and verification operations is valid
 * against the schema of the selected service version (support/schemas). Responses of real
 * Konnektors are still missing (replay from KSP traces open).
 */
class RequestSchemaTest {

  private static final Pattern DOCTYPE =
      Pattern.compile("<!DOCTYPE[^\\[>]*(\\[.*?\\])?\\s*>", Pattern.DOTALL);

  /** Records the requests; every SOAP response is a fault so that the call ends. */
  private static KonnektorTest.FakeTransport capture() {
    KonnektorTest.FakeTransport transport = new KonnektorTest.FakeTransport();
    transport.status = 500;
    transport.soap = KonnektorTest.FAULT;
    return transport;
  }

  static void validate(byte[] envelope, String xsd) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    org.w3c.dom.Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(envelope));
    Element body =
        (Element) doc.getDocumentElement().getElementsByTagNameNS(Soap.ENVELOPE_NS, "Body").item(0);
    Element operation = null;
    for (var node = body.getFirstChild(); node != null; node = node.getNextSibling()) {
      if (node instanceof Element e) {
        operation = e;
      }
    }
    SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
    factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "file");
    factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    factory.setResourceResolver(
        (type, ns, publicId, systemId, baseUri) ->
            systemId == null || baseUri == null
                ? null
                : new Input(URI.create(baseUri).resolve(systemId).toString()));
    factory
        .newSchema(Path.of("support/schemas").resolve(xsd).toFile())
        .newValidator()
        .validate(new DOMSource(operation));
  }

  private static Konnektor konnektor(KonnektorTest.FakeTransport transport) throws IOException {
    return Konnektor.builder()
        .url("https://kon")
        .context("M1", "CS1", "WP1", "U1")
        .product("KOCO")
        .transport(transport)
        .build();
  }

  @Test
  @DisplayName(
      "SignDocument CAdES detached, PAdES, XAdES, signAll; GetJobNumber, StopSignature, Komfortsignatur "
          + "gegen SignatureService 7.5.6")
  void signatur() throws Exception {
    KonnektorTest.FakeTransport transport = capture();
    try (Konnektor kon = konnektor(transport)) {
      CardScope hba = kon.card("HBA-1");
      byte[] pdf = "%PDF-1.4".getBytes(StandardCharsets.US_ASCII);
      assertThrows(KonnektorException.class, () -> kon.signatures().jobNumber());
      assertThrows(
          KonnektorException.class,
          () ->
              hba.sign(Document.of("x".getBytes(), "text/plain"))
                  .cades()
                  .detached()
                  .includeRevocationInfo(true)
                  .sign("ABC-123"));
      assertThrows(
          KonnektorException.class,
          () -> hba.sign(Document.pdfA(pdf).withShortText("Rezept")).pades().sign("ABC-124"));
      assertThrows(
          KonnektorException.class,
          () -> hba.sign(Document.xml("<a/>".getBytes())).xades().crypt("ECC").sign("ABC-125"));
      assertThrows(
          KonnektorException.class,
          () ->
              hba.signAll(List.of(Document.pdfA(pdf), Document.of("y".getBytes(), "text/plain")))
                  .sign("ABC-126"));
      assertThrows(KonnektorException.class, () -> kon.signatures().stop("ABC-126"));
      assertThrows(KonnektorException.class, () -> hba.comfort().activate());
      assertThrows(KonnektorException.class, () -> hba.comfort().deactivate());
      assertThrows(KonnektorException.class, () -> hba.comfort().status());
    }
    List<Transport.Request> posts =
        transport.requests.stream().filter(r -> r.method().equals("POST")).toList();
    assertTrue(posts.size() == 9, String.valueOf(posts.size()));
    for (Transport.Request post : posts) {
      validate(post.body(), "conn/SignatureService_V7_5_6.xsd");
    }
    // Counter-check: a request of a different service is invalid against this schema
    assertThrows(
        org.xml.sax.SAXException.class,
        () ->
            validate(
                Soap.envelope(Binding.EVENT_SERVICE_7_2, KonnektorTest.request()),
                "conn/SignatureService_V7_5_6.xsd"));
    String cades = new String(posts.get(1).body(), StandardCharsets.UTF_8);
    assertTrue(
        cades.contains("SignatureType>urn:ietf:rfc:5652<")
            && cades.contains("IncludeEContent>false<"),
        cades);
    assertTrue(
        new String(posts.get(2).body(), StandardCharsets.UTF_8)
            .contains("MimeType=\"application/pdf-a\""));
  }

  @Test
  @DisplayName(
      "EncryptDocument an Zertifikat und an Karte, DecryptDocument gegen EncryptionService 6.1.2; "
          + "VerifyDocument (7.5.6) und VerifyCertificate (6.0.2)")
  void verschluesselungUndPruefung() throws Exception {
    KonnektorTest.FakeTransport transport = capture();
    java.security.cert.X509Certificate cert =
        HttpTransportTest.certificate(TlsServer.SERVER.resolve("komp-ca.pem"));
    try (Konnektor kon = konnektor(transport)) {
      Document doc = Document.of("Befund".getBytes(), "text/plain");
      assertThrows(KonnektorException.class, () -> kon.encrypt(doc).to(cert));
      assertThrows(KonnektorException.class, () -> kon.encrypt(doc).toCard("SMC-B-1"));
      assertThrows(
          KonnektorException.class, () -> kon.card("SMC-B-1").decrypt(new byte[] {0x30, 0x00}));
      assertThrows(
          KonnektorException.class, () -> kon.verify().signature(Document.pdfA(new byte[] {1})));
      assertThrows(
          KonnektorException.class,
          () -> kon.verify().signature(doc, new byte[] {0x30, 0x00}, Signing.CADES_URI));
      assertThrows(KonnektorException.class, () -> kon.verify().certificate(cert));
    }
    List<Transport.Request> posts =
        transport.requests.stream().filter(r -> r.method().equals("POST")).toList();
    validate(posts.get(0).body(), "conn/EncryptionService_v6_1_2.xsd");
    validate(posts.get(1).body(), "conn/EncryptionService_v6_1_2.xsd");
    validate(posts.get(2).body(), "conn/EncryptionService_v6_1_2.xsd");
    validate(posts.get(3).body(), "conn/SignatureService_V7_5_6.xsd");
    validate(posts.get(4).body(), "conn/SignatureService_V7_5_6.xsd");
    validate(posts.get(5).body(), "conn/CertificateService_v6_0_2.xsd");
  }

  @Test
  @DisplayName("VSDM-A_2567 ReadVSD ohne Onlineprüfung gegen VSDService 5.2.0")
  void readVsd() throws Exception {
    KonnektorTest.FakeTransport transport = capture();
    try (Konnektor kon = konnektor(transport)) {
      assertThrows(KonnektorException.class, () -> kon.card("EGK-1").readVsd("SMC-B-1"));
    }
    Transport.Request post =
        transport.requests.stream()
            .filter(r -> r.method().equals("POST"))
            .findFirst()
            .orElseThrow();
    validate(post.body(), "conn/vsds/VSDService.xsd");
    String body = new String(post.body(), StandardCharsets.UTF_8);
    assertTrue(
        body.contains("EhcHandle>EGK-1<")
            && body.contains("HpcHandle>SMC-B-1<")
            && body.contains("PerformOnlineCheck>false<"),
        body);
    assertTrue(
        post.headers().get("SOAPAction").contains("VSDService/v6.0#ReadVSD"),
        post.headers().toString());
  }

  /** Imported schema file without DOCTYPE (W3C schemas refer to an unpinned DTD). */
  private record Input(String systemId) implements LSInput {
    @Override
    public Reader getCharacterStream() {
      try {
        return new StringReader(
            DOCTYPE.matcher(Files.readString(Path.of(URI.create(systemId)))).replaceFirst(""));
      } catch (IOException e) {
        throw new UncheckedIOException(e);
      }
    }

    @Override
    public void setCharacterStream(Reader characterStream) {}

    @Override
    public InputStream getByteStream() {
      return null;
    }

    @Override
    public void setByteStream(InputStream byteStream) {}

    @Override
    public String getStringData() {
      return null;
    }

    @Override
    public void setStringData(String stringData) {}

    @Override
    public String getSystemId() {
      return systemId;
    }

    @Override
    public void setSystemId(String systemId) {}

    @Override
    public String getPublicId() {
      return null;
    }

    @Override
    public void setPublicId(String publicId) {}

    @Override
    public String getBaseURI() {
      return systemId;
    }

    @Override
    public void setBaseURI(String baseURI) {}

    @Override
    public String getEncoding() {
      return null;
    }

    @Override
    public void setEncoding(String encoding) {}

    @Override
    public boolean getCertifiedText() {
      return false;
    }

    @Override
    public void setCertifiedText(boolean certifiedText) {}
  }
}
