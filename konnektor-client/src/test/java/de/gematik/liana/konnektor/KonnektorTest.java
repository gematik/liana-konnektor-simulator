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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.konnektor.ws.conn.connectorcontext.v2_0.ContextType;
import de.gematik.liana.konnektor.ws.conn.eventservice.v7_2.GetCards;
import de.gematik.liana.konnektor.ws.conn.eventservice.v7_2.GetCardsResponse;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** LIANA-133: Konnektor via a test transport, without network. */
class KonnektorTest {

  static final String GET_CARDS_RESPONSE =
      "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/"
          + "envelope/\"><SOAP-ENV:Header/><SOAP-ENV:Body><EVT:GetCardsResponse xmlns:CONN=\"http://ws.gematik.de/"
          + "conn/ConnectorCommon/v5.0\" xmlns:CARD=\"http://ws.gematik.de/conn/CardService/v8.1\" xmlns:EVT=\""
          + "http://ws.gematik.de/conn/EventService/v7.2\"><CONN:Status><CONN:Result>OK</CONN:Result></CONN:Status>"
          + "<CARD:Cards/></EVT:GetCardsResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>";

  static final String FAULT =
      "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\">"
          + "<SOAP-ENV:Body><SOAP-ENV:Fault><faultcode>SOAP-ENV:Server</faultcode><faultstring>Konnektorfehler"
          + "</faultstring><detail><GERROR:Error xmlns:GERROR=\"http://ws.gematik.de/tel/error/v2.0\"><GERROR:Code>"
          + "4004</GERROR:Code></GERROR:Error></detail></SOAP-ENV:Fault></SOAP-ENV:Body></SOAP-ENV:Envelope>";

  /** Answers GET with LIANA's SDS, POST with {@code soap}. */
  static class FakeTransport implements Transport {
    final List<Request> requests = new ArrayList<>();
    int status = 200;
    String soap = GET_CARDS_RESPONSE;

    @Override
    public Response send(Request request) throws IOException {
      requests.add(request);
      if (request.method().equals("GET")) {
        try (InputStream in = KonnektorTest.class.getResourceAsStream("/sds/liana.xml")) {
          return new Response(200, "application/xml", in.readAllBytes());
        }
      }
      return new Response(status, "text/xml", soap.getBytes(StandardCharsets.UTF_8));
    }
  }

  private static Konnektor konnektor(FakeTransport transport, String url, boolean rewrite)
      throws IOException {
    return Konnektor.builder()
        .url(url)
        .rewriteServiceEndpoints(rewrite)
        .context("M1", "CS1", "WP1", null)
        .transport(transport)
        .build();
  }

  static GetCards request() {
    ContextType context = new ContextType();
    context.setMandantId("M1");
    context.setClientSystemId("CS1");
    context.setWorkplaceId("WP1");
    GetCards request = new GetCards();
    request.setContext(context);
    return request;
  }

  @Test
  @DisplayName(
      "GetCards: connector.sds von <url>, POST an EndpointTLS mit SOAPAction aus der WSDL, Antwort per JAXB")
  void getCards() throws Exception {
    FakeTransport transport = new FakeTransport();
    try (Konnektor kon = konnektor(transport, "https://localhost:8443/", false)) {
      GetCardsResponse response =
          kon.invoke(Operation.GET_CARDS, request(), GetCardsResponse.class);
      assertEquals("OK", response.getStatus().getResult());
    }
    assertEquals(
        URI.create("https://localhost:8443/connector.sds"), transport.requests.get(0).uri());
    Transport.Request post = transport.requests.get(1);
    assertEquals(URI.create("https://localhost:8443/ws/EventService"), post.uri());
    assertEquals(
        "\"http://ws.gematik.de/conn/EventService/v7.2#GetCards\"",
        post.headers().get("SOAPAction"));
    assertEquals("text/xml; charset=UTF-8", post.headers().get("Content-Type"));
    assertEquals(Duration.ofSeconds(10), post.timeout());
    String body = new String(post.body(), StandardCharsets.UTF_8);
    assertTrue(
        body.contains(
            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">"
                + "<soap:Body>"),
        body);
    assertTrue(body.contains("MandantId>M1<"), body);
  }

  @Test
  @DisplayName(
      ".kon rewriteServiceEndpoints: nur der Pfad aus dem SDS, angehängt an die url; http nimmt Endpoint")
  void rewrite() throws Exception {
    FakeTransport transport = new FakeTransport();
    try (Konnektor kon = konnektor(transport, "http://liana:18080/kon1", true)) {
      kon.invoke(Operation.GET_CARDS, request(), GetCardsResponse.class);
    }
    assertEquals(
        URI.create("http://liana:18080/kon1/ws/EventService"), transport.requests.get(1).uri());
    try (Konnektor kon = konnektor(new FakeTransport(), "http://liana:18080", false)) {
      assertEquals(
          URI.create("http://localhost:8080/ws/CardService"),
          kon.endpoint(kon.serviceDirectory().select(Operation.VERIFY_PIN)));
    }
  }

  @Test
  @DisplayName("SOAP-Fault: SoapFaultException mit faultcode und detail (GERROR)")
  void fault() throws Exception {
    FakeTransport transport = new FakeTransport();
    transport.status = 500;
    transport.soap = FAULT;
    try (Konnektor kon = konnektor(transport, "https://kon", false)) {
      SoapFaultException e =
          assertThrows(
              SoapFaultException.class,
              () -> kon.invoke(Operation.GET_CARDS, request(), GetCardsResponse.class));
      assertEquals("SOAP-ENV:Server", e.faultCode());
      assertTrue(e.detail().contains("<GERROR:Code>4004</GERROR:Code>"), e.detail());
      assertEquals("GetCards: SOAP-Fault SOAP-ENV:Server Konnektorfehler", e.getMessage());
    }
  }

  @Test
  @DisplayName("HTTP-Fehler ohne SOAP und Request aus dem falschen Binding")
  void fehler() throws Exception {
    FakeTransport transport = new FakeTransport();
    transport.status = 401;
    transport.soap = "";
    try (Konnektor kon = konnektor(transport, "https://kon", false)) {
      KonnektorException e =
          assertThrows(
              KonnektorException.class,
              () -> kon.invoke(Operation.GET_CARDS, request(), GetCardsResponse.class));
      assertEquals("GetCards an https://localhost:8443/ws/EventService: HTTP 401", e.getMessage());
      assertThrows(
          IllegalArgumentException.class,
          () -> kon.invoke(Operation.VERIFY_PIN, request(), Object.class));
    }
  }

  @Test
  @DisplayName("SOAPAction je Operation aus der WSDL, auch abweichend vom Muster (DecryptDocument)")
  void soapAction() {
    assertEquals(
        "http://ws.gematik.de/conn/crypt/EncryptionService/v6.1#DecryptDocument",
        Soap.action(Binding.ENCRYPTION_SERVICE_6_1, Operation.DECRYPT_DOCUMENT));
    assertEquals(
        "http://ws.gematik.de/conn/SignatureService/v7.4#ExternalAuthenticate",
        Soap.action(Binding.AUTH_SIGNATURE_SERVICE_7_4, Operation.EXTERNAL_AUTHENTICATE));
    for (Operation operation : Operation.values()) {
      for (Binding binding : operation.bindings()) {
        assertTrue(
            Soap.action(binding, operation).endsWith("#" + operation.wsdlName()), operation.name());
      }
    }
  }

  @Test
  @DisplayName("Deployment setzt die Zeitlimits, der Builder überschreibt sie")
  void timeouts() throws Exception {
    try (Konnektor kon =
        Konnektor.builder()
            .url("https://kon")
            .context("M", "C", "W", null)
            .deployment(Deployment.KSP)
            .onPinPrompt(prompt -> {})
            .transport(new FakeTransport())
            .build()) {
      assertEquals(Duration.ofMinutes(5), kon.timeout(Operation.VERIFY_PIN));
      assertEquals(Duration.ofSeconds(30), kon.timeout(Operation.GET_CARDS));
    }
    try (Konnektor kon =
        Konnektor.builder()
            .url("https://kon")
            .context("M", "C", "W", null)
            .timeouts(Duration.ofSeconds(1), Duration.ofSeconds(2))
            .transport(new FakeTransport())
            .build()) {
      assertEquals(Duration.ofSeconds(2), kon.timeout(Operation.SIGN_DOCUMENT));
    }
  }

  @Test
  @DisplayName(
      "ExternalAuthenticate: ECDSA nach TR-03111, RSASSA-PSS mit SignatureType RFC 3447, Hash als "
          + "Base64Data application/octet-stream (TAB_KON_781)")
  void externalAuthenticateRequest() throws Exception {
    FakeTransport transport = new FakeTransport();
    try (Konnektor kon = konnektor(transport, "https://kon", false)) {
      assertThrows(
          KonnektorException.class, () -> kon.card("SMC-B-1").authenticate(new byte[32]).rsaPss());
      assertThrows(
          KonnektorException.class, () -> kon.card("SMC-B-1").authenticate(new byte[32]).ecdsa());
    }
    String rsa = new String(transport.requests.get(1).body(), StandardCharsets.UTF_8);
    assertTrue(rsa.contains("SignatureType>urn:ietf:rfc:3447<"), rsa);
    assertTrue(rsa.contains("SignatureSchemes>RSASSA-PSS<"), rsa);
    assertTrue(rsa.contains("MimeType=\"application/octet-stream\""), rsa);
    assertTrue(rsa.contains("CardHandle>SMC-B-1<"), rsa);
    String ecdsa = new String(transport.requests.get(2).body(), StandardCharsets.UTF_8);
    assertTrue(ecdsa.contains("SignatureType>urn:bsi:tr:03111:ecdsa<"), ecdsa);
    assertTrue(!ecdsa.contains("SignatureSchemes"), ecdsa);
  }
}
