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
package de.gematik.liana.adapter.vsdm;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.card.CardData;
import de.gematik.liana.kern.card.CardObject;
import de.gematik.liana.kern.card.CardType;
import de.gematik.liana.kern.vsdm.UpdateFlagService;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import javax.xml.XMLConstants;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.SchemaFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** UfsClient against a stub UFS (JDK HttpServer) over TCP. */
class UfsClientTest {

  private static final Path SCHEMAS = Path.of("support/schemas");
  private static final String ICCSN = "80276883110000168584";
  private static final Context CTX = new Context("M1", "CS1", "WP1", null);
  private static final CardObject SMB =
      new CardObject(
          "SMB-1",
          "KT-01",
          2,
          Instant.EPOCH,
          new CardData(CardType.SMC_B, "80276883110000117894", null, "Praxis", null, null));
  private static final UfsClient.Connector TCP =
      (url, context, smb, timeout) -> {
        Socket socket = new Socket();
        socket.connect(
            new InetSocketAddress(url.getHost(), url.getPort()), (int) timeout.toMillis());
        return socket;
      };

  private final UfsClient client = new UfsClient(TCP, Clock.systemUTC());
  private HttpServer server;
  private final AtomicReference<byte[]> request = new AtomicReference<>();
  private final AtomicReference<String> soapAction = new AtomicReference<>();

  private URI serve(int status, String response) throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext(
        "/ufs",
        exchange -> {
          request.set(exchange.getRequestBody().readAllBytes());
          soapAction.set(exchange.getRequestHeaders().getFirst("SOAPAction"));
          byte[] body = response.getBytes(StandardCharsets.UTF_8);
          exchange.getResponseHeaders().add("Content-Type", "text/xml; charset=utf-8");
          // 0: chunked
          exchange.sendResponseHeaders(status, 0);
          exchange.getResponseBody().write(body);
          exchange.close();
        });
    server.start();
    return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/ufs");
  }

  @AfterEach
  void stop() {
    if (server != null) {
      server.stop(0);
    }
  }

  private static void validate(byte[] envelope) throws Exception {
    SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
    factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "file");
    factory
        .newSchema(
            new Source[] {
              new StreamSource(SCHEMAS.resolve("ext/soap-envelope-1.1.xsd").toFile()),
              new StreamSource(SCHEMAS.resolve("cm/common/CmCommon.xsd").toFile()),
              new StreamSource(SCHEMAS.resolve("cm/uf/CmUfServiceRequest.xsd").toFile()),
            })
        .newValidator()
        .validate(new StreamSource(new ByteArrayInputStream(envelope)));
  }

  @Test
  @DisplayName(
      "Tab_FM_VSDM_20 / gemSpec_SST_FD_VSDM: GetUpdateFlags mit ICCSN, Lokalisierung UFS/ProviderID im "
          + "Header und SOAPAction der WSDL, gegen die Schemas; Prüfziffer aus ServiceReceipt")
  void keineAktualisierung() throws Exception {
    URI url =
        serve(
            200,
            """
                <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>\
                <r:GetUpdateFlagsResponse xmlns:r="http://ws.gematik.de/cm/uf/CmUfServiceResponse/v2.0" \
                xmlns:CM="http://ws.gematik.de/cm/common/CmCommon/v2.0"><CM:ServiceReceipt><CM:ServiceLocalization>\
                <CM:Type>UFS</CM:Type><CM:Provider>109500969</CM:Provider></CM:ServiceLocalization>\
                <CM:Receipt>UHLDvGZ6aWZmZXIgZGVzIFVGUw==</CM:Receipt></CM:ServiceReceipt>\
                </r:GetUpdateFlagsResponse></soap:Body></soap:Envelope>""");

    var answer =
        client.getUpdateFlags(
            url, ICCSN, "109500969", CTX, SMB, Duration.ofSeconds(2), Duration.ofSeconds(5));

    var flags = assertInstanceOf(UpdateFlagService.Flags.class, answer);
    assertEquals(List.of(), flags.flags());
    assertArrayEquals(Base64.getDecoder().decode("UHLDvGZ6aWZmZXIgZGVzIFVGUw=="), flags.receipt());
    validate(request.get());
    String xml = new String(request.get(), StandardCharsets.UTF_8);
    assertTrue(xml.contains("<CM:Type>UFS</CM:Type><CM:Provider>109500969</CM:Provider>"), xml);
    assertTrue(xml.contains("<CM:Iccsn>" + ICCSN + "</CM:Iccsn>"), xml);
    assertEquals("\"http://ws.gematik.de/cm/uf/WSDL/v1.0#getupdateflags\"", soapAction.get());
  }

  @Test
  @DisplayName("VSDM-A_2597: UpdateFlag mit Lokalisierung, UpdateId und UpdatePriority")
  void aktualisierungsauftraege() throws Exception {
    URI url =
        serve(
            200,
            """
                <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>\
                <r:GetUpdateFlagsResponse xmlns:r="http://ws.gematik.de/cm/uf/CmUfServiceResponse/v2.0" \
                xmlns:CM="http://ws.gematik.de/cm/common/CmCommon/v2.0">\
                <CM:UpdateFlag><CM:ServiceLocalization><CM:Type>VSD</CM:Type><CM:Provider>GEMTK</CM:Provider>\
                </CM:ServiceLocalization><CM:UpdateId>0A0B</CM:UpdateId><CM:UpdatePriority>MANDATORY\
                </CM:UpdatePriority><CM:ShortDescription>VSD</CM:ShortDescription></CM:UpdateFlag>\
                <CM:UpdateFlag><CM:ServiceLocalization><CM:Type>CMS</CM:Type><CM:Provider>GEMTK</CM:Provider>\
                </CM:ServiceLocalization><CM:UpdateId>0C</CM:UpdateId><CM:UpdatePriority>OPTIONAL\
                </CM:UpdatePriority><CM:ShortDescription>CMS</CM:ShortDescription></CM:UpdateFlag>\
                </r:GetUpdateFlagsResponse></soap:Body></soap:Envelope>""");

    var flags =
        (UpdateFlagService.Flags)
            client.getUpdateFlags(
                url, ICCSN, "109500969", CTX, SMB, Duration.ofSeconds(2), Duration.ofSeconds(5));

    assertEquals(
        List.of(
            new UpdateFlagService.UpdateFlag("VSD", "GEMTK", "0A0B", true),
            new UpdateFlagService.UpdateFlag("CMS", "GEMTK", "0C", false)),
        flags.flags());
  }

  @Test
  @DisplayName("Tab_FM_VSDM_04: SOAP-Fault mit GERROR:Error (HTTP 500) → Fehlercode aus Trace/Code")
  void fault() throws Exception {
    URI url =
        serve(
            500,
            """
                <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><soap:Fault>\
                <faultcode>soap:Server</faultcode><faultstring>Karte unbekannt</faultstring><detail>\
                <GERROR:Error xmlns:GERROR="http://ws.gematik.de/tel/error/v2.0"><GERROR:MessageID>1\
                </GERROR:MessageID><GERROR:Timestamp>2026-10-17T10:00:00Z</GERROR:Timestamp><GERROR:Trace>\
                <GERROR:EventID>2</GERROR:EventID><GERROR:Instance>ufs</GERROR:Instance><GERROR:LogReference>3\
                </GERROR:LogReference><GERROR:CompType>UFS</GERROR:CompType><GERROR:Code>12105</GERROR:Code>\
                <GERROR:Severity>Error</GERROR:Severity><GERROR:ErrorType>Business</GERROR:ErrorType>\
                <GERROR:ErrorText>Karte unbekannt</GERROR:ErrorText></GERROR:Trace></GERROR:Error></detail>\
                </soap:Fault></soap:Body></soap:Envelope>""");

    var fault =
        (UpdateFlagService.Fault)
            client.getUpdateFlags(
                url, ICCSN, "109500969", CTX, SMB, Duration.ofSeconds(2), Duration.ofSeconds(5));

    assertEquals(new UpdateFlagService.Fault(12105, "Karte unbekannt"), fault);
  }

  @Test
  @DisplayName(
      "Kein UFS unter der URL: HTTP 404, Antwort ohne SOAP, Verbindung abgelehnt → IOException")
  void nichtErreichbar() throws Exception {
    URI url = serve(404, "nicht hier");
    var notFound =
        assertThrows(
            IOException.class,
            () ->
                client.getUpdateFlags(
                    url, ICCSN, null, CTX, SMB, Duration.ofSeconds(2), Duration.ofSeconds(5)));
    assertTrue(notFound.getMessage().contains("HTTP 404"), notFound.getMessage());
    server.stop(0);

    URI html = serve(200, "<html><body>kein UFS</body></html>");
    assertThrows(
        IOException.class,
        () ->
            client.getUpdateFlags(
                html, ICCSN, null, CTX, SMB, Duration.ofSeconds(2), Duration.ofSeconds(5)));
    server.stop(0);
    server = null;

    int free;
    try (ServerSocket socket = new ServerSocket(0)) {
      free = socket.getLocalPort();
    }
    assertThrows(
        ConnectException.class,
        () ->
            client.getUpdateFlags(
                URI.create("http://127.0.0.1:" + free + "/ufs"),
                ICCSN,
                null,
                CTX,
                SMB,
                Duration.ofSeconds(2),
                Duration.ofSeconds(5)));
  }

  @Test
  @DisplayName("TIMEOUT_VSDM: UFS antwortet nicht → SocketTimeoutException nach dem Lese-Timeout")
  void zeitlimit() throws Exception {
    try (ServerSocket silent = new ServerSocket(0)) {
      URI url = URI.create("http://127.0.0.1:" + silent.getLocalPort() + "/ufs");
      long start = System.nanoTime();

      assertThrows(
          SocketTimeoutException.class,
          () ->
              client.getUpdateFlags(
                  url, ICCSN, null, CTX, SMB, Duration.ofSeconds(2), Duration.ofMillis(300)));
      long millis = (System.nanoTime() - start) / 1_000_000;
      assertTrue(millis >= 250 && millis < 2000, millis + " ms");
    }
  }

  @Test
  @DisplayName(
      "VSDM-A_2998: der Lese-Timeout endet nie, bevor die Uhr der Onlineprüfung ihn erreicht hat, auch wenn "
          + "sie langsamer läuft als der Socket (sonst fragt OnlineCheck nach abgelaufener MAXTIME_VSDM weiter)")
  void zeitlimitNachDerUhr() throws Exception {
    Instant real = Instant.now();
    Clock slow =
        new Clock() {
          @Override
          public Instant instant() {
            return real.plus(Duration.between(real, Instant.now()).dividedBy(2));
          }

          @Override
          public ZoneId getZone() {
            return ZoneOffset.UTC;
          }

          @Override
          public Clock withZone(ZoneId zone) {
            return this;
          }
        };
    try (ServerSocket silent = new ServerSocket(0)) {
      URI url = URI.create("http://127.0.0.1:" + silent.getLocalPort() + "/ufs");
      Instant deadline = slow.instant().plus(Duration.ofMillis(200));

      assertThrows(
          SocketTimeoutException.class,
          () ->
              new UfsClient(TCP, slow)
                  .getUpdateFlags(
                      url, ICCSN, null, CTX, SMB, Duration.ofSeconds(2), Duration.ofMillis(200)));
      assertFalse(slow.instant().isBefore(deadline), slow.instant() + " vor " + deadline);
    }
  }
}
