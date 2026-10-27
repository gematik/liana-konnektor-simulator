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

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.lang.reflect.Method;
import java.nio.file.Path;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * LIANA-135 AC 2: every example from {@code konnektor-client/examples} runs against the LIANA
 * recording.
 */
class ExamplesTest {

  private static final Path TRACE =
      Path.of("support/traces/konnektor-client/LIANA/0.5.26/cards.tgr");

  @ParameterizedTest(name = "{0}")
  @ValueSource(
      strings = {
        "ListCards",
        "CardsOfType",
        "CardByIccsn",
        "CardByHandle",
        "CardsByTelematikId",
        "ListTerminals",
        "RequestCard",
        "EjectCard",
        "GetPinStatus",
        "VerifyPin",
        "ChangePin",
        "UnblockPin",
        "DisableAndEnablePin",
        "ReadCertificate",
        "ExternalAuthenticate",
        "SignJws"
      })
  @DisplayName("Beispiel gegen die Aufnahme")
  void beispiel(String name) throws Exception {
    Method run =
        Class.forName("de.gematik.liana.konnektor.examples." + name)
            .getMethod("run", Konnektor.class);
    try (Konnektor kon =
        Konnektor.builder()
            .url("http://127.0.0.1:18080")
            .rewriteServiceEndpoints(true)
            .context("M1", "CS1", "WP1", null)
            .transport(new ReplayTransport(TRACE, ReplayTransport.Mode.PREFER_EXACT))
            .build()) {
      assertNotNull(run.invoke(null, kon));
    }
  }

  @ParameterizedTest(name = "{0}")
  @org.junit.jupiter.params.provider.CsvSource({
    "GetJobNumber, conn/SignatureService_V7_5_6.xsd",
    "SignCadesDetached, conn/SignatureService_V7_5_6.xsd",
    "SignPades, conn/SignatureService_V7_5_6.xsd",
    "SignXades, conn/SignatureService_V7_5_6.xsd",
    "SignAll, conn/SignatureService_V7_5_6.xsd",
    "StopSignature, conn/SignatureService_V7_5_6.xsd",
    "ComfortSignature, conn/SignatureService_V7_5_6.xsd",
    "EncryptForCard, conn/EncryptionService_v6_1_2.xsd",
    "Decrypt, conn/EncryptionService_v6_1_2.xsd",
    "VerifySignature, conn/SignatureService_V7_5_6.xsd",
    "VerifyCertificate, conn/CertificateService_v6_0_2.xsd"
  })
  @DisplayName("LIANA-136-Beispiel: Requests bis zum ersten SOAP-Aufruf ohne Antwort schemagültig")
  void dokumentBeispiel(String name, String xsd) throws Exception {
    Method run =
        Class.forName("de.gematik.liana.konnektor.examples." + name)
            .getMethod("run", Konnektor.class);
    KonnektorTest.FakeTransport transport =
        new KonnektorTest.FakeTransport() {
          @Override
          public Response send(Request request) throws java.io.IOException {
            Response response = super.send(request);
            // The recording answers GetCards, everything else gets a fault: the example ends at the
            // request
            return request.method().equals("POST")
                    && !request.headers().get("SOAPAction").contains("GetCards")
                ? new Response(500, "text/xml", KonnektorTest.FAULT.getBytes())
                : response;
          }
        };
    transport.soap = CARDS;
    try (Konnektor kon =
        Konnektor.builder()
            .url("https://kon")
            .context("M1", "CS1", "WP1", "U1")
            .product("KOCO")
            .transport(transport)
            .build()) {
      try {
        run.invoke(null, kon);
      } catch (java.lang.reflect.InvocationTargetException e) {
        org.junit.jupiter.api.Assertions.assertInstanceOf(KonnektorException.class, e.getCause());
      }
    }
    Transport.Request last = transport.requests.get(transport.requests.size() - 1);
    RequestSchemaTest.validate(last.body(), xsd);
  }

  /** GetCards response with SMC-B and HBA. */
  static final String CARDS =
      "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\">"
          + "<SOAP-ENV:Body><EVT:GetCardsResponse xmlns:CONN=\"http://ws.gematik.de/conn/ConnectorCommon/v5.0\" "
          + "xmlns:CARDCMN=\"http://ws.gematik.de/conn/CardServiceCommon/v2.0\" "
          + "xmlns:CARD=\"http://ws.gematik.de/conn/CardService/v8.1\" "
          + "xmlns:EVT=\"http://ws.gematik.de/conn/EventService/v7.2\"><CONN:Status><CONN:Result>OK</CONN:Result>"
          + "</CONN:Status><CARD:Cards>"
          + "<CARD:Card><CONN:CardHandle>SMC-B-1</CONN:CardHandle><CARDCMN:CardType>SM-B</CARDCMN:CardType>"
          + "<CARDCMN:CtId>KT-01</CARDCMN:CtId><CARDCMN:SlotId>1</CARDCMN:SlotId>"
          + "<CARD:InsertTime>2026-10-14T12:00:00Z</CARD:InsertTime></CARD:Card>"
          + "<CARD:Card><CONN:CardHandle>HBA-1</CONN:CardHandle><CARDCMN:CardType>HBA</CARDCMN:CardType>"
          + "<CARDCMN:CtId>KT-01</CARDCMN:CtId><CARDCMN:SlotId>2</CARDCMN:SlotId>"
          + "<CARD:InsertTime>2026-10-14T12:00:00Z</CARD:InsertTime></CARD:Card>"
          + "</CARD:Cards></EVT:GetCardsResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>";
}
