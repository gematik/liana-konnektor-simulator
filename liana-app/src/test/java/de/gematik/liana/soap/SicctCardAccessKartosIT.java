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
import static de.gematik.liana.soap.EventServiceTest.xpath;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.adapter.sicct.SicctTerminal;
import de.gematik.liana.adapter.sicct.SicctTerminals;
import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.card.CardObject;
import de.gematik.liana.kern.event.GetCards;
import de.gematik.liana.kern.terminal.NoCardException;
import de.gematik.liana.sicct.KartosTerminal;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.ValidatableResponse;
import jakarta.inject.Inject;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.w3c.dom.Element;

/**
 * LIANA-79: the card operations from phase 1 over SICCT against {@code kartos terminal} instead of
 * {@code kartos pipe}, with the same cards in the same slots as the test profile of the fake
 * terminal (KT-01: egk-valid, smcb-valid, hba-valid; plus the gSMC-KT) and the same expectations as
 * EventServiceTest, CardServiceTest, CertificateServiceTest and AuthSignatureServiceTest. The tests
 * run in order on the same KT; the faults at the end disconnect it. The card session
 * (StartCardSession, SecureSendAPDU, StopCardSession) over SICCT is checked by the SICCT pass of
 * PoppKonTuIT.CardSession against the shipped artifact (LIANA-125).
 */
@QuarkusTest
@QuarkusTestResource(value = SicctCardAccessKartosIT.Kartos.class, restrictToAnnotatedClass = true)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SicctCardAccessKartosIT {

  static final String SECRET = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
  static final String CONTEXT =
      """
            <ns11:Context xmlns:ns11="http://ws.gematik.de/conn/ConnectorContext/v2.0"><ns6:MandantId>M1</ns6:MandantId>\
            <ns6:ClientSystemId>CS1</ns6:ClientSystemId><ns6:WorkplaceId>WP1</ns6:WorkplaceId></ns11:Context>""";
  static final Duration WAIT = Duration.ofSeconds(20);
  static final String CT = "http://ws.gematik.de/conn/CardTerminalService/v1.1";

  public static class Kartos implements QuarkusTestResourceLifecycleManager {
    static KartosTerminal kt;

    @Override
    public Map<String, String> start() {
      kt =
          KartosTerminal.start(
              "02:00:00:4C:49:44",
              "kartos-kt-01",
              0,
              Map.of(),
              SECRET,
              List.of("egk-valid", "smcb-valid", "hba-valid", "gsmckt-valid"));
      int announcements;
      try {
        announcements = KartosTerminal.freeUdpPort();
      } catch (IOException e) {
        throw new UncheckedIOException(e);
      }
      return Map.of(
          "liana.infrastructure.terminals.KT-01.type", "sicct",
          "liana.infrastructure.terminals.KT-01.host", "127.0.0.1",
          "liana.infrastructure.terminals.KT-01.shared-secret", SECRET,
          "liana.ctm.service-discovery-port", String.valueOf(kt.port()),
          "liana.ctm.service-announcement-port", String.valueOf(announcements),
          "liana.ctm.service-discovery-timeout", "2s",
          "liana.infomodel.workplaces[0].terminals", "KT-01");
    }

    @Override
    public void stop() {
      if (kt != null) {
        kt.close();
      }
    }
  }

  @Inject CardList cards;

  @Inject SicctTerminals sicct;

  @Inject GetCards getCards;

  private static void await(String what, BooleanSupplier condition) throws InterruptedException {
    long deadline = System.nanoTime() + WAIT.toNanos();
    while (!condition.getAsBoolean()) {
      if (System.nanoTime() > deadline) {
        throw new AssertionError(what + "\nkartos: " + Kartos.kt.log());
      }
      Thread.sleep(100);
    }
  }

  private CardObject card(int slot) {
    return cards.card("KT-01", slot).orElseThrow();
  }

  private SicctTerminal kt01() {
    return sicct.terminals().getFirst();
  }

  /** Certificate from EF {@code ef} of an image under support/images. */
  private static byte[] fromImage(String image, String ef) throws IOException {
    Matcher m =
        Pattern.compile(
                "<child id=\"" + Pattern.quote(ef) + "\".*?id=\"body\">([0-9A-F]+)<",
                Pattern.DOTALL)
            .matcher(Files.readString(Path.of("support/images", image)));
    assertTrue(m.find(), ef);
    return HexFormat.of().parseHex(m.group(1));
  }

  private static ValidatableResponse soap(String path, String ns, String operation, String inner) {
    return given()
        .contentType("text/xml; charset=utf-8")
        .header("SOAPAction", "\"" + ns + "#" + operation + "\"")
        .body(
            """
                        <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>\
                        <ns2:%1$s xmlns:ns2="%2$s" xmlns:ns3="http://ws.gematik.de/conn/ConnectorCommon/v5.0" \
                        xmlns:ns6="http://ws.gematik.de/conn/ConnectorCommon/v5.0" \
                        xmlns:ns4="http://ws.gematik.de/conn/CardServiceCommon/v2.0">%3$s</ns2:%1$s></SOAP-ENV:Body>\
                        </SOAP-ENV:Envelope>"""
                .formatted(operation, ns, inner))
        .post(path)
        .then();
  }

  private static Element ok(ValidatableResponse response) throws Exception {
    return bodyElement(response.statusCode(200).extract().asString());
  }

  private static String faultCode(ValidatableResponse response) throws Exception {
    return xpath(
        bodyElement(response.statusCode(500).extract().asString()), "//*[local-name()='Code']");
  }

  private static ValidatableResponse readCaut(String cardHandle) {
    return soap(
        "/ws/CertificateService",
        "http://ws.gematik.de/conn/CertificateService/v6.0",
        "ReadCardCertificate",
        "<ns6:CardHandle>"
            + cardHandle
            + "</ns6:CardHandle>"
            + CONTEXT
            + "<ns2:CertRefList><ns2:CertRef>C.AUT</ns2:CertRef></ns2:CertRefList>");
  }

  @Test
  @Order(1)
  @DisplayName(
      "TUC_KON_001 über SICCT: GetCards findet eGK, SMC-B und HBA in KT-01/1–3 mit denselben ICCSN wie beim "
          + "Fake-Terminal, die gSMC-KT des KT als SMC-KT in Slot 4")
  void getCards() throws Exception {
    // each card comes with its own CT/SLOT_IN_USE, the gSMC-KT in slot 4 may be ready after the HBA
    // (LIANA-196)
    await(
        "KT-01 verbunden, Karten gelesen",
        () ->
            java.util.stream.IntStream.rangeClosed(1, 4)
                .allMatch(
                    slot ->
                        cards
                            .card("KT-01", slot)
                            .filter(c -> !c.data().type().value().equals("UNKNOWN"))
                            .isPresent()));
    assertEquals("EGK", card(1).data().type().value());
    assertEquals("80276883110000168584", card(1).data().iccsn());
    assertEquals("SMC-B", card(2).data().type().value());
    assertEquals("80276883110000168650", card(2).data().iccsn());
    assertEquals("HBA", card(3).data().type().value());
    assertEquals("80276883119000000020", card(3).data().iccsn());
    List<CardObject> listed =
        getCards.execute(
            new GetCards.Request(
                new Context("M1", "CS1", "WP1", null), "KT-01", null, null, false));
    assertEquals(
        List.of("EGK", "SMC-B", "HBA", "SMC-KT"),
        listed.stream()
            .sorted(java.util.Comparator.comparingInt(CardObject::slotNo))
            .map(c -> c.data().type().value())
            .toList(),
        "die gSMC-KT steht als SMC-KT in Slot 4 wie beim secunet-Konnektor (LIANA-188)");
  }

  @Test
  @Order(3)
  @DisplayName(
      "TIP1-A_4700-03 über SICCT: ReadCardCertificate C.AUT der SMC-B ist byte-gleich EF.C.HCI.AUT.E256 des "
          + "Images; VerifyPin PIN.SMC (PERFORM VERIFICATION) und ExternalAuthenticate, Signatur prüfbar mit C.AUT")
  void zertifikatUndSignatur() throws Exception {
    String smcb = card(2).cardHandle();
    Element read = ok(readCaut(smcb));
    byte[] der = Base64.getDecoder().decode(xpath(read, "//*[local-name()='X509Certificate']"));
    assertArrayEquals(fromImage("smcb-valid.xml", "EF.C.HCI.AUT.E256"), der);

    Element pin =
        ok(
            soap(
                "/ws/CardService",
                "http://ws.gematik.de/conn/CardService/v8.2",
                "VerifyPin",
                CONTEXT
                    + "<ns6:CardHandle>"
                    + smcb
                    + "</ns6:CardHandle><ns4:PinTyp>PIN.SMC</ns4:PinTyp>"));
    assertEquals("OK", xpath(pin, "//*[local-name()='PinResult']"));

    String hash = "8Tqb6qisC00ZtYRHyFIpVZwb5FnIBVqD4aY4EjVHF/4=";
    Element signed =
        ok(
            given()
                .contentType("text/xml; charset=utf-8")
                .header(
                    "SOAPAction",
                    "\"http://ws.gematik.de/conn/SignatureService/v7.4#ExternalAuthenticate\"")
                .body(
                    """
                        <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>\
                        <ns3:ExternalAuthenticate xmlns:ns2="urn:oasis:names:tc:dss:1.0:core:schema" \
                        xmlns:ns3="http://ws.gematik.de/conn/SignatureService/v7.4" \
                        xmlns:ns6="http://ws.gematik.de/conn/ConnectorCommon/v5.0"><ns6:CardHandle>%s</ns6:CardHandle>%s\
                        <ns3:BinaryString><ns2:Base64Data MimeType="application/octet-stream">%s</ns2:Base64Data>\
                        </ns3:BinaryString></ns3:ExternalAuthenticate></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
                        .formatted(smcb, CONTEXT, hash))
                .post("/ws/AuthSignatureService")
                .then());
    byte[] signature =
        Base64.getDecoder().decode(xpath(signed, "//*[local-name()='Base64Signature']"));
    Signature verify = Signature.getInstance("NONEwithECDSA", "BC");
    verify.initVerify(
        CertificateFactory.getInstance("X.509", "BC")
            .generateCertificate(new ByteArrayInputStream(der)));
    verify.update(Base64.getDecoder().decode(hash));
    assertTrue(verify.verify(signature), "Signatur passt zu C.HCI.AUT.E256");
  }

  @Test
  @Order(4)
  @DisplayName(
      "ICC-Reset über SICCT liefert den Cold ATR aus dem Image; LIANA-110 RequestCard (TUC_KON_056) für die "
          + "gesteckte eGK: REQUEST ICC → 6201, AlreadyInserted true")
  void resetUndRequest() throws Exception {
    byte[] atr = HexFormat.of().parseHex("3B909681B1FE451F0391");
    assertArrayEquals(atr, kt01().reset(1));
    Element requested =
        ok(
            soap(
                "/ws/CardTerminalService",
                CT,
                "RequestCard",
                CONTEXT
                    + "<ns2:Slot><ns4:CtId>KT-01</ns4:CtId><ns4:SlotId>1</ns4:SlotId></ns2:Slot>"
                    + "<ns4:CardType>EGK</ns4:CardType><ns2:TimeOut>5</ns2:TimeOut>"));
    assertEquals("true", xpath(requested, "//*[local-name()='AlreadyInserted']"));
    assertEquals(
        card(1).cardHandle(),
        xpath(requested, "//*[local-name()='Card']/*[local-name()='CardHandle']"));
  }

  @Test
  @Order(5)
  @DisplayName(
      "LIANA-110 EjectCard (TUC_KON_057) per CardHandle: EJECT ICC wirft den HBA aus, kartos meldet 9001 und "
          + "85 → CARD/REMOVED, die Karte ist aus CM_CARD_LIST, bevor EjectCard antwortet; ein Kartenzugriff auf den "
          + "leeren Slot scheitert mit NoCardException; RequestCard dafür: kartos meldet ohne Karte sofort 6200 → 4202")
  void auswerfen() throws Exception {
    String hba = card(3).cardHandle();
    Element ejected =
        ok(
            soap(
                "/ws/CardTerminalService",
                CT,
                "EjectCard",
                CONTEXT
                    + "<ns6:CardHandle>"
                    + hba
                    + "</ns6:CardHandle><ns2:TimeOut>5000</ns2:TimeOut>"));
    assertEquals("OK", xpath(ejected, "//*[local-name()='Result']"));
    assertTrue(cards.card(hba).isEmpty());
    assertThrows(
        NoCardException.class, () -> kt01().transmit(3, new byte[] {0, (byte) 0xA4, 4, 0x0C}));
    assertEquals(
        "4202",
        faultCode(
            soap(
                "/ws/CardTerminalService",
                CT,
                "RequestCard",
                CONTEXT
                    + "<ns2:Slot><ns4:CtId>KT-01</ns4:CtId><ns4:SlotId>3</ns4:SlotId></ns2:Slot><ns2:TimeOut>1</ns2:TimeOut>")));
  }

  @Test
  @Order(6)
  @DisplayName(
      "TUC_KON_200 / LIANA-41 über SICCT: antwortet das KT nicht (kartos-Störung mute), 4094 nach "
          + "CARD_TIMEOUT_CARD; bricht die Verbindung während der Operation ab (Störung io-error), 4044")
  void stoerungen() throws Exception {
    String smcb = card(2).cardHandle();
    Kartos.kt.fault(2, "{\"type\":\"mute\",\"count\":1}");
    assertEquals("4094", faultCode(readCaut(smcb)));

    Kartos.kt.fault(2, "{\"type\":\"io-error\",\"count\":1}");
    assertEquals("4044", faultCode(readCaut(smcb)));
    await("KT-01 nach dem Abbruch getrennt, Karten weg", () -> cards.card("KT-01", 2).isEmpty());
  }
}
