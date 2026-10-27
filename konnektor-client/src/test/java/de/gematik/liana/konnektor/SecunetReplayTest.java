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
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.konnektor.ws.conn.cardservice.v8_1.VerifyPin;
import de.gematik.liana.konnektor.ws.conn.cardservicecommon.v2_0.CardTypeType;
import de.gematik.liana.konnektor.ws.conn.cardservicecommon.v2_0.PinResponseType;
import de.gematik.liana.konnektor.ws.conn.cardservicecommon.v2_0.PinResultEnum;
import de.gematik.liana.konnektor.ws.conn.eventservice.v7_2.GetCards;
import de.gematik.liana.konnektor.ws.conn.eventservice.v7_2.GetCardsResponse;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * LIANA-139: the client against the responses of a real Konnektor (secunet konnektor 2.0.0, TU lab,
 * {@code support/vendor/traces/vsdm/vsdm-read-secunet.tgr}, LIANA-101): connector.sds, GetCards,
 * VerifyPin via CardService 8.1 as in the recording, ReadVSD via the domain API (LIANA-105).
 */
@Tag("vendor-data")
class SecunetReplayTest {

  private static final Path TRACE = Path.of("support/vendor/traces/vsdm/vsdm-read-secunet.tgr");

  private static ReplayTransport transport;
  private static Konnektor kon;

  @BeforeAll
  static void replay() throws Exception {
    transport = new ReplayTransport(TRACE);
    kon =
        Konnektor.builder()
            .url("http://localhost:11111")
            .rewriteServiceEndpoints(true)
            .context("Mandant1", "ClientID1", "Workplace1", null)
            .transport(transport)
            .build();
  }

  @Test
  @DisplayName("connector.sds von secunet: Produkt, TLS-Pflicht, Versionen je Dienst")
  void serviceDirectory() throws Exception {
    ServiceDirectory sds = kon.serviceDirectory();
    assertTrue(
        sds.product().vendorId() != null && !sds.product().vendorId().isBlank(),
        sds.product().toString());
    assertTrue(sds.offered(Service.EVENT_SERVICE).size() >= 1);
    assertEquals(Binding.EVENT_SERVICE_7_2, sds.select(Operation.GET_CARDS).binding());
    assertTrue(
        sds.offered(Service.CARD_SERVICE).stream().anyMatch(o -> o.version().compatibleWith(8, 1)),
        sds.offered(Service.CARD_SERVICE).toString());
  }

  @Test
  @DisplayName(
      "GetCards SM-B und VerifyPin PIN.SMC (CardService 8.1): Antworten von secunet per JAXB gelesen")
  void getCardsUndVerifyPin() throws Exception {
    GetCards getCards = KonnektorTest.request();
    getCards.getContext().setMandantId("Mandant1");
    getCards.setCardType(CardTypeType.SM_B);
    GetCardsResponse cards = kon.invoke(Operation.GET_CARDS, getCards, GetCardsResponse.class);
    assertEquals("OK", cards.getStatus().getResult());
    String handle = cards.getCards().getCard().get(0).getCardHandle();
    assertEquals("SMC-B-571", handle);

    ServiceDirectory.Offer v81 =
        kon.serviceDirectory().offered(Service.CARD_SERVICE).stream()
            .filter(o -> o.version().compatibleWith(8, 1))
            .reduce((a, b) -> b)
            .orElseThrow();
    VerifyPin verify = new VerifyPin();
    verify.setContext(getCards.getContext());
    verify.setCardHandle(handle);
    verify.setPinTyp("PIN.SMC");
    PinResponseType response =
        kon.invoke(
            new ServiceDirectory.Selection(Operation.VERIFY_PIN, Binding.CARD_SERVICE_8_1, v81),
            verify,
            PinResponseType.class);
    assertEquals("OK", response.getStatus().getResult());
    assertEquals(PinResultEnum.OK, response.getPinResult());
    assertEquals(
        "\"http://ws.gematik.de/conn/CardService/v8.1#VerifyPin\"",
        transport.requests().get(transport.requests().size() - 1).headers().get("SOAPAction"));
  }

  @Test
  @DisplayName("VSDM-A_2567 ReadVSD von secunet: PD, VD und GVD entpackt, VSD_Status")
  void readVsd() {
    Vsd vsd = kon.card("EGK-572").readVsd("SMC-B-571");
    assertTrue(vsd.pdXml().contains("<Versicherten_ID>"), vsd.pdXml());
    assertTrue(vsd.vdXml().contains("<Kostentraegerkennung>"), vsd.vdXml());
    assertTrue(vsd.vdValue("Kostentraegerkennung").orElseThrow().matches("\\d{9}"), vsd.vdXml());
    assertTrue(vsd.pdValue("Nachname").isPresent() && vsd.pdValue("Gibtsnicht").isEmpty());
    assertTrue(vsd.gvdXml().orElseThrow().startsWith("<?xml"), vsd.gvdXml().orElseThrow());
    assertEquals(
        new Vsd.Status(false, java.time.LocalDateTime.parse("2026-10-12T09:07:41"), "5.2.0"),
        vsd.status());
  }
}
