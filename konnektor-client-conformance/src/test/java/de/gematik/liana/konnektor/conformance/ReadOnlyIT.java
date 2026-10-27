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
package de.gematik.liana.konnektor.conformance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import de.gematik.liana.konnektor.Binding;
import de.gematik.liana.konnektor.Konnektor;
import de.gematik.liana.konnektor.Operation;
import de.gematik.liana.konnektor.Service;
import de.gematik.liana.konnektor.ServiceDirectory;
import de.gematik.liana.konnektor.ws.conn.cardservicecommon.v2_0.CardTypeType;
import de.gematik.liana.konnektor.ws.conn.cardservicecommon.v2_0.PinResponseType;
import de.gematik.liana.konnektor.ws.conn.certificateservice.v6_0.ReadCardCertificate;
import de.gematik.liana.konnektor.ws.conn.certificateservice.v6_0.ReadCardCertificateResponse;
import de.gematik.liana.konnektor.ws.conn.certificateservicecommon.v2_0.CertRefEnum;
import de.gematik.liana.konnektor.ws.conn.connectorcontext.v2_0.ContextType;
import de.gematik.liana.konnektor.ws.conn.eventservice.v7_2.GetCardTerminals;
import de.gematik.liana.konnektor.ws.conn.eventservice.v7_2.GetCardTerminalsResponse;
import de.gematik.liana.konnektor.ws.conn.eventservice.v7_2.GetCards;
import de.gematik.liana.konnektor.ws.conn.eventservice.v7_2.GetCardsResponse;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Read-only checks against the Konnektor from {@code TI_TEST_KON_PATH} (LIANA-139). Interactive
 * checks (PIN entry) only with {@code -Dconformance.interactive=true}. Skeleton: grows with each
 * operation from LIANA-135 and LIANA-136.
 */
@ExtendWith(ConformanceTarget.class)
class ReadOnlyIT {

  private static ContextType context(Konnektor kon) {
    ContextType context = new ContextType();
    context.setMandantId(kon.context().mandantId());
    context.setClientSystemId(kon.context().clientSystemId());
    context.setWorkplaceId(kon.context().workplaceId());
    context.setUserId(kon.context().userId());
    return context;
  }

  private static List<String> smcbHandles(Konnektor kon) {
    GetCards request = new GetCards();
    request.setContext(context(kon));
    request.setCardType(CardTypeType.SM_B);
    GetCardsResponse cards = kon.invoke(Operation.GET_CARDS, request, GetCardsResponse.class);
    assertEquals("OK", cards.getStatus().getResult());
    return cards.getCards() == null
        ? List.of()
        : cards.getCards().getCard().stream().map(c -> c.getCardHandle()).toList();
  }

  @Test
  @DisplayName(
      "TIP1-A_4965/TIP1-A_4966: connector.sds lesbar, Event- und CardService mit Binding angeboten")
  void dienstverzeichnis() throws Exception {
    ServiceDirectory sds = ConformanceTarget.konnektor().serviceDirectory();
    assertNotNull(sds.product().vendorId(), "ProductVendorID");
    assertFalse(sds.offered(Service.EVENT_SERVICE).isEmpty(), "EventService");
    sds.select(Operation.GET_CARDS);
    sds.select(Operation.VERIFY_PIN);
  }

  @Test
  @DisplayName("GetCards und GetCardTerminals: Status OK")
  void kartenUndTerminals() {
    Konnektor kon = ConformanceTarget.konnektor();
    GetCards cards = new GetCards();
    cards.setContext(context(kon));
    assertEquals(
        "OK",
        kon.invoke(Operation.GET_CARDS, cards, GetCardsResponse.class).getStatus().getResult());
    GetCardTerminals terminals = new GetCardTerminals();
    terminals.setContext(context(kon));
    GetCardTerminalsResponse response =
        kon.invoke(Operation.GET_CARD_TERMINALS, terminals, GetCardTerminalsResponse.class);
    assertEquals("OK", response.getStatus().getResult());
  }

  @Test
  @DisplayName("ReadCardCertificate C.AUT der ersten SMC-B")
  void smcbZertifikat() {
    Konnektor kon = ConformanceTarget.konnektor();
    List<String> handles = smcbHandles(kon);
    assumeFalse(handles.isEmpty(), "keine SMC-B gesteckt");
    ReadCardCertificate request = new ReadCardCertificate();
    request.setContext(context(kon));
    request.setCardHandle(handles.get(0));
    request.setCertRefList(new ReadCardCertificate.CertRefList());
    request.getCertRefList().getCertRef().add(CertRefEnum.C_AUT);
    ReadCardCertificateResponse response =
        kon.invoke(Operation.READ_CARD_CERTIFICATE, request, ReadCardCertificateResponse.class);
    assertEquals("OK", response.getStatus().getResult());
    assertFalse(response.getX509DataInfoList().getX509DataInfo().isEmpty());
  }

  @Test
  @DisplayName("GetPinStatus PIN.SMC der ersten SMC-B in der gewählten CardService-Version")
  void pinStatus() throws Exception {
    Konnektor kon = ConformanceTarget.konnektor();
    List<String> handles = smcbHandles(kon);
    assumeFalse(handles.isEmpty(), "keine SMC-B gesteckt");
    ServiceDirectory.Selection selection = kon.serviceDirectory().select(Operation.GET_PIN_STATUS);
    Object request;
    Class<?> responseType;
    if (selection.binding() == Binding.CARD_SERVICE_8_2) {
      var r = new de.gematik.liana.konnektor.ws.conn.cardservice.v8_2.GetPinStatus();
      r.setContext(context(kon));
      r.setCardHandle(handles.get(0));
      r.setPinTyp("PIN.SMC");
      request = r;
      responseType = de.gematik.liana.konnektor.ws.conn.cardservice.v8_2.GetPinStatusResponse.class;
    } else {
      var r = new de.gematik.liana.konnektor.ws.conn.cardservice.v8_1.GetPinStatus();
      r.setContext(context(kon));
      r.setCardHandle(handles.get(0));
      r.setPinTyp("PIN.SMC");
      request = r;
      responseType = de.gematik.liana.konnektor.ws.conn.cardservice.v8_1.GetPinStatusResponse.class;
    }
    assertNotNull(kon.invoke(selection, request, responseType));
  }

  @Test
  @DisplayName("interaktiv: VerifyPin PIN.SMC der ersten SMC-B (PIN-Eingabe am KT)")
  void verifyPin() throws Exception {
    assumeTrue(ConformanceTarget.interactive(), ConformanceTarget.INTERACTIVE + " nicht gesetzt");
    Konnektor kon = ConformanceTarget.konnektor();
    List<String> handles = smcbHandles(kon);
    assumeFalse(handles.isEmpty(), "keine SMC-B gesteckt");
    ServiceDirectory.Selection selection = kon.serviceDirectory().select(Operation.VERIFY_PIN);
    Object request;
    if (selection.binding() == Binding.CARD_SERVICE_8_2) {
      var r = new de.gematik.liana.konnektor.ws.conn.cardservice.v8_2.VerifyPin();
      r.setContext(context(kon));
      r.setCardHandle(handles.get(0));
      r.setPinTyp("PIN.SMC");
      request = r;
    } else {
      var r = new de.gematik.liana.konnektor.ws.conn.cardservice.v8_1.VerifyPin();
      r.setContext(context(kon));
      r.setCardHandle(handles.get(0));
      r.setPinTyp("PIN.SMC");
      request = r;
    }
    assertEquals(
        "OK", kon.invoke(selection, request, PinResponseType.class).getStatus().getResult());
  }
}
