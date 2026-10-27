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
import static org.junit.jupiter.api.Assertions.assertFalse;

import de.gematik.liana.konnektor.ws.conn.cardservicecommon.v2_0.CardTypeType;
import de.gematik.liana.konnektor.ws.conn.certificateservice.v6_0.ReadCardCertificate;
import de.gematik.liana.konnektor.ws.conn.certificateservice.v6_0.ReadCardCertificateResponse;
import de.gematik.liana.konnektor.ws.conn.certificateservicecommon.v2_0.CertRefEnum;
import de.gematik.liana.konnektor.ws.conn.eventservice.v7_2.GetCards;
import de.gematik.liana.konnektor.ws.conn.eventservice.v7_2.GetCardsResponse;
import java.nio.file.Path;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * LIANA-139: the client against the conformance suite's recording at LIANA ({@code
 * support/traces/konnektor-client/LIANA/0.5.24/read-only.tgr}).
 */
class LianaReplayTest {

  private static final Path TRACE =
      Path.of("support/traces/konnektor-client/LIANA/0.5.24/read-only.tgr");

  @Test
  @DisplayName("connector.sds, GetCards SM-B und ReadCardCertificate C.AUT aus der LIANA-Aufnahme")
  void readOnly() throws Exception {
    try (Konnektor kon =
        Konnektor.builder()
            .url("http://127.0.0.1:18080")
            .rewriteServiceEndpoints(true)
            .context("M1", "CS1", "WP1", null)
            .transport(new ReplayTransport(TRACE))
            .build()) {
      assertEquals("LIANA", kon.serviceDirectory().product().vendorId());
      GetCards request = KonnektorTest.request();
      request.setCardType(CardTypeType.SM_B);
      GetCardsResponse cards = kon.invoke(Operation.GET_CARDS, request, GetCardsResponse.class);
      String handle = cards.getCards().getCard().get(0).getCardHandle();
      ReadCardCertificate read = new ReadCardCertificate();
      read.setContext(request.getContext());
      read.setCardHandle(handle);
      read.setCertRefList(new ReadCardCertificate.CertRefList());
      read.getCertRefList().getCertRef().add(CertRefEnum.C_AUT);
      ReadCardCertificateResponse response =
          kon.invoke(Operation.READ_CARD_CERTIFICATE, read, ReadCardCertificateResponse.class);
      assertEquals("OK", response.getStatus().getResult());
      assertFalse(response.getX509DataInfoList().getX509DataInfo().isEmpty());
    }
  }
}
