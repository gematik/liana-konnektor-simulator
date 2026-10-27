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

import de.gematik.liana.konnektor.ws.conn.cardservicecommon.v2_0.CardTypeType;
import de.gematik.liana.konnektor.ws.conn.eventservice.v7_2.GetCards;
import de.gematik.liana.konnektor.ws.conn.eventservice.v7_2.GetCardsResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Inserted cards via GetCards (TIP1-A_4559, EventService 7.2; LIANA-135). Each call queries the
 * Konnektor anew.
 */
public final class Cards {

  private final Konnektor kon;

  Cards(Konnektor kon) {
    this.kon = kon;
  }

  /** All cards in the Aufrufkontext (GetCards without filter). */
  public List<Card> list() {
    return getCards(null);
  }

  /**
   * Cards of one or more types, such as {@code "SM-B"} or {@code "EGK"} (GetCards with CardType per
   * type).
   */
  public List<Card> ofType(String... types) {
    List<Card> cards = new ArrayList<>();
    for (String type : types) {
      cards.addAll(getCards(CardTypeType.fromValue(type)));
    }
    return cards;
  }

  /** The card with this ICCSN. */
  public Optional<Card> byIccsn(String iccsn) {
    return list().stream().filter(c -> iccsn.equals(c.iccsn())).findFirst();
  }

  /** The card with this CardHandle. */
  public Optional<Card> byHandle(String handle) {
    return list().stream().filter(c -> handle.equals(c.handle())).findFirst();
  }

  /**
   * Cards of the institution or person with this Telematik-ID: reads the C.AUT (ECC, otherwise RSA)
   * of every SMC-B and every HBA and compares the {@code registrationNumber} of the Admission
   * extension (gemSpec_PKI, OID 1.3.36.8.3.3).
   */
  public List<Card> byTelematikId(String telematikId) {
    List<Card> found = new ArrayList<>();
    for (Card card : ofType("SM-B", "HBA")) {
      CertificateScope certificate = kon.card(card).certificate("C.AUT");
      Optional<String> id = TelematikId.of(readAny(certificate));
      if (id.isPresent() && id.get().equals(telematikId)) {
        found.add(card);
      }
    }
    return found;
  }

  private static java.security.cert.X509Certificate readAny(CertificateScope certificate) {
    try {
      return certificate.ecc().read();
    } catch (KonnektorException e) {
      return certificate.rsa().read();
    }
  }

  private List<Card> getCards(CardTypeType type) {
    GetCards request = new GetCards();
    request.setContext(Jaxb.context(kon.context()));
    request.setCardType(type);
    GetCardsResponse response = kon.invoke(Operation.GET_CARDS, request, GetCardsResponse.class);
    if (response.getCards() == null) {
      return List.of();
    }
    return response.getCards().getCard().stream().map(Card::of).toList();
  }
}
