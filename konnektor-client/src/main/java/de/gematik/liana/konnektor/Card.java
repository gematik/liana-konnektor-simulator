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

import de.gematik.liana.konnektor.ws.conn.cardservice.v8_1.CardInfoType;
import java.time.Instant;
import java.time.LocalDate;

/**
 * An inserted card from GetCards ({@code CARD:Card}, CardService 8.1 in EventService 7.2).
 *
 * @param handle CardHandle, valid until the card is pulled
 * @param type CardType ({@code EGK}, {@code HBA}, {@code SMC-B}, {@code SM-B}, {@code SMC-KT}, …)
 * @param iccsn ICCSN, may be absent
 * @param ctId card terminal
 * @param slot slot in the card terminal
 * @param insertTime insertion time
 * @param holderName CardHolderName, may be absent
 * @param kvnr KVNR of the eGK, may be absent
 * @param certificateExpiration expiry of the C.AUT as reported by the Konnektor, may be absent
 */
public record Card(
    String handle,
    String type,
    String iccsn,
    String ctId,
    int slot,
    Instant insertTime,
    String holderName,
    String kvnr,
    LocalDate certificateExpiration) {

  static Card of(CardInfoType info) {
    return new Card(
        info.getCardHandle(),
        info.getCardType() == null ? null : info.getCardType().value(),
        info.getIccsn(),
        info.getCtId(),
        info.getSlotId() == null ? 0 : info.getSlotId().intValue(),
        info.getInsertTime() == null
            ? null
            : info.getInsertTime().toGregorianCalendar().toInstant(),
        info.getCardHolderName(),
        info.getKvnr(),
        info.getCertificateExpirationDate() == null
            ? null
            : LocalDate.of(
                info.getCertificateExpirationDate().getYear(),
                info.getCertificateExpirationDate().getMonth(),
                info.getCertificateExpirationDate().getDay()));
  }
}
