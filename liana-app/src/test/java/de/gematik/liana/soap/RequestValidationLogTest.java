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

import static de.gematik.liana.soap.EventServiceTest.getCards;
import static de.gematik.liana.soap.RequestValidationTest.post;
import static org.junit.jupiter.api.Assertions.assertEquals;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * {@code liana.soap.request-validation=log} (default, LIANA-48): violations only in the log, the
 * request proceeds.
 */
@QuarkusTest
class RequestValidationLogTest {

  @Test
  @DisplayName(
      "LIANA-48 Messmodus: GetCards mit vertauschten Elementen und SOAPAction im falschen Namensraum → "
          + "beantwortet wie bisher")
  void log() throws Exception {
    assertEquals(
        "GetCardsResponse",
        post(
                "EventService",
                "\"http://ws.gematik.de/conn/EventService/v7.1#GetCards\"",
                getCards(
                    "M1",
                    "CS1",
                    "WP1",
                    "<ns5:CardType>EGK</ns5:CardType><ns5:CtId>KT-01</ns5:CtId>"),
                200)
            .getLocalName());
  }
}
