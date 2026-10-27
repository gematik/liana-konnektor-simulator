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

import static de.gematik.liana.soap.DocumentOperationsTest.context;
import static de.gematik.liana.soap.DocumentOperationsTest.signDocument;
import static de.gematik.liana.soap.EventServiceTest.getCards;
import static de.gematik.liana.soap.EventServiceTest.xpath;
import static de.gematik.liana.soap.RequestValidationTest.GET_CARDS;
import static de.gematik.liana.soap.RequestValidationTest.post;
import static org.junit.jupiter.api.Assertions.assertEquals;

import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Request validation from the built artifact (LIANA-48 AC #4): the schemas come from liana-contract
 * in the jar or as a resource in the native image ({@code quarkus.native.resources.includes}),
 * including imports and the W3C schemas with DOCTYPE.
 */
@QuarkusIntegrationTest
@TestProfile(RequestValidationTest.Profile.class)
class RequestValidationIT {

  @Test
  @DisplayName("GetCards gültig → 200, mit vertauschten Elementen → 4000")
  void eventService() throws Exception {
    assertEquals(
        "GetCardsResponse",
        post(
                "EventService",
                GET_CARDS,
                getCards("M1", "CS1", "WP1", "<ns5:CtId>KT-01</ns5:CtId>"),
                200)
            .getLocalName());
    assertEquals(
        "4000",
        xpath(
            post(
                "EventService",
                GET_CARDS,
                getCards(
                    "M1",
                    "CS1",
                    "WP1",
                    "<ns5:CardType>EGK</ns5:CardType><ns5:CtId>KT-01</ns5:CtId>"),
                500),
            "//*[local-name()='Code']"));
  }

  @Test
  @DisplayName("SignDocument v7.5 (dss, xmldsig) mit JobNumber vor TvMode → 4000")
  void signatureService() throws Exception {
    String body =
        signDocument("egal", context("M1", "CS1", "WP1", "bert"))
            .replace(
                "<ns4:TvMode>NONE</ns4:TvMode><ns4:JobNumber>ABC-123</ns4:JobNumber>",
                "<ns4:JobNumber>ABC-123</ns4:JobNumber><ns4:TvMode>NONE</ns4:TvMode>");
    assertEquals(
        "4000",
        xpath(
            post(
                "SignatureService",
                "\"http://ws.gematik.de/conn/SignatureService/v7.5#SignDocument\"",
                body,
                500),
            "//*[local-name()='Code']"));
  }
}
