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
package de.gematik.liana.postman;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.postman.Konnektor.Answer;
import de.gematik.liana.postman.Konnektor.Endpoints;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

/**
 * Base of the Konnektor PoPP Postman collections as JVM tests (LIANA-40, LIANA-55). A test class is
 * a collection, a test method is a Postman request in the order of the collection; the method
 * checks what the test scripts of the request check and names each check like its {@code pm.test}.
 * The Postman environment variables ({@code CardHandle}, {@code SessionId}, {@code SignedScenario},
 * …) are fields that the requests pass on.
 *
 * <p>Instead of popp-bridge and PoPP service, {@link PoppServiceDouble} answers; the card is the
 * recorded egk-valid in KT-01/1 (RecordedCardEngine), context as in the test profile. If a card
 * session stays open (test failed early), {@link #stopLeftoverSession()} ends it so that the next
 * collection finds the card free.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
abstract class PostmanCollection {

  final Konnektor konnektor = new Konnektor("M1", "CS1", "WP1");
  final PoppServiceDouble bridge = new PoppServiceDouble();

  Endpoints endpoints;
  String cardHandle;
  String sessionId;
  String signedScenario;
  List<String> responses;

  @AfterAll
  void stopLeftoverSession() {
    bridge.close();
    if (endpoints != null && sessionId != null) {
      konnektor.stopCardSession(endpoints, sessionId);
    }
  }

  // --- Requests that (almost) every collection has in the same form
  // -----------------------------------------------

  /** GetConnector.sds: „EndPoint für Services erfolgreich extrahiert“. */
  void getConnectorSds() {
    endpoints = konnektor.connectorSds();
    assertAll(
        "EndPoint für Services erfolgreich extrahiert",
        () -> assertNotNull(endpoints.eventService(), "eventServiceEndpoint"),
        () -> assertNotNull(endpoints.cardService(), "cardServiceEndpoint"),
        () -> assertNotNull(endpoints.signatureService(), "signatureServiceEndpoint"),
        () -> assertNotNull(endpoints.encryptionService(), "encryptionServiceEndpoint"));
  }

  /** GetCards: „Statuscode ist 200“, „EGK CardHandle erfolgreich extrahiert“. */
  void getCards() {
    Answer answer = konnektor.getCards(endpoints);
    cardHandle = Konnektor.cardHandle(answer, "EGK");
    assertAll(
        "GetCards",
        () -> assertEquals(200, answer.status(), "Statuscode ist 200"),
        () -> assertNotNull(cardHandle, "EGK CardHandle erfolgreich extrahiert"));
  }

  /** StartCardSession: „Statuscode ist 200“, „SessionId erfolgreich extrahiert“. */
  void startCardSession() {
    Answer answer = konnektor.startCardSession(endpoints, cardHandle);
    sessionId = answer.text("SessionId");
    assertAll(
        "StartCardSession",
        () -> assertEquals(200, answer.status(), "Statuscode ist 200"),
        () -> assertNotNull(sessionId, "SessionId erfolgreich extrahiert"));
  }

  /** Bridge_start: Start to the PoPP service, response {@code signedScenario}. */
  void bridgeStart() {
    signedScenario = bridge.start(sessionId);
  }

  /**
   * Pre-request script of SecureSendApdu: the scenario of the PoPP service has the headers {@code
   * typ} and {@code alg} and a message with {@code type}, {@code clientSessionId}, {@code
   * sequenceCounter} and {@code steps}.
   */
  static void scenarioFromPoppService(String jws) {
    var header = PoppServiceDouble.header(jws);
    var message = PoppServiceDouble.message(jws);
    assertAll(
        "Prerequest SecureSendApdu",
        () -> assertNotNull(header.getString("typ"), "✅ Typ exists"),
        () -> assertNotNull(header.getString("alg"), "✅ Alg exists"),
        () -> assertNotNull(message.getString("type"), "✅ Type exists"),
        () -> assertNotNull(message.getString("clientSessionId"), "✅ ClientSessionId exists"),
        () -> assertNotNull(message.getInteger("sequenceCounter"), "✅ SequenceCounter exists"),
        () -> assertNotNull(message.getJsonArray("steps"), "✅ Message Steps exists"));
  }

  /**
   * SecureSendApdu n in the good case: „Statuscode ist 200“, response APDUs as {@code Responses}.
   */
  void secureSendApdu(String jws) {
    scenarioFromPoppService(jws);
    Answer answer = konnektor.secureSendApdu(endpoints, jws);
    responses = answer.responseApdus();
    assertEquals(200, answer.status(), "Statuscode ist 200");
  }

  /**
   * Bridge_responses n: ScenarioResponse with {@code Responses}, response {@code signedScenario}.
   */
  void bridgeResponses() {
    signedScenario = bridge.responses(responses);
  }

  /** StopCardSession in the good case: „Statuscode ist 200“, „Result ist OK“. */
  void stopCardSession() {
    Answer answer = konnektor.stopCardSession(endpoints, sessionId);
    assertAll(
        "StopCardSession",
        () -> assertEquals(200, answer.status(), "Statuscode ist 200"),
        () -> assertEquals("OK", answer.text("Result"), "Result ist OK"));
    sessionId = null;
  }

  /**
   * StopCardSession after the session has ended: 4288 „Unbekannte Session ID“ (A_26022,
   * TUC_KON_224).
   */
  void stopCardSessionUnknown() {
    Answer answer = konnektor.stopCardSession(endpoints, sessionId);
    assertFault(answer, "4288", "Unbekannte Session ID");
    sessionId = null;
  }

  /** Bridge_websocket_stop */
  void bridgeWebsocketStop() {
    bridge.close();
  }

  // --- Checks
  // ---------------------------------------------------------------------------------------------------

  /**
   * A SOAP fault with exactly one trace {@code code}/{@code errorText}: „Statuscode ist 500“,
   * „SoapFault vorhanden“, „Mindestens ein Trace vorhanden“, „Fehlercode … erwartet“, „Erwarteter
   * Text zu …“, „Nur ein Fehlercode in SoapFault ist vorhanden“.
   */
  static void assertFault(Answer answer, String code, String errorText) {
    List<Map.Entry<String, String>> traces = answer.traces();
    assertAll(
        "SOAP-Fault " + code,
        () -> assertEquals(500, answer.status(), "Statuscode ist 500"),
        () -> assertTrue(answer.isFault(), "SoapFault vorhanden"),
        () -> assertFalse(traces.isEmpty(), "Mindestens ein Trace vorhanden"),
        () ->
            assertEquals(
                List.of(code),
                traces.stream().map(Map.Entry::getKey).toList(),
                "Fehlercode " + code + " erwartet"),
        () ->
            assertEquals(
                errorText,
                traces.isEmpty() ? null : traces.get(0).getValue(),
                "Erwarteter Text zu " + code + " '" + errorText + "'"),
        () -> assertEquals(1, traces.size(), "Nur ein Fehlercode in SoapFault ist vorhanden"));
  }

  /**
   * SecureSendAPDUResponse with warning: „Statuscode ist 200“, „SecureSendAPDUResponse vorhanden“,
   * „Status vorhanden“, „Result ist 'Warning'“, „Mindestens ein Trace vorhanden“, „Warnungscode …
   * vorhanden“, „Warnungstext passt exakt“.
   */
  static void assertWarning(Answer answer, String code, String errorText) {
    List<Map.Entry<String, String>> traces = answer.traces();
    assertAll(
        "Warnung " + code,
        () -> assertEquals(200, answer.status(), "Statuscode ist 200"),
        () ->
            assertEquals(
                "SecureSendAPDUResponse",
                answer.body().getLocalName(),
                "SecureSendAPDUResponse vorhanden"),
        () -> assertNotNull(answer.text("Status"), "Status vorhanden"),
        () -> assertEquals("Warning", answer.text("Result"), "Result ist 'Warning'"),
        () -> assertFalse(traces.isEmpty(), "Mindestens ein Trace vorhanden"),
        () ->
            assertEquals(
                "Warning", answer.severity(), "Warnungscode " + code + " vorhanden (Severity)"),
        () ->
            assertTrue(
                traces.stream().anyMatch(t -> t.getKey().equals(code)),
                "Warnungscode " + code + " vorhanden"),
        () ->
            assertTrue(
                traces.stream()
                    .anyMatch(t -> t.getKey().equals(code) && errorText.equals(t.getValue())),
                "Warnungstext passt exakt: " + errorText));
  }
}
