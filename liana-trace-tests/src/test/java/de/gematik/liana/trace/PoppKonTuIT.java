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
package de.gematik.liana.trace;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.rbellogger.data.RbelElement;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * popp-client ↔ TU Konnektor (popp-kon-tu) against LIANA, environment {@link PoppKonTuGegenLiana}:
 * one replay of the trace with one LIANA start (LIANA-124), the checks grouped by flow.
 *
 * <ul>
 *   <li>{@link GetCards}: GetCards from popp-kon-tu, StartCardSession with LIANA's CardHandle;
 *   <li>{@link Smcb}: the popp-client's ZETA login via the SMC-B. LIANA has smcb-valid inserted
 *       instead of the TU SMC-B; certificate and signature therefore differ, status and structure
 *       do not;
 *   <li>{@link CardSession}: the PoPP tunnel. LIANA assigns the SessionId; because it is part of
 *       the SignedScenario, the replay re-signs the scenarios with the test signer.
 * </ul>
 */
@Tag("vendor-data")
@PoppKonTuGegenLiana
@ReplaceSteps(
    sequence = 2,
    with = "support/blueprints/poppApdusSequence2Connector.json",
    why =
        "die TU-eGK kannte den CV-Schlüssel des PoPP-Service schon, egk-valid lernt ihn erst per PSO VERIFY CERTIFICATE")
class PoppKonTuIT {

  @BeforeAll
  static void kartos() {
    Assumptions.assumeTrue(
        LianaProcess.kartosBin().isPresent(),
        "kein eingechecktes kartos für dieses System: LIANA_KARTOS_BIN setzen");
  }

  @Nested
  @DisplayName("GetCards (EGK und SMC-B) und StartCardSession mit LIANAs CardHandle")
  class GetCards {

    private static final String CARD_HANDLE = PoppKonTuGegenLiana.CARD_HANDLE;
    private static final String CARD = "$.body.Envelope.Body.GetCardsResponse.Cards.Card";

    /** Requests of the trace, from 0: popp-client fetches the SMC-B for ZETA twice. */
    private static final int GET_CARDS_SMCB = 2;

    private static final int GET_CARDS_SMCB_NOCHMAL = 4;

    @Test
    @DisplayName(
        "TIP1-A_4605-03 GetCards EGK: Status, CardType, SlotId wie im Trace; Handle, ICCSN, InsertTime, CardVersion vorhanden")
    void getCardsEgk(Replay replay) {
      var exchange = replay.exchange(0);
      exchange
          .assertThatSentRequest()
          .hasStringContentEqualToAtPosition("$.body.Envelope.Body.GetCards.CtId.text", "KT-01");
      exchange.assertSameAt(
          "$.responseCode",
          "$.body.Envelope.Body.GetCardsResponse.Status.Result.text",
          CARD + ".CardType.text",
          CARD + ".SlotId.text",
          CARD + ".CardVersion.COSVersion.Major.text",
          CARD + ".CardVersion.ObjectSystemVersion.Major.text");
      exchange
          .assertThatLianaResponse()
          .hasChildWithPath(CARD + ".CardHandle")
          .hasChildWithPath(CARD + ".Iccsn")
          .hasChildWithPath(CARD + ".InsertTime")
          .hasChildWithPath(CARD + ".CardVersion")
          .hasStringContentEqualToAtPosition(CARD + ".CtId.text", "KT-01");
    }

    @ParameterizedTest(name = "Request {0}")
    @ValueSource(ints = {GET_CARDS_SMCB, GET_CARDS_SMCB_NOCHMAL})
    @DisplayName(
        "TIP1-A_4605-03 GetCards SMC-B (ZETA-Anmeldung des popp-client): Status, CardType, SlotId, CardVersion wie im "
            + "Trace; Handle, ICCSN, Name und Ablauf vorhanden")
    void getCardsSmcb(int request, Replay replay) {
      var exchange = replay.exchange(request);
      exchange
          .assertThatSentRequest()
          .hasStringContentEqualToAtPosition(
              "$.body.Envelope.Body.GetCards.CardType.text", "SMC-B");
      exchange.assertSameAt(
          "$.responseCode",
          "$.body.Envelope.Body.GetCardsResponse.Status.Result.text",
          CARD + ".CardType.text",
          CARD + ".SlotId.text",
          CARD + ".CardVersion.COSVersion.Major.text",
          CARD + ".CardVersion.ObjectSystemVersion.Major.text");
      exchange
          .assertThatLianaResponse()
          .hasChildWithPath(CARD + ".CardHandle")
          .hasChildWithPath(CARD + ".Iccsn")
          .hasChildWithPath(CARD + ".CardHolderName")
          .hasChildWithPath(CARD + ".CertificateExpirationDate")
          .hasStringContentEqualToAtPosition(CARD + ".CtId.text", "KT-01");
    }

    @Test
    @DisplayName(
        "LIANA-21 carry: StartCardSession geht mit dem CardHandle, den LIANA bei GetCards vergeben hat")
    void startCardSessionMitLianaHandle(Replay replay) {
      var handle =
          replay
              .exchange(0)
              .lianaResponse()
              .findElement(CARD_HANDLE)
              .orElseThrow()
              .getRawStringContent();
      assertThat(handle).isNotEqualTo("EGK-24");
      replay
          .exchange(1)
          .assertThatSentRequest()
          .hasStringContentEqualToAtPosition(
              "$.body.Envelope.Body.StartCardSession.CardHandle.text", handle);
      assertThat(replay.exchange(1).replaced()).containsEntry("EGK-24", handle);
    }
  }

  @Nested
  @DisplayName(
      "ZETA-Anmeldung über die SMC-B: ReadCardCertificate, VerifyPin, ExternalAuthenticate")
  class Smcb {

    private static final String TU_SMCB = "SMC-B-25";
    private static final String READ_RESPONSE = "$.body.Envelope.Body.ReadCardCertificateResponse.";
    private static final String X509 = READ_RESPONSE + "X509DataInfoList.X509DataInfo.";

    /** Requests of the trace, from 0. */
    private static final int READ_CARD_CERTIFICATE = 3;

    private static final int VERIFY_PIN = 5;
    private static final int EXTERNAL_AUTHENTICATE = 6;

    @Test
    @DisplayName(
        "TIP1-A_4700-03 ReadCardCertificate C.AUT: mit LIANAs SMC-B-Handle; Status, CertRef und Aufbau wie im Trace, "
            + "Aussteller eine GEM.SMCB-CA")
    void readCardCertificate(Replay replay) {
      var exchange = replay.exchange(READ_CARD_CERTIFICATE);
      assertThat(exchange.replaced()).containsKey(TU_SMCB);
      exchange.assertSameAt(
          "$.responseCode", READ_RESPONSE + "Status.Result.text", X509 + "CertRef.text");
      exchange
          .assertThatLianaResponse()
          .hasChildWithPath(X509 + "X509Data.X509IssuerSerial.X509SerialNumber")
          .hasChildWithPath(X509 + "X509Data.X509SubjectName")
          .hasChildWithPath(X509 + "X509Data.X509Certificate");
      assertThat(
              exchange
                  .lianaResponse()
                  .findElement(X509 + "X509Data.X509IssuerSerial.X509IssuerName.text")
                  .orElseThrow()
                  .getRawStringContent())
          .contains("CN=GEM.SMCB-CA");
    }

    @Test
    @DisplayName(
        "TIP1-A_4587 VerifyPin PIN.SMC: mit LIANAs SMC-B-Handle; Status und PinResult OK wie im Trace (simuliertes PIN-Pad)")
    void verifyPin(Replay replay) {
      var exchange = replay.exchange(VERIFY_PIN);
      assertThat(exchange.replaced()).containsKey(TU_SMCB);
      exchange.assertSameAt(
          "$.responseCode",
          "$.body.Envelope.Body.VerifyPinResponse.Status.Result.text",
          "$.body.Envelope.Body.VerifyPinResponse.PinResult.text");
    }

    @Test
    @DisplayName(
        "TIP1-A_5439-02 ExternalAuthenticate nach VerifyPin: Status OK und Signaturtyp urn:bsi:tr:03111:ecdsa wie im "
            + "Trace; die Signatur selbst stammt von smcb-valid")
    void externalAuthenticate(Replay replay) {
      var exchange = replay.exchange(EXTERNAL_AUTHENTICATE);
      assertThat(exchange.replaced()).containsKey(TU_SMCB);
      exchange.assertSameAt(
          "$.responseCode",
          "$.body.Envelope.Body.ExternalAuthenticateResponse.Status.Result.text",
          "$.body.Envelope.Body.ExternalAuthenticateResponse.SignatureObject.Base64Signature.Type");
      exchange
          .assertThatLianaResponse()
          .hasChildWithPath(
              "$.body.Envelope.Body.ExternalAuthenticateResponse.SignatureObject.Base64Signature.text");
    }
  }

  @Nested
  @DisplayName("PoPP-Tunnel: StartCardSession, SecureSendAPDU der Sequenzen 0–3, StopCardSession")
  class CardSession {

    private static final String TRACE_SESSION = "84dd0fde-d04f-4834-af17-7058baa675ec";
    private static final String RESPONSE = "$.body.Envelope.Body.SecureSendAPDUResponse.";
    private static final String RESULT = RESPONSE + "Status.Result.text";
    private static final String TIME_SPAN = RESPONSE + "SignedScenarioResponse.TimeSpan.text";
    private static final String RESPONSE_APDUS =
        RESPONSE + "SignedScenarioResponse.ResponseApduList.ResponseApdu.text";
    private static final String FAULT = "$.body.Envelope.Body.Fault.";

    /** Requests of the trace, from 0. */
    private static final int START_CARD_SESSION = 1;

    private static final int SEQUENZ_0 = 7;
    private static final int SEQUENZ_1 = 8;
    private static final int SEQUENZ_2 = 9;
    private static final int SEQUENZ_3 = 10;
    private static final int STOP_CARD_SESSION = 11;

    @Test
    @DisplayName(
        "A_25970-01 StartCardSession: Status wie im Trace, SessionId ist eine UUID, die LIANA vergibt")
    void startCardSession(Replay replay) {
      var exchange = replay.exchange(START_CARD_SESSION);
      exchange.assertSameAt(
          "$.responseCode", "$.body.Envelope.Body.StartCardSessionResponse.Status.Result.text");
      assertThat(UUID.fromString(sessionId(replay)).toString())
          .isEqualTo(sessionId(replay))
          .isNotEqualTo(TRACE_SESSION);
    }

    @Test
    @DisplayName("A_25822-02 SecureSendAPDU geht mit LIANAs SessionId, neu signiert")
    void secureSendMitLianasSessionId(Replay replay) {
      for (int i = SEQUENZ_0; i <= SEQUENZ_3; i++) {
        assertThat(replay.exchange(i).replaced()).containsEntry(TRACE_SESSION, sessionId(replay));
        assertThat(replay.exchange(i).adjustments())
            .contains("JWS neu signiert mit dem Test-Signer aus support/pki/replay");
      }
    }

    @Test
    @DisplayName(
        "A_25822-02 Sequenz 0 und 1: Status, Anzahl ResponseApdu, Statuswörter und TimeSpan wie im Trace")
    void sequenz0und1(Replay replay) {
      for (int i : List.of(SEQUENZ_0, SEQUENZ_1)) {
        var exchange = replay.exchange(i);
        exchange.assertSameAt("$.responseCode", RESULT, TIME_SPAN);
        assertThat(statusWords(exchange.lianaResponse()))
            .isEqualTo(statusWords(exchange.traceResponse()));
      }
    }

    @Test
    @DisplayName(
        "A_25822-02 Sequenz 2 (Trusted Channel, Konnektor-Blueprint): alle Statuswörter 9000 wie im Trace, "
            + "GENERAL AUTHENTICATE liefert einen ephemeren Schlüssel derselben Länge")
    void sequenz2(Replay replay) {
      var exchange = replay.exchange(SEQUENZ_2);
      exchange.assertSameAt("$.responseCode", RESULT, TIME_SPAN);
      assertThat(statusWords(exchange.traceResponse())).containsOnly("9000");
      assertThat(statusWords(exchange.lianaResponse())).hasSize(6).containsOnly("9000");
      assertThat(last(exchange.lianaResponse()))
          .startsWith("7C4385410")
          .hasSameSizeAs(last(exchange.traceResponse()));
    }

    @Test
    @DisplayName(
        "TUC_KON_208 Sequenz 3: GENERAL AUTHENTICATE 9000 wie im Trace; das Secure Messaging trägt MACs zum "
            + "Sitzungsschlüssel der TU-Karte, egk-valid lehnt es ab (6988, gemSpec_COS G2_N031.700.b) → Warning 4284, Abbruch; TimeSpan 0 wie im Trace")
    void sequenz3(Replay replay) {
      var exchange = replay.exchange(SEQUENZ_3);
      exchange.assertSameAt("$.responseCode", TIME_SPAN);
      assertThat(statusWords(exchange.traceResponse())).containsExactly("9000", "9000", "9000");
      assertThat(statusWords(exchange.lianaResponse())).containsExactly("9000", "6988");
      assertThat(text(exchange.lianaResponse(), RESULT)).isEqualTo("Warning");
      assertThat(text(exchange.lianaResponse(), RESPONSE + "Status.Error.Trace.Code.text"))
          .isEqualTo("4284");
    }

    @Test
    @DisplayName(
        "A_26022 / TUC_KON_208: nach dem letzten Szenario ist die Sitzung beendet, StopCardSession → Fault 4288 wie im Trace")
    void stopCardSession(Replay replay) {
      var exchange = replay.exchange(STOP_CARD_SESSION);
      exchange
          .assertThatSentRequest()
          .hasStringContentEqualToAtPosition(
              "$.body.Envelope.Body.StopCardSession.SessionId.text", sessionId(replay));
      exchange.assertSameAt(
          "$.responseCode",
          FAULT + "faultcode.text",
          FAULT + "faultstring.text",
          FAULT + "detail.Error.Trace.Code.text",
          FAULT + "detail.Error.Trace.ErrorType.text",
          FAULT + "detail.Error.Trace.Severity.text");
    }

    private static String sessionId(Replay replay) {
      return text(
          replay.exchange(START_CARD_SESSION).lianaResponse(), PoppKonTuGegenLiana.SESSION_ID);
    }

    /**
     * Status words of the ResponseApdus (last two bytes); response data is ephemeral or
     * card-specific.
     */
    private static List<String> statusWords(RbelElement response) {
      return responseApdus(response).stream()
          .map(apdu -> apdu.substring(apdu.length() - 4).toUpperCase())
          .toList();
    }

    private static String last(RbelElement response) {
      return responseApdus(response).getLast();
    }

    private static List<String> responseApdus(RbelElement response) {
      return response.findRbelPathMembers(RESPONSE_APDUS).stream()
          .map(RbelElement::getRawStringContent)
          .toList();
    }

    private static String text(RbelElement element, String rbelPath) {
      return element
          .findElement(rbelPath)
          .orElseThrow(() -> new AssertionError(rbelPath + " fehlt"))
          .getRawStringContent();
    }
  }
}
