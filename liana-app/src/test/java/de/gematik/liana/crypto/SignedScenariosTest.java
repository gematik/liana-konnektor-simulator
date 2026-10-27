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
package de.gematik.liana.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import de.gematik.liana.crypto.ReplaySigner.Profile;
import de.gematik.liana.kern.card.Scenario;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.time.Clock;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

class SignedScenariosTest {

  private static final Pattern SIGNED_SCENARIO = Pattern.compile("SignedScenario>([^<]+)<");
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final String SCENARIO =
      """
            {"type":"StandardScenario","version":"1.0.0","clientSessionId":"s","sequenceCounter":0,"timeSpan":0,\
            "steps":[{"commandApdu":"00B0910000","expectedStatusWords":["9000"]}]}""";
  private static SignedScenarios decoder;

  @BeforeAll
  static void decoder() {
    if (Security.getProvider(CryptoProviders.BC) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    decoder =
        new SignedScenarios(
            new ScenarioSignerCheck(
                TrustSpace.load(
                    ScenarioSignerCheckTest.TSL, List.of(ScenarioSignerCheckTest.REPLAY_CA)),
                Clock.systemUTC()));
  }

  /**
   * The first SignedScenario from the popp-kon-tu trace, as signed by the PoPP service of the TU.
   */
  private static String fromTrace() throws Exception {
    var json = new ObjectMapper();
    for (String line :
        Files.readAllLines(Path.of("support/vendor/traces/popp-kon-tu/popp-client.tgr"))) {
      var raw =
          new String(
              Base64.getDecoder().decode(json.readTree(line).path("rawMessageContent").asText()),
              StandardCharsets.UTF_8);
      var matcher = SIGNED_SCENARIO.matcher(raw);
      if (matcher.find()) {
        return matcher.group(1);
      }
    }
    throw new AssertionError("kein SignedScenario im Trace");
  }

  @Test
  @Tag("vendor-data")
  @DisplayName(
      "A_25822-02: SignedScenario des TU-PoPP-Service aus popp-kon-tu – Signatur und Signer (TSL) gültig, "
          + "Szenario 0 gelesen")
  void trace() throws Exception {
    Scenario scenario = decoder.decode(fromTrace());
    assertEquals("84dd0fde-d04f-4834-af17-7058baa675ec", scenario.clientSessionId());
    assertEquals(0, scenario.sequenceCounter());
    assertEquals(10000, scenario.timeSpan());
    assertEquals(
        "00A4040C07D2760001448000",
        HexFormat.of().withUpperCase().formatHex(scenario.steps().getFirst().commandApdu()));
    assertEquals(List.of("9000", "6281"), scenario.steps().get(1).expectedStatusWords());
  }

  @Test
  @Tag("vendor-data")
  @DisplayName("TAB_KON_271 Schritt 2: veränderter Payload → 4701")
  void signatur() throws Exception {
    String[] parts = fromTrace().split("\\.");
    String forged =
        parts[0]
            + "."
            + Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString("{\"message\":{}}".getBytes(StandardCharsets.UTF_8))
            + "."
            + parts[2];
    assertError(ConnectorError.SIGNATURE_INVALID, () -> decoder.decode(forged));
  }

  @Test
  @DisplayName(
      "TAB_KON_271 Schritt 2: Signer ohne oid_popp → 4700, erst nach der Signatur (4701) und vor dem Inhalt (4286)")
  void reihenfolge() throws Exception {
    var poppToken = ReplaySigner.issue(Profile.poppService().withRole(ReplaySigner.OID_POPP_TOKEN));
    assertError(
        ConnectorError.CERT_ROLE, () -> decoder.decode(ReplaySigner.sign(poppToken, SCENARIO)));
    String jws = ReplaySigner.sign(poppToken, SCENARIO);
    String forged = jws.substring(0, jws.length() - 4) + (jws.endsWith("AAAA") ? "BBBB" : "AAAA");
    assertError(ConnectorError.SIGNATURE_INVALID, () -> decoder.decode(forged));
    assertError(
        ConnectorError.CERT_ROLE,
        () -> decoder.decode(ReplaySigner.sign(poppToken, "{\"type\":\"Other\"}")));
  }

  @Test
  @DisplayName("checkArguments: kein JWS Compact → 4000")
  void format() {
    assertError(ConnectorError.SYNTAX, () -> decoder.decode("kein.jws"));
    assertError(ConnectorError.SYNTAX, () -> decoder.decode("a.b.c d"));
  }

  /** {@link #SCENARIO}, changed in one place. */
  private static ObjectNode message(Consumer<ObjectNode> change) throws Exception {
    ObjectNode message = (ObjectNode) JSON.readTree(SCENARIO);
    change.accept(message);
    return message;
  }

  private static ObjectNode step(ObjectNode message) {
    return (ObjectNode) message.withArray("steps").get(0);
  }

  private static ArrayNode steps(ObjectNode message, int count) {
    ArrayNode steps = message.putArray("steps");
    for (int i = 0; i < count; i++) {
      steps
          .addObject()
          .put("commandApdu", "00B0910000")
          .putArray("expectedStatusWords")
          .add("9000");
    }
    return steps;
  }

  private static Scenario decode(ObjectNode message) throws Exception {
    return decoder.decode(ReplaySigner.sign(message.toString()));
  }

  private static void assertInvalid(ObjectNode message) throws Exception {
    String jws = ReplaySigner.sign(message.toString());
    assertError(ConnectorError.SCENARIO_INVALID, () -> decoder.decode(jws));
  }

  @Test
  @DisplayName(
      "A_26069-01 TUC_KON_208 Schritt 2: Schritt ohne expectedStatusWords (umbenannt in expectedStatus wie "
          + "EE_KON_POPP_FF_014) → 4286")
  void ohneExpectedStatusWords() throws Exception {
    assertInvalid(
        message(m -> step(m).set("expectedStatus", step(m).remove("expectedStatusWords"))));
    assertInvalid(message(m -> step(m).put("expectedStatusWords", "9000")));
  }

  @Test
  @DisplayName("TUC_KON_208 Schritt 6c: unbekannte Felder im Schritt bleiben unbeachtet")
  void unbekanntesFeld() throws Exception {
    Scenario scenario = decode(message(m -> step(m).putArray("expectedStatus").add("6A82")));
    assertEquals(List.of("9000"), scenario.steps().getFirst().expectedStatusWords());
  }

  @Test
  @DisplayName("A_26069-01: version fehlt → 4286")
  void ohneVersion() throws Exception {
    assertInvalid(message(m -> m.remove("version")));
  }

  @Test
  @DisplayName("A_26069-01: version ≠ \"1.0.0\" → 4286")
  void andereVersion() throws Exception {
    assertInvalid(message(m -> m.put("version", "1.0.1")));
  }

  @Test
  @DisplayName("A_26069-01: 64 steps → 4286 (maxItems 63), 63 steps gültig")
  void schrittzahl() throws Exception {
    assertInvalid(message(m -> steps(m, 64)));
    assertEquals(63, decode(message(m -> steps(m, 63))).steps().size());
  }

  @Test
  @DisplayName("A_26069-01: steps [] gültig (minItems 0)")
  void ohneSchritte() throws Exception {
    assertEquals(List.of(), decode(message(m -> steps(m, 0))).steps());
  }

  @Test
  @DisplayName("A_26069-01: sequenceCounter 32768 → 4286 (maximum 32767), 32767 gültig")
  void sequenceCounterGrenze() throws Exception {
    assertInvalid(message(m -> m.put("sequenceCounter", 32768)));
    assertEquals(32767, decode(message(m -> m.put("sequenceCounter", 32767))).sequenceCounter());
  }

  @Test
  @DisplayName("A_26069-01: timeSpan 32768 → 4286 (maximum 32767), 32767 gültig")
  void timeSpanGrenze() throws Exception {
    assertInvalid(message(m -> m.put("timeSpan", 32768)));
    assertEquals(32767, decode(message(m -> m.put("timeSpan", 32767))).timeSpan());
  }

  @Test
  @DisplayName("A_26069-01 SignedScenarioHeaders: typ ≠ \"JWT\" → 4286")
  void headerTyp() throws Exception {
    String jws =
        ReplaySigner.signPayload(
            ReplaySigner.signer(),
            Map.of("typ", "JOSE", "stpl", "TUlBPQ=="),
            "{\"message\":" + SCENARIO + "}");
    assertError(ConnectorError.SCENARIO_INVALID, () -> decoder.decode(jws));
  }

  @Test
  @DisplayName("A_26069-01 SignedScenarioHeaders: stpl fehlt → 4286")
  void headerOhneStpl() throws Exception {
    String jws =
        ReplaySigner.signPayload(ReplaySigner.signer(), Map.of(), "{\"message\":" + SCENARIO + "}");
    assertError(ConnectorError.SCENARIO_INVALID, () -> decoder.decode(jws));
  }

  @Test
  @DisplayName("A_26069-01: ungültige commandApdu → 4286")
  void commandApdu() throws Exception {
    assertInvalid(message(m -> step(m).put("commandApdu", "00B0")));
    assertInvalid(message(m -> step(m).put("commandApdu", "00B091000G")));
    assertInvalid(message(m -> step(m).remove("commandApdu")));
  }

  @Test
  @DisplayName("A_26069-01: ungültiges Statuswort → 4286")
  void statuswort() throws Exception {
    assertInvalid(message(m -> step(m).putArray("expectedStatusWords").add("90")));
    assertInvalid(message(m -> step(m).putArray("expectedStatusWords").add(9000)));
  }

  @Test
  @DisplayName("A_26069-01: clientSessionId fehlt oder leer → 4286")
  void clientSessionId() throws Exception {
    assertInvalid(message(m -> m.remove("clientSessionId")));
    assertInvalid(message(m -> m.put("clientSessionId", "")));
  }

  @Test
  @DisplayName("A_26069-01: negativer sequenceCounter bzw. timeSpan → 4286")
  void negativ() throws Exception {
    assertInvalid(message(m -> m.put("sequenceCounter", -1)));
    assertInvalid(message(m -> m.put("timeSpan", -1)));
  }

  @Test
  @DisplayName("A_26069-01: type ≠ \"StandardScenario\" → 4286")
  void type() throws Exception {
    assertInvalid(message(m -> m.put("type", "Other")));
  }

  @Test
  @DisplayName("A_26069-01 SignedScenarioClaims: message fehlt → 4286")
  void ohneMessage() throws Exception {
    String jws = ReplaySigner.signPayload(ReplaySigner.signer(), ReplaySigner.HEADERS, SCENARIO);
    assertError(ConnectorError.SCENARIO_INVALID, () -> decoder.decode(jws));
  }

  private static void assertError(ConnectorError expected, Executable call) {
    assertEquals(expected, assertThrows(ConnectorException.class, call).error());
  }
}
