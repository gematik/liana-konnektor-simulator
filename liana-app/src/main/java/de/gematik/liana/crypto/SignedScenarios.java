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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.liana.kern.card.Scenario;
import de.gematik.liana.kern.card.ScenarioDecoder;
import de.gematik.liana.kern.error.ConnectorError;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Pattern;

/**
 * SignedScenario from SecureSendAPDU (A_25822-02): JWS Compact with ES256 and x5c, payload {@code
 * {"message": StandardScenarioMessage}} per I_PoPP_Token_Generation ([api-popp]).
 *
 * <p>Order per TAB_KON_271 step 2: signature with the key from {@code x5c[0]} (4701), then the
 * signer certificate per TUC_KON_037 ({@link ScenarioSignerCheck}, role oid_popp → 4700), then the
 * content (4286).
 *
 * <p>Content per A_26069-01 (TUC_KON_208 step 2): header per {@code SignedScenarioHeaders}, payload
 * per {@code SignedScenarioClaims} and {@code StandardScenarioMessage}. Unknown fields are ignored
 * (step 6c).
 */
public final class SignedScenarios implements ScenarioDecoder {

  /** SignedScenarioType from CardService v8.2. */
  private static final Pattern COMPACT =
      Pattern.compile("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+");

  private static final Pattern APDU = Pattern.compile("([0-9a-fA-F]{2}){4,}");
  private static final Pattern STATUS_WORD = Pattern.compile("[0-9a-fA-F]{4}");
  private static final int MAX_STEPS = 63;
  private static final long MAX_COUNTER = 32767;
  private static final ObjectMapper JSON = new ObjectMapper();

  private final ScenarioSignerCheck signerCheck;

  public SignedScenarios(ScenarioSignerCheck signerCheck) {
    this.signerCheck = signerCheck;
  }

  @Override
  public Scenario decode(String signedScenario) {
    if (signedScenario.length() > 750_000 || !COMPACT.matcher(signedScenario).matches()) {
      throw ConnectorError.SYNTAX.exception("SignedScenario ist kein JWS Compact");
    }
    EcJws.Verified verified;
    try {
      verified = EcJws.verifySignature(signedScenario);
    } catch (GeneralSecurityException e) {
      throw ConnectorError.SIGNATURE_INVALID.exception(e.getMessage()).causedBy(e);
    }
    signerCheck.check(verified.signer());
    headers(verified.header());
    try {
      return scenario(JSON.readTree(verified.payload()).path("message"));
    } catch (IOException e) {
      throw ConnectorError.SCENARIO_INVALID
          .exception("Payload ist kein JSON: " + e.getMessage())
          .causedBy(e);
    }
  }

  /**
   * SignedScenarioHeaders: {@code typ} "JWT" and {@code stpl}; {@link EcJws} checks {@code alg} and
   * {@code x5c}.
   */
  private static void headers(JsonNode header) {
    if (!"JWT".equals(header.path("typ").textValue())) {
      throw invalid("Header typ " + header.path("typ") + " statt JWT");
    }
    if (!header.path("stpl").isTextual()) {
      throw invalid("Header stpl fehlt");
    }
  }

  /** StandardScenarioMessage; deviations → 4286 (TUC_KON_208 step 2). */
  private static Scenario scenario(JsonNode message) {
    if (!"StandardScenario".equals(message.path("type").textValue())) {
      throw invalid("type " + message.path("type") + " statt StandardScenario");
    }
    if (!"1.0.0".equals(message.path("version").textValue())) {
      throw invalid("version " + message.path("version") + " statt 1.0.0");
    }
    JsonNode sessionId = message.path("clientSessionId");
    if (!sessionId.isTextual() || sessionId.asText().isBlank()) {
      throw invalid("clientSessionId fehlt");
    }
    JsonNode steps = message.path("steps");
    if (!steps.isArray() || steps.size() > MAX_STEPS) {
      throw invalid("steps fehlt oder hat mehr als " + MAX_STEPS + " Einträge");
    }
    List<Scenario.Step> parsed = new ArrayList<>();
    for (JsonNode step : steps) {
      String apdu = step.path("commandApdu").asText();
      if (!step.path("commandApdu").isTextual() || !APDU.matcher(apdu).matches()) {
        throw invalid("commandApdu '" + apdu + "'");
      }
      JsonNode expected = step.path("expectedStatusWords");
      if (!expected.isArray()) {
        throw invalid("expectedStatusWords fehlt");
      }
      List<String> words = new ArrayList<>();
      for (JsonNode word : expected) {
        if (!word.isTextual() || !STATUS_WORD.matcher(word.asText()).matches()) {
          throw invalid("expectedStatusWords '" + word.asText() + "'");
        }
        words.add(word.asText());
      }
      parsed.add(new Scenario.Step(HexFormat.of().parseHex(apdu), List.copyOf(words)));
    }
    return new Scenario(
        sessionId.asText(),
        number(message, "sequenceCounter"),
        number(message, "timeSpan"),
        List.copyOf(parsed));
  }

  /** {@code integer}, {@code minimum: 0}, {@code maximum: 32767}. */
  private static long number(JsonNode message, String field) {
    JsonNode value = message.path(field);
    if (!value.isIntegralNumber()
        || !value.canConvertToLong()
        || value.asLong() < 0
        || value.asLong() > MAX_COUNTER) {
      throw invalid(field + " " + value);
    }
    return value.asLong();
  }

  private static RuntimeException invalid(String detail) {
    return ConnectorError.SCENARIO_INVALID.exception(detail);
  }
}
