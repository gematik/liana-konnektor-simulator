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

import de.gematik.liana.crypto.ReplaySigner;
import de.gematik.liana.crypto.ReplaySigner.Profile;
import de.gematik.liana.crypto.ReplaySigner.Signer;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.List;

/**
 * Replacement for the PoPP service and popp-bridge of the Konnektor PoPP test suite ({@code
 * ../konnektor-popp-testsuite}, revision 9069cae), so that the collections run without Docker,
 * newman, bridge and PoPP service.
 *
 * <p>{@link #start(String)} and {@link #responses(List)} correspond to {@code POST /bridge} with
 * {@code Start} and {@code ScenarioResponse} respectively: the PoPP service answers with the next
 * scenario from {@code support/blueprints/} (sequence 0, 1, …), with the {@code clientSessionId} of
 * the card session inserted, signed by the replay signer (profile of the PoPP service, oid_popp;
 * LIANA imports the replay CA in the test profile). It does not evaluate the card responses.
 *
 * <p>The static methods emulate the manipulations of the bridge and the Postman scripts.
 */
final class PoppServiceDouble {

  private static final Path BLUEPRINTS = Path.of("support/blueprints");

  private boolean connected;
  private String clientSessionId;
  private int sequence;

  /** {@code POST /bridge/start}: open the WebSocket to the PoPP service. */
  void connect() {
    connected = true;
  }

  /** {@code POST /bridge/stop}: close the WebSocket. */
  void close() {
    connected = false;
    clientSessionId = null;
  }

  /**
   * {@code {"type":"Start",…,"clientSessionId":…,"cardConnectionType":"contact-connector"}} →
   * scenario 0.
   */
  String start(String clientSessionId) {
    requireConnected();
    this.clientSessionId = clientSessionId;
    this.sequence = 0;
    return scenario(sequence);
  }

  /** {@code {"type":"ScenarioResponse","steps":[…]}} → next scenario. */
  String responses(List<String> responseApdus) {
    requireConnected();
    if (clientSessionId == null || responseApdus.isEmpty()) {
      throw new IllegalStateException("ScenarioResponse ohne Start oder ohne Antworten");
    }
    return scenario(++sequence);
  }

  private void requireConnected() {
    if (!connected) {
      throw new IllegalStateException(
          "WebSocket connection not established. Call /bridge/start first.");
    }
  }

  private String scenario(int number) {
    JsonObject message = blueprint(number).put("clientSessionId", clientSessionId);
    return sign(popp(), message);
  }

  static JsonObject blueprint(int number) {
    try {
      return new JsonObject(
          Files.readString(BLUEPRINTS.resolve("poppApdusSequence" + number + ".json")));
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  // --- Bridge: re-sign (JwtSignService), signer by role
  // ------------------------------------------------------------

  /**
   * {@code /bridge/resignScenario}: the same message, signed with a certificate of the technical
   * role {@code oid}.
   */
  static String resign(String jws, String roleOid) {
    try {
      return sign(ReplaySigner.issue(Profile.poppService().withRole(roleOid)), message(jws));
    } catch (GeneralSecurityException | IOException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * {@code /bridge/manipulateFirstExpectedStatus}: {@code steps[0].expectedStatusWords =
   * [statusWord]}, re-signed (oid_popp).
   */
  static String manipulateFirstExpectedStatus(String jws, String statusWord) {
    JsonObject message = message(jws);
    message
        .getJsonArray("steps")
        .getJsonObject(0)
        .put("expectedStatusWords", new JsonArray().add(statusWord));
    return sign(popp(), message);
  }

  /**
   * {@code /bridge/renameFirstExpectedStatusWordsInPayload}: key {@code expectedStatusWords} in
   * {@code steps[0]} renamed, re-signed (oid_popp).
   */
  static String renameFirstExpectedStatusWords(String jws, String newKeyName) {
    JsonObject message = message(jws);
    JsonObject first = message.getJsonArray("steps").getJsonObject(0);
    first.put(newKeyName, first.remove("expectedStatusWords"));
    return sign(popp(), message);
  }

  // --- Postman scripts: change payload or signature without re-signing
  // --------------------------------------------

  /** Pre-request script FF_007/FF_008: change a field of the message, header and signature stay. */
  static String tamperMessage(String jws, String field, Object value) {
    String[] parts = jws.split("\\.");
    JsonObject payload =
        new JsonObject(new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));
    payload.getJsonObject("message").put(field, value);
    return parts[0] + "." + b64(payload.encode().getBytes(StandardCharsets.UTF_8)) + "." + parts[2];
  }

  /** Pre-request script FF_009: flip a bit in the first byte of the signature. */
  static String flipFirstSignatureBit(String jws) {
    String[] parts = jws.split("\\.");
    byte[] signature = Base64.getUrlDecoder().decode(parts[2]);
    signature[0] ^= 0x01;
    return parts[0] + "." + parts[1] + "." + b64(signature);
  }

  /** {@code message} from the payload of a JWS Compact. */
  static JsonObject message(String jws) {
    return payload(jws).getJsonObject("message");
  }

  /** Payload of a JWS Compact. */
  static JsonObject payload(String jws) {
    return new JsonObject(
        new String(Base64.getUrlDecoder().decode(jws.split("\\.")[1]), StandardCharsets.UTF_8));
  }

  /** Header of a JWS Compact. */
  static JsonObject header(String jws) {
    return new JsonObject(
        new String(Base64.getUrlDecoder().decode(jws.split("\\.")[0]), StandardCharsets.UTF_8));
  }

  private static Signer popp() {
    try {
      return ReplaySigner.signer();
    } catch (GeneralSecurityException | IOException e) {
      throw new IllegalStateException(e);
    }
  }

  private static String sign(Signer signer, JsonObject message) {
    try {
      return ReplaySigner.sign(signer, message.encode());
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static String b64(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }
}
