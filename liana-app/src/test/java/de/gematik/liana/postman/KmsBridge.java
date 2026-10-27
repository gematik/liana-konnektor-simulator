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

import static io.restassured.RestAssured.given;

import io.restassured.specification.RequestSpecification;
import io.vertx.core.json.JsonObject;
import java.time.Clock;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * The KMS endpoints of the popp-bridge ({@code KmsConnector}, konnektor-popp-testsuite 9069cae)
 * without bridge and without kms-client: the same HTTP calls that {@code KmsEhex} sends to the EHEX
 * KMS (HTTPS without certificate verification, login, operation; the bridge does not log out),
 * responses as the bridge returns them to Postman. The environment corresponds to {@code
 * kmsVendorName=EHEX}, {@code kmsUsername}/{@code kmsPassword} from {@code
 * tools/testhub/postman/liana.postman_environment.json}. "Now" is the test clock, like {@code
 * Date.now()} in Postman and {@code System.currentTimeMillis()} in the bridge.
 */
final class KmsBridge {

  private final int port;
  private final Clock clock;

  KmsBridge(int port, Clock clock) {
    this.port = port;
    this.clock = clock;
  }

  /**
   * {@code /bridge/kms/findInLog}: {@code downloadLog(SYSTEM_OP, logPath, startTime, now)}, then
   * {@code SubstringLogSearchAll} searches for a line containing every part of {@code searched}
   * separated by {@code @@} (case-insensitive). Response {@code isFound}.
   */
  boolean findInLog(String searched, long startTime) {
    String log =
        session()
            .get(
                "/rest/mgmt/ak/dienste/protokoll/download/system/OP/"
                    + startTime
                    + "/"
                    + clock.millis())
            .then()
            .statusCode(200)
            .extract()
            .asString();
    List<String> parts =
        Arrays.stream(searched.split("@@")).map(p -> p.toLowerCase(Locale.ROOT)).toList();
    return log.lines()
        .map(l -> l.toLowerCase(Locale.ROOT))
        .anyMatch(line -> parts.stream().allMatch(line::contains));
  }

  /**
   * {@code /bridge/kms/getCardSessionTimeout}: {@code getValue(CARD_SESSION_TIMEOUT)}, response in
   * seconds.
   */
  String getCardSessionTimeout() {
    JsonObject dauer =
        new JsonObject(
                session()
                    .get("/rest/mgmt/ak/dienste/karten/einstellungen")
                    .then()
                    .statusCode(200)
                    .extract()
                    .asString())
            .getJsonObject("cardSessionTimeout");
    if (!"SECONDS".equals(dauer.getString("unit"))) {
      throw new IllegalStateException("kms-client rechnet nur SECONDS bis DAYS um: " + dauer);
    }
    return String.valueOf(dauer.getValue("amount"));
  }

  /**
   * {@code /bridge/kms/ensureKmsParameter} with MGM_LU_ONLINE: {@code getValue}, on mismatch {@code
   * setValue} (GET the group, set field {@code online} to ENABLED/DISABLED, PUT). Response {@code
   * status} "ok" or "error".
   */
  String ensureOnline(String paramVal) {
    RequestSpecification session = session();
    JsonObject group =
        new JsonObject(
            session
                .get("/rest/mgmt/nk/leistungsumfang/einstellungen")
                .then()
                .statusCode(200)
                .extract()
                .asString());
    String current = "ENABLED".equalsIgnoreCase(group.getString("online")) ? "Enabled" : "Disabled";
    if (current.equals(paramVal)) {
      return "ok";
    }
    group.put("online", paramVal.toUpperCase(Locale.ROOT));
    int status =
        session
            .contentType("application/json")
            .body(group.encode())
            .put("/rest/mgmt/nk/leistungsumfang/einstellungen")
            .statusCode();
    return status == 200 ? "ok" : "error";
  }

  /**
   * {@code kms.login(connectInfo)}: POST …/konten/login, token from the {@code Authorization}
   * header.
   */
  private RequestSpecification session() {
    String token =
        kms()
            .contentType("application/json")
            .body("{\"username\":\"super\",\"password\":\"33ee§§EE\"}")
            .post("/rest/mgmt/ak/konten/login")
            .then()
            .statusCode(204)
            .extract()
            .header("Authorization");
    return kms().header("Authorization", token);
  }

  private RequestSpecification kms() {
    return given().relaxedHTTPSValidation().baseUri("https://localhost").port(port);
  }
}
