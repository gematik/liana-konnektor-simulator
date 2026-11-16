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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * LIANA-195.03: {@link TigerWebUi} against the WebUI of Tiger {@value TigerStub#VERSION}, as
 * recorded; JSON goes through unchanged.
 */
class TigerWebUiTest {

  private final TigerStub stub = new TigerStub(0);
  private final TigerWebUi tiger =
      new TigerWebUi(URI.create("http://localhost:" + stub.port()), Duration.ofSeconds(5));

  @AfterEach
  void stop() {
    stub.close();
  }

  @Test
  @DisplayName("Nachrichten: getMessagesWithMeta unverändert, ohne Filter ohne Query")
  void messages() throws Exception {
    assertEquals(TigerStub.fixture("getMessagesWithMeta.json"), tiger.messages(null, null, null));
    assertEquals("", stub.queries.take());
  }

  @Test
  @DisplayName("Filter und Zeitfenster gehen als filterRbelPath, minTimestamp und maxTimestamp")
  void filter() throws Exception {
    Instant from = Instant.parse("2026-11-16T13:00:00Z");
    Instant to = Instant.parse("2026-11-16T13:00:01Z");
    assertEquals(
        TigerStub.fixture("getMessagesWithMeta-filter.json"),
        tiger.messages(TigerStub.FILTER, from, to));
    assertEquals(
        "filterRbelPath=" + TigerStub.FILTER + "&minTimestamp=" + from + "&maxTimestamp=" + to,
        stub.queries.take());
  }

  @Test
  @DisplayName("Ein Filter, den Tiger nicht auswerten kann (500), ist Rejected")
  void rejected() {
    assertThrows(TigerWebUi.Rejected.class, () -> tiger.messages("$.foo ==", null, null));
  }

  @Test
  @DisplayName("Proxy nicht erreichbar: Unavailable mit der Adresse")
  void unavailable() throws IOException {
    int closed;
    try (ServerSocket socket = new ServerSocket(0)) {
      closed = socket.getLocalPort();
    }
    TigerWebUi gone =
        new TigerWebUi(URI.create("http://localhost:" + closed), Duration.ofSeconds(2));
    TigerWebUi.Unavailable e =
        assertThrows(TigerWebUi.Unavailable.class, () -> gone.messages(null, null, null));
    assertTrue(e.getMessage().contains("localhost:" + closed), e.getMessage());
  }
}
