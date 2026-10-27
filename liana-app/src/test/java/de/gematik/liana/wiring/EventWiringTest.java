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
package de.gematik.liana.wiring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.gematik.liana.adapter.cetp.CetpSender;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class EventWiringTest {

  @Test
  @DisplayName(
      "LIANA-183 liana.events.redirect: jede CETP-Verbindung geht an die feste Adresse statt an das EventTo")
  void umgeleitet() throws Exception {
    List<String> targets = new ArrayList<>();
    CetpSender.Connector connector =
        (host, port) -> {
          targets.add(host + ":" + port);
          return new Socket();
        };

    CetpSender.Connector redirected = EventWiring.redirected(connector, "liana-ps-tiger-cetp:7001");
    redirected.connect("192.168.1.20", 4711).close();
    redirected.connect("ps.example", 9000).close();

    assertEquals(List.of("liana-ps-tiger-cetp:7001", "liana-ps-tiger-cetp:7001"), targets);
  }

  @Test
  @DisplayName("LIANA-183 liana.events.redirect ohne Port ist ein Konfigurationsfehler")
  void ohnePort() {
    CetpSender.Connector connector = (host, port) -> new Socket();
    assertThrows(IllegalArgumentException.class, () -> EventWiring.redirected(connector, "tiger"));
    assertThrows(IllegalArgumentException.class, () -> EventWiring.redirected(connector, "tiger:"));
  }
}
