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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.trace.Traffic;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** LIANA-195.05: each channel reports only while it is switched on, asked per message. */
class TraceChannelsTest {

  private final List<String> reported = new ArrayList<>();
  private final Traffic recording =
      new Traffic() {
        @Override
        public String report(
            byte[] message, String sender, String receiver, Instant time, String responseTo) {
          reported.add(sender);
          return "uuid-" + reported.size();
        }

        @Override
        public String name() {
          return "konnektor-a";
        }
      };

  @Test
  @DisplayName(
      "Ausgeschalteter Kanal meldet nichts, die anderen weiter; wieder an meldet er sofort")
  void schalten() {
    var channels = new TraceChannels(recording);
    Traffic kt = channels.traffic(TraceChannels.terminal("KT-01"));
    Traffic soap = channels.traffic(TraceChannels.KONNEKTOR);

    channels.set("kt:KT-01", false);
    assertNull(kt.report(new byte[1], "kt", "x", Instant.now(), null));
    assertEquals("uuid-1", soap.report(new byte[1], "soap", "x", Instant.now(), null));
    assertTrue(kt.active(), "aktiv bleibt, damit der Kanal ohne Neuverdrahtung wieder melden kann");
    assertEquals("konnektor-a", kt.name());
    assertEquals(Set.of("kt:KT-01"), channels.off());

    channels.set("kt:KT-01", true);
    assertEquals("uuid-2", kt.report(new byte[1], "kt", "x", Instant.now(), null));
    assertEquals(List.of("soap", "kt"), reported);
  }

  @Test
  @DisplayName("reset schaltet alle Kanäle an, wie beim Start")
  void reset() {
    var channels = new TraceChannels(recording);
    channels.set(TraceChannels.CETP, false);
    channels.set(TraceChannels.UFS, false);
    channels.reset();
    assertTrue(channels.on(TraceChannels.CETP));
    assertTrue(channels.off().isEmpty());
  }

  @Test
  @DisplayName("Ohne push-url bleibt jeder Kanal Traffic.OFF")
  void ohnePush() {
    var channels = new TraceChannels(Traffic.OFF);
    assertSame(Traffic.OFF, channels.traffic(TraceChannels.KONNEKTOR));
    assertFalse(channels.traffic(TraceChannels.KONNEKTOR).active());
  }
}
