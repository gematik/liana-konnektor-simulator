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
package de.gematik.liana.adapter.sicct;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.net.InetAddress;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Packets of SICCT service discovery, protocol version 1.20 (SICCT 1.2.3 §6.2.3.1, tables 13 and
 * 14).
 */
class ServiceDiscoveryTest {

  static final HexFormat HEX = HexFormat.of();

  @Test
  @DisplayName("Tabelle 13: Dienstanfrage A0 mit Version 0114, Client-IP und Client-Port")
  void anfrage() throws Exception {
    assertArrayEquals(
        HEX.parseHex("a00e800201148104c0a80a07820212a6"),
        ServiceDiscovery.enquiry(InetAddress.getByName("192.168.10.7"), 4774));
  }

  @Test
  @DisplayName("Tabelle 14: Dienstbeschreibung A1 mit IP, MAC, Name, Port und TLS 1.2 (A3 8A 30)")
  void beschreibung() throws Exception {
    byte[] packet =
        HEX.parseHex(
            "a12d8002011481047f00000183060011223344558410"
                + HEX.formatHex("kartos-terminal1".getBytes())
                + "82021286a3038a0130");
    ServiceDiscovery.Announcement announcement = ServiceDiscovery.announcement(packet);
    assertEquals(InetAddress.getByName("127.0.0.1"), announcement.ip());
    assertEquals("00:11:22:33:44:55", announcement.mac());
    assertEquals("kartos-terminal1", announcement.name());
    assertEquals(4742, announcement.port());
    assertEquals(List.of(0x30), announcement.tlsVersions());
    assertArrayEquals(packet, ServiceDiscovery.encode(announcement));
  }

  @Test
  @DisplayName("Keine Dienstbeschreibung: Anfrage (A0), fehlende Pflichtfelder, falsche Längen")
  void abgewiesen() {
    assertThrows(
        IOException.class,
        () -> ServiceDiscovery.announcement(HEX.parseHex("a00e800201148104c0a80a07820212a6")));
    assertThrows(
        IOException.class,
        () -> ServiceDiscovery.announcement(HEX.parseHex("a10e8002011481047f00000182021286")));
    assertThrows(
        IOException.class,
        () ->
            ServiceDiscovery.announcement(
                HEX.parseHex("a1188002011481037f0000830600112233445584014182021286")));
    assertThrows(IOException.class, () -> ServiceDiscovery.announcement(HEX.parseHex("a1ff00")));
  }
}
