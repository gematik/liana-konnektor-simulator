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
package de.gematik.liana.kern.management;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.event.SystemLog;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class ManagementSettingsTest {

  private final SystemLog log = new SystemLog(Clock.systemUTC(), 10);
  private final ManagementSettings settings =
      new ManagementSettings(Duration.ofSeconds(120), Duration.ofSeconds(10), log);

  @Test
  @DisplayName(
      "TAB_KON_554: CARD_SESSION_TIMEOUT 10–180 s setzbar, außerhalb abgelehnt, reset stellt den Boot-Wert her")
  void sessionTimeout() {
    settings.sessionTimeout(Duration.ofSeconds(10));
    assertEquals(Duration.ofSeconds(10), settings.sessionTimeout());
    settings.sessionTimeout(Duration.ofSeconds(180));
    assertThrows(
        IllegalArgumentException.class, () -> settings.sessionTimeout(Duration.ofSeconds(9)));
    assertThrows(
        IllegalArgumentException.class, () -> settings.sessionTimeout(Duration.ofSeconds(181)));
    assertEquals(Duration.ofSeconds(180), settings.sessionTimeout());
    settings.reset();
    assertEquals(Duration.ofSeconds(120), settings.sessionTimeout());
  }

  @Test
  @DisplayName(
      "TAB_KON_658: MGM_LU_ONLINE ändern meldet MGM/LU_CHANGED/LU_ONLINE Op/Info Active=…, gleicher Wert meldet nichts")
  void online() {
    assertTrue(settings.online());
    settings.online(true);
    settings.online(false);
    settings.online(false);
    settings.online(true);
    assertEquals(
        List.of(Map.of("Active", "Disabled"), Map.of("Active", "Enabled")),
        log.entries(null, null).stream().map(SystemLog.Entry::parameters).toList());
    SystemLog.Entry entry = log.entries(null, null).getFirst();
    assertEquals(ManagementSettings.LU_ONLINE_CHANGED, entry.topic());
    assertEquals(SystemLog.Type.OP, entry.type());
    assertEquals(SystemLog.Severity.INFO, entry.severity());
    settings.online(false);
    settings.reset();
    assertTrue(settings.online());
    assertFalse(log.entries(null, null).isEmpty());
  }
}
