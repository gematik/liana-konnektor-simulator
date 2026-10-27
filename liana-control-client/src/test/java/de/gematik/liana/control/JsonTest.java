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
package de.gematik.liana.control;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class JsonTest {

  @Test
  @DisplayName("Schreiben und wieder Lesen: Escapes, Zahlen, Listen, null")
  void roundTrip() {
    Map<String, Object> value = new LinkedHashMap<>();
    value.put("image", "egk \"valid\"\\\n\u0001");
    value.put("count", 1);
    value.put("slots", List.of(1.5, true));
    value.put("none", null);
    String json = Json.write(value);
    assertEquals(
        "{\"image\":\"egk \\\"valid\\\"\\\\\\n\\u0001\",\"count\":1,\"slots\":[1.5,true],\"none\":null}",
        json);
    Map<String, Object> back = new LinkedHashMap<>(value);
    back.put("count", 1.0);
    assertEquals(back, Json.parse(json));
    assertEquals(
        "[{\"outcome\":\"wrong\",\"slotNo\":2}]",
        Json.write(List.of(PinInput.wrong().slot(2).json())));
    assertEquals(
        "{\"type\":\"status-word\",\"statusWord\":\"6A82\",\"commandPrefix\":\"00B0\",\"count\":1}",
        Json.write(Fault.statusWord("6A82").commandPrefix("00B0").count(1).json()));
  }
}
