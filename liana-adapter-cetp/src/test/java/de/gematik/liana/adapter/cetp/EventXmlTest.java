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
package de.gematik.liana.adapter.cetp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.event.Event;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class EventXmlTest {

  private static final Event INSERTED;

  static {
    Map<String, String> parameters = new LinkedHashMap<>();
    parameters.put("CardHandle", "CH-1");
    parameters.put("CardType", "HBA");
    parameters.put("CtID", "KT-01");
    parameters.put("CardHolderName", "Rudolf Kätner <TEST-ONLY> & Co");
    INSERTED = new Event("CARD/INSERTED", Event.Type.OPERATION, Event.Severity.INFO, parameters);
  }

  @Test
  @DisplayName(
      "TIP1-A_4596 / TAB_KON_030: Event mit Topic, Type, Severity, SubscriptionID, Message/Parameter im "
          + "Namespace EventService v7.2, UTF-8, Sonderzeichen maskiert")
  void render() {
    String xml = new String(EventXml.render(INSERTED, "sub-1"), StandardCharsets.UTF_8);
    assertEquals(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Event xmlns=\"http://ws.gematik.de/conn/EventService/v7.2\">"
            + "<Topic>CARD/INSERTED</Topic><Type>Operation</Type><Severity>Info</Severity>"
            + "<SubscriptionID>sub-1</SubscriptionID><Message>"
            + "<Parameter><Key>CardHandle</Key><Value>CH-1</Value></Parameter>"
            + "<Parameter><Key>CardType</Key><Value>HBA</Value></Parameter>"
            + "<Parameter><Key>CtID</Key><Value>KT-01</Value></Parameter>"
            + "<Parameter><Key>CardHolderName</Key><Value>Rudolf Kätner &lt;TEST-ONLY&gt; &amp; Co</Value></Parameter>"
            + "</Message></Event>",
        xml);
  }

  @Test
  @DisplayName(
      "TUC_KON_256 Schritt 5c / TAB_KON_571: Filter als XPath mit Default-Namespace ohne Präfix oder mit "
          + "Präfix EVT; leeres Ergebnis verwirft, ohne Filter geht alles durch")
  void filter() {
    byte[] xml = EventXml.render(INSERTED, "sub-1");
    assertTrue(EventXml.matches(null, xml));
    assertTrue(EventXml.matches("/Event/Message/Parameter[Key='CardType' and Value='HBA']", xml));
    assertFalse(EventXml.matches("/Event/Message/Parameter[Key='CardType' and Value='EGK']", xml));
    assertTrue(EventXml.matches("//EVT:Parameter[EVT:Key='CtID']/EVT:Value = 'KT-01'", xml));
    assertFalse(EventXml.matches("//EVT:Parameter[EVT:Key='CtID']/EVT:Value = 'KT-02'", xml));
    assertTrue(EventXml.matches("Event/Topic", xml));
    assertFalse(EventXml.matches("/Event/Fehlt", xml));
  }

  @Test
  @DisplayName("TAB_KON_557: nicht auswertbarer Filter → FilterException (4095)")
  void filterFehler() {
    byte[] xml = EventXml.render(INSERTED, "sub-1");
    assertThrows(EventXml.FilterException.class, () -> EventXml.matches("/Event[", xml));
  }
}
