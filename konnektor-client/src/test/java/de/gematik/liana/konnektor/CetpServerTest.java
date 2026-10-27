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
package de.gematik.liana.konnektor;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.DataOutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** LIANA-137: CETP reception (TIP1-A_4596) with the event XML as LIANA's EventXml renders it. */
class CetpServerTest {

  static byte[] event(String topic, String subscription, String... keyValues) {
    StringBuilder xml =
        new StringBuilder(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Event xmlns=\""
                + "http://ws.gematik.de/conn/EventService/v7.2\"><Topic>"
                + topic
                + "</Topic><Type>Operation</Type>"
                + "<Severity>Info</Severity><SubscriptionID>"
                + subscription
                + "</SubscriptionID><Message>");
    for (int i = 0; i < keyValues.length; i += 2) {
      xml.append("<Parameter><Key>")
          .append(keyValues[i])
          .append("</Key><Value>")
          .append(keyValues[i + 1])
          .append("</Value></Parameter>");
    }
    return xml.append("</Message></Event>").toString().getBytes(StandardCharsets.UTF_8);
  }

  @Test
  @DisplayName(
      "\"CETP\", Länge Big-Endian, Event-XML; mehrere Ereignisse über eine Verbindung (LIANA-95)")
  void empfang() throws Exception {
    LinkedBlockingQueue<KonnektorEvent> events = new LinkedBlockingQueue<>();
    try (CetpServer server = new CetpServer(EventSink.plain("127.0.0.1", 0), events::add);
        Socket socket = new Socket(InetAddress.getLoopbackAddress(), server.port())) {
      DataOutputStream out = new DataOutputStream(socket.getOutputStream());
      for (byte[] xml :
          List.of(
              event(
                  "CARD/INSERTED",
                  "S1",
                  "CardHandle",
                  "EGK-7",
                  "CardType",
                  "EGK",
                  "ICCSN",
                  "80276",
                  "CtID",
                  "KT-02",
                  "SlotID",
                  "1"),
              event("CARD/REMOVED", "S1"))) {
        out.write("CETP".getBytes(StandardCharsets.US_ASCII));
        out.writeInt(xml.length);
        out.write(xml);
      }
      out.flush();
      KonnektorEvent inserted = events.poll(5, TimeUnit.SECONDS);
      assertEquals("CARD/INSERTED", inserted.topic());
      assertEquals("Operation", inserted.type());
      assertEquals("Info", inserted.severity());
      assertEquals("S1", inserted.subscriptionId());
      assertEquals(
          Map.of(
              "CardHandle",
              "EGK-7",
              "CardType",
              "EGK",
              "ICCSN",
              "80276",
              "CtID",
              "KT-02",
              "SlotID",
              "1"),
          inserted.parameters());
      assertEquals("CARD/REMOVED", events.poll(5, TimeUnit.SECONDS).topic());
    }
  }
}
