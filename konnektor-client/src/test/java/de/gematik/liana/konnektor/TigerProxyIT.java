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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import de.gematik.rbellogger.data.RbelElement;
import de.gematik.test.tiger.common.data.config.tigerproxy.TigerProxyConfiguration;
import de.gematik.test.tiger.proxy.TigerProxy;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * LIANA-133 AC 2: with {@code proxy(host, port)} the traffic goes through a Tiger proxy that
 * records it and parses it as SOAP. The peer is a stub with LIANA's SDS; runs with {@code
 * -DskipITs=false}.
 */
class TigerProxyIT {

  @Test
  @DisplayName(
      "connector.sds und GetCards über den Tiger-Proxy: im Rbel-Log, SOAP-Umschlag und GetCards per RbelPath")
  void tigerLiestMit() throws Exception {
    byte[] sds;
    try (InputStream in = TigerProxyIT.class.getResourceAsStream("/sds/liana.xml")) {
      sds =
          new String(in.readAllBytes(), StandardCharsets.UTF_8)
              .replace("http://localhost:8080", "http://127.0.0.1:PORT")
              .getBytes(StandardCharsets.UTF_8);
    }
    HttpServer stub =
        HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    int port = stub.getAddress().getPort();
    byte[] directory =
        new String(sds, StandardCharsets.UTF_8)
            .replace("PORT", String.valueOf(port))
            .getBytes(StandardCharsets.UTF_8);
    stub.createContext(
        "/connector.sds",
        exchange -> {
          exchange.getResponseHeaders().add("Content-Type", "application/xml");
          exchange.sendResponseHeaders(200, directory.length);
          exchange.getResponseBody().write(directory);
          exchange.close();
        });
    stub.createContext(
        "/ws/EventService",
        exchange -> {
          byte[] body = KonnektorTest.GET_CARDS_RESPONSE.getBytes(StandardCharsets.UTF_8);
          exchange.getRequestBody().readAllBytes();
          exchange.getResponseHeaders().add("Content-Type", "text/xml; charset=UTF-8");
          exchange.sendResponseHeaders(200, body.length);
          exchange.getResponseBody().write(body);
          exchange.close();
        });
    stub.start();
    try (TigerProxy tiger = new TigerProxy(TigerProxyConfiguration.builder().proxyPort(0).build());
        Konnektor kon =
            Konnektor.builder()
                .url("http://127.0.0.1:" + port)
                .context("M1", "CS1", "WP1", null)
                .proxy("127.0.0.1", tiger.getProxyPort())
                .build()) {
      assertEquals(
          "OK",
          kon.invoke(
                  Operation.GET_CARDS,
                  KonnektorTest.request(),
                  de.gematik.liana.konnektor.ws.conn.eventservice.v7_2.GetCardsResponse.class)
              .getStatus()
              .getResult());
      tiger.waitForAllCurrentMessagesToBeParsed();
      List<RbelElement> messages = tiger.getRbelMessagesList();
      assertEquals(4, messages.size(), "SDS und GetCards, je Request und Response");
      RbelElement request = messages.get(2);
      assertFalse(
          request
              .findRbelPathMembers("$.body.Envelope.Body.GetCards.Context.MandantId.text")
              .isEmpty(),
          request.printTreeStructure());
      assertEquals(
          "M1",
          request
              .findElement("$.body.Envelope.Body.GetCards.Context.MandantId.text")
              .orElseThrow()
              .getRawStringContent());
      assertTrue(
          request
              .findElement("$.header.SOAPAction")
              .orElseThrow()
              .getRawStringContent()
              .contains("EventService/v7.2#GetCards"));
      assertEquals(
          "OK",
          messages
              .get(3)
              .findElement("$.body.Envelope.Body.GetCardsResponse.Status.Result.text")
              .orElseThrow()
              .getRawStringContent());
    } finally {
      stub.stop(0);
    }
  }
}
