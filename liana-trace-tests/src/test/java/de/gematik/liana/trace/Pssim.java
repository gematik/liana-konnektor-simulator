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

import de.gematik.rbellogger.RbelLogger;
import de.gematik.rbellogger.data.RbelElement;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The PSSIM steps of Konnektor-QES (tiger-pssim-extension 2.11.0) as SOAP requests in the form of
 * konnektor-service-client 1.6.2 (Spring-WS, JAXB: prefixes ns2 ConnectorCommon, ns4 service, ns9
 * ConnectorContext), with the default context M1/CS1/WP1/bert from the default YAML.
 */
final class Pssim {

  static final String EVT = "http://ws.gematik.de/conn/EventService/v7.2";
  static final String CARD = "http://ws.gematik.de/conn/CardService/v8.2";
  static final String CARDCMN = "http://ws.gematik.de/conn/CardServiceCommon/v2.0";
  static final String SIG = "http://ws.gematik.de/conn/SignatureService/v7.5";
  static final String CRYPT = "http://ws.gematik.de/conn/EncryptionService/v6.1";
  static final String CONTEXT = context("M1", "CS1", "WP1", "bert");

  /**
   * Response of the Konnektor; {@link #rbel()} parses the body like Tiger, for the suite's RbelPath
   * checks.
   */
  record Answer(int status, String body) {
    RbelElement rbel() {
      return RbelLogger.build()
          .getRbelConverter()
          .convertElement(body.getBytes(StandardCharsets.UTF_8), null);
    }

    /** Text at the RbelPath, as the TGR steps read it. */
    String text(String rbelPath) {
      RbelElement element = rbel();
      return element
          .findElement(rbelPath)
          .map(RbelElement::getRawStringContent)
          .orElseThrow(
              () -> new AssertionError(rbelPath + " fehlt in\n" + element.printTreeStructure()));
    }
  }

  private final LianaProcess liana;

  Pssim(LianaProcess liana) {
    this.liana = liana;
  }

  /**
   * {@code CCTX:Context}; {@code userId} {@code ""} becomes an empty element, as with JAXB and an
   * empty string.
   */
  static String context(String mandant, String clientSystem, String workplace, String userId) {
    return """
                <ns9:Context><ns2:MandantId>%s</ns2:MandantId><ns2:ClientSystemId>%s</ns2:ClientSystemId>\
                <ns2:WorkplaceId>%s</ns2:WorkplaceId><ns2:UserId>%s</ns2:UserId></ns9:Context>"""
        .formatted(mandant, clientSystem, workplace, userId);
  }

  /** SOAP envelope with the operation {@code name} in the namespace {@code namespace}. */
  static String envelope(String namespace, String name, String attributes, String inner) {
    return """
                <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/>\
                <SOAP-ENV:Body><ns4:%s%s xmlns:ns2="http://ws.gematik.de/conn/ConnectorCommon/v5.0" \
                xmlns:ns3="urn:oasis:names:tc:dss:1.0:core:schema" xmlns:ns4="%s" xmlns:ns5="%s" \
                xmlns:ns9="http://ws.gematik.de/conn/ConnectorContext/v2.0">%s</ns4:%s></SOAP-ENV:Body>\
                </SOAP-ENV:Envelope>"""
        .formatted(name, attributes, namespace, CARDCMN, inner, name);
  }

  Answer soap(String service, String namespace, String operation, String body) throws Exception {
    return send(
        service,
        namespace,
        operation,
        "text/xml; charset=utf-8",
        body.getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Like {@link #soap}, as an MTOM message the way Spring-WS with SAAJ sends it with {@code
   * pssim.enableMtom}: {@code multipart/related} without {@code start}, root part first, {@code
   * attachment} as second part with the Content-ID that {@code root} points to via {@code
   * xop:Include}.
   */
  Answer mtom(
      String service,
      String namespace,
      String operation,
      String root,
      String contentId,
      byte[] attachment)
      throws Exception {
    String boundary = "----=_Part_0_" + UUID.randomUUID();
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    body.writeBytes(
        ("--"
                + boundary
                + "\r\nContent-Type: application/xop+xml; charset=utf-8; type=\"text/xml\"\r\n"
                + "Content-Transfer-Encoding: binary\r\n\r\n"
                + root
                + "\r\n--"
                + boundary
                + "\r\n"
                + "Content-Type: application/octet-stream\r\nContent-ID: <"
                + contentId
                + ">\r\n"
                + "Content-Transfer-Encoding: binary\r\n\r\n")
            .getBytes(StandardCharsets.UTF_8));
    body.writeBytes(attachment);
    body.writeBytes(("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));
    return send(
        service,
        namespace,
        operation,
        "Multipart/Related; start-info=\"text/xml\"; "
            + "type=\"application/xop+xml\"; boundary=\""
            + boundary
            + "\"",
        body.toByteArray());
  }

  private Answer send(
      String service, String namespace, String operation, String contentType, byte[] body)
      throws Exception {
    HttpResponse<String> response =
        HttpClient.newHttpClient()
            .send(
                HttpRequest.newBuilder(URI.create(liana.baseUrl() + "/ws/" + service))
                    .header("Content-Type", contentType)
                    .header("SOAPAction", "\"" + namespace + "#" + operation + "\"")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                    .build(),
                HttpResponse.BodyHandlers.ofString());
    return new Answer(response.statusCode(), response.body());
  }

  private String ok(String service, String namespace, String operation, String body)
      throws Exception {
    Answer answer = soap(service, namespace, operation, body);
    assertEquals(200, answer.status(), answer.body());
    return answer.body();
  }

  /** EventTo of all subscriptions of the client (Mandant) (GetSubscription with mandant-wide). */
  Set<String> eventTos() throws Exception {
    return all(
        ok(
            "EventService",
            EVT,
            "GetSubscription",
            envelope(EVT, "GetSubscription", " mandant-wide=\"true\"", CONTEXT)),
        "EventTo");
  }

  void unsubscribe(String eventTo) throws Exception {
    ok(
        "EventService",
        EVT,
        "Unsubscribe",
        envelope(EVT, "Unsubscribe", "", CONTEXT + "<ns4:EventTo>" + eventTo + "</ns4:EventTo>"));
  }

  /**
   * „PSSIM löscht alle Abonnements für die Events des Aufrufkontexts“: GetSubscription, Unsubscribe
   * per EventTo.
   */
  void deleteSubscriptions() throws Exception {
    for (String eventTo : eventTos()) {
      unsubscribe(eventTo);
    }
  }

  /** „PSSIM abonniert Event …“; returns the SubscriptionID. */
  String subscribe(String eventTo, String topic) throws Exception {
    return all(
            ok(
                "EventService",
                EVT,
                "Subscribe",
                envelope(
                    EVT,
                    "Subscribe",
                    "",
                    CONTEXT
                        + "<ns4:Subscription><ns4:EventTo>"
                        + eventTo
                        + "</ns4:EventTo><ns4:Topic>"
                        + topic
                        + "</ns4:Topic></ns4:Subscription>")),
            "SubscriptionID")
        .iterator()
        .next();
  }

  /** „PSSIM ermittelt das Card-Handle für den Kartentyp …“, restricted to KT and slot. */
  String cardHandle(String cardType, String ctId, int slot) throws Exception {
    Set<String> handles =
        all(
            ok(
                "EventService",
                EVT,
                "GetCards",
                envelope(
                    EVT,
                    "GetCards",
                    "",
                    CONTEXT
                        + "<ns5:CtId>"
                        + ctId
                        + "</ns5:CtId><ns5:SlotId>"
                        + slot
                        + "</ns5:SlotId><ns5:CardType>"
                        + cardType
                        + "</ns5:CardType>")),
            "CardHandle");
    assertEquals(
        1, handles.size(), "eine Karte " + cardType + " in " + ctId + "/" + slot + ": " + handles);
    return handles.iterator().next();
  }

  /**
   * „PSSIM verifiziert PIN für Kartentyp …“: VerifyPin with PIN.SMC (SMC-B) or PIN.CH (HBA),
   * PinResult OK.
   */
  void verifyPin(String cardHandle, String pinTyp) throws Exception {
    String response =
        ok(
            "CardService",
            CARD,
            "VerifyPin",
            envelope(
                CARD,
                "VerifyPin",
                "",
                CONTEXT
                    + "<ns2:CardHandle>"
                    + cardHandle
                    + "</ns2:CardHandle><ns5:PinTyp>"
                    + pinTyp
                    + "</ns5:PinTyp>"));
    assertEquals(Set.of("OK"), all(response, "PinResult"), response);
  }

  /** „PSSIM ermittelt eine Job-Number für einen Signaturauftrag“. */
  String jobNumber() throws Exception {
    return all(
            ok("SignatureService", SIG, "GetJobNumber", envelope(SIG, "GetJobNumber", "", CONTEXT)),
            "JobNumber")
        .iterator()
        .next();
  }

  /** Texts of all elements {@code name} (local name, any prefix). */
  static Set<String> all(String xml, String name) {
    Matcher m =
        Pattern.compile("<(?:\\w+:)?" + name + ">([^<]*)</(?:\\w+:)?" + name + ">").matcher(xml);
    Set<String> values = new LinkedHashSet<>();
    while (m.find()) {
      values.add(m.group(1));
    }
    return values;
  }
}
