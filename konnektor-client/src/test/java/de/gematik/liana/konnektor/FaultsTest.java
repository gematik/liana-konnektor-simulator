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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * LIANA-137: read error traces leniently, exceptions by ErrorType, decision-12 as "not supported".
 */
class FaultsTest {

  /** Error trace like LIANA's {@code soap/Gerror.xml}. */
  static final String LIANA_GERROR =
      "<GERROR:Error xmlns:GERROR=\"http://ws.gematik.de/tel/error/v2.0\">"
          + "<GERROR:MessageID>m-1</GERROR:MessageID><GERROR:Timestamp>2026-10-14T12:00:00Z</GERROR:Timestamp>"
          + "<GERROR:Trace><GERROR:EventID>e-1</GERROR:EventID><GERROR:Instance>Konnektor-Lokal</GERROR:Instance>"
          + "<GERROR:LogReference/><GERROR:CompType>Konnektor</GERROR:CompType><GERROR:Code>4021</GERROR:Code>"
          + "<GERROR:Severity>Error</GERROR:Severity><GERROR:ErrorType>Technical</GERROR:ErrorType>"
          + "<GERROR:ErrorText>Kein Clientsystem</GERROR:ErrorText></GERROR:Trace></GERROR:Error>";

  @Test
  @DisplayName("GERROR wie LIANA: MessageID, Code, ErrorType, ErrorText")
  void lianaGerror() {
    GematikError error = GematikError.parse(LIANA_GERROR).orElseThrow();
    assertEquals("m-1", error.messageId());
    assertEquals(Optional.of(4021), error.code());
    assertEquals(Optional.of("Technical"), error.errorType());
    assertEquals(Optional.of("Kein Clientsystem"), error.errorText());
    assertEquals("Konnektor", error.traces().get(0).compType());
  }

  @Test
  @DisplayName(
      "nachsichtig: anderes Präfix, fehlende Felder, Code nicht numerisch, mehrere Traces, kein Trace")
  void nachsichtig() {
    GematikError error =
        GematikError.parse(
                "<e:Error xmlns:e=\"urn:anders\"><e:Trace><e:Code>x</e:Code>"
                    + "</e:Trace><e:Trace><e:Code> 4004 </e:Code><e:ErrorType>Business</e:ErrorType></e:Trace>"
                    + "</e:Error>")
            .orElseThrow();
    assertEquals(Optional.of(4004), error.code());
    assertEquals(Optional.of("Business"), error.errorType());
    assertEquals(null, error.messageId());
    assertTrue(
        GematikError.parse("<ns:Error xmlns:ns=\"urn:x\"/>").orElseThrow().traces().isEmpty());
    assertEquals(Optional.empty(), GematikError.parse("<Andere/>"));
    assertEquals(Optional.empty(), GematikError.parse("kein xml <"));
  }

  @Test
  @DisplayName(
      "ErrorType → Technical, Security, Business, Infrastructure, sonst KonnektorFault; ohne GERROR "
          + "SoapFaultException")
  void typen() {
    Optional<QuirksTable.Gap> none = Optional.empty();
    assertInstanceOf(
        KonnektorFault.Technical.class,
        SoapFaultException.of(Operation.GET_CARDS, "SOAP-ENV:Server", "x", LIANA_GERROR, none));
    for (String type : new String[] {"Security", "Business", "Infrastructure", "Other"}) {
      SoapFaultException e =
          SoapFaultException.of(
              Operation.GET_CARDS,
              "SOAP-ENV:Server",
              "x",
              LIANA_GERROR.replace("Technical", type),
              none);
      assertInstanceOf(KonnektorFault.class, e);
      assertEquals(
          type.equals("Other") ? KonnektorFault.class.getSimpleName() : type,
          e.getClass().getSimpleName());
      assertEquals(Optional.of(4021), e.code());
    }
    SoapFaultException plain =
        SoapFaultException.of(Operation.GET_CARDS, "SOAP-ENV:Client", "x", "", none);
    assertEquals(SoapFaultException.class, plain.getClass());
    assertEquals(
        "GetCards: SOAP-Fault SOAP-ENV:Server x (4021 Technical)",
        SoapFaultException.of(Operation.GET_CARDS, "SOAP-ENV:Server", "x", LIANA_GERROR, none)
            .getMessage());
  }

  @Test
  @DisplayName(
      "LIANA-136/137: decision-12-Fault (ohne GERROR) bei bekannter Lücke → ProductUnsupportedException")
  void nichtUnterstuetzt() throws Exception {
    KonnektorTest.FakeTransport transport = new KonnektorTest.FakeTransport();
    transport.status = 500;
    transport.soap =
        "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\"><SOAP-ENV:Body>"
            + "<SOAP-ENV:Fault><faultcode>SOAP-ENV:Client</faultcode><faultstring>SignatureService: Operation "
            + "SignDocument wird von LIANA nur bis zur Zugriffsprüfung (TUC_KON_000) unterstützt, die Fachlogik ist "
            + "nicht umgesetzt</faultstring></SOAP-ENV:Fault></SOAP-ENV:Body></SOAP-ENV:Envelope>";
    try (Konnektor kon =
        Konnektor.builder()
            .url("https://kon")
            .context("M1", "CS1", "WP1", null)
            .transport(transport)
            .build()) {
      ProductUnsupportedException e =
          assertThrows(
              ProductUnsupportedException.class,
              () ->
                  kon.invoke(
                      Operation.SIGN_DOCUMENT,
                      new de.gematik.liana.konnektor.ws.conn.signatureservice.v7_5.SignDocument(),
                      Object.class));
      assertTrue(e.gap().accessCheckOnly());
      assertTrue(e.gap().source().contains("decision-12"));
    }
  }

  @Test
  @DisplayName(
      "LIANA-137: PIN-Hook vor VerifyPin mit CardHandle und PinTyp, nicht vor GetCards; KSP ohne Hook "
          + "scheitert beim Verbinden")
  void pinHook() throws Exception {
    java.util.List<PinPromptHandler.PinPrompt> prompts = new java.util.ArrayList<>();
    try (Konnektor kon =
        Konnektor.builder()
            .url("https://kon")
            .context("M1", "CS1", "WP1", null)
            .onPinPrompt(prompts::add)
            .transport(new KonnektorTest.FakeTransport())
            .build()) {
      kon.cards().list();
      assertThrows(KonnektorException.class, () -> kon.card("SMC-B-1").pin("PIN.SMC").verify());
    }
    assertEquals(
        java.util.List.of(
            new PinPromptHandler.PinPrompt(Operation.VERIFY_PIN, "SMC-B-1", "PIN.SMC")),
        prompts);
    IllegalStateException e =
        assertThrows(
            IllegalStateException.class,
            () ->
                Konnektor.builder()
                    .url("https://kon")
                    .context("M1", "CS1", "WP1", null)
                    .deployment(Deployment.KSP)
                    .transport(new KonnektorTest.FakeTransport())
                    .build());
    assertEquals(
        "Deployment KSP: PIN-Eingaben brauchen einen Hook, Builder.onPinPrompt(…) fehlt (LIANA-137)",
        e.getMessage());
    try (Konnektor kon =
        Konnektor.builder()
            .url("https://kon")
            .context("M1", "CS1", "WP1", null)
            .onPinPrompt(
                p -> {
                  throw new IllegalStateException("Roboter nicht bereit");
                })
            .transport(new KonnektorTest.FakeTransport())
            .build()) {
      KonnektorException abort =
          assertThrows(KonnektorException.class, () -> kon.card("SMC-B-1").pin("PIN.SMC").verify());
      assertEquals("VerifyPin: PIN-Hook abgebrochen: Roboter nicht bereit", abort.getMessage());
    }
  }
}
