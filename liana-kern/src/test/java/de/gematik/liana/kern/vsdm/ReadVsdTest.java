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
package de.gematik.liana.kern.vsdm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.access.Infomodel;
import de.gematik.liana.kern.card.AuthState;
import de.gematik.liana.kern.card.CardAccess;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.card.CardLocks;
import de.gematik.liana.kern.card.EgkFiles;
import de.gematik.liana.kern.card.PinVerification;
import de.gematik.liana.kern.card.RecordedCards;
import de.gematik.liana.kern.card.RecordedTerminal;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import de.gematik.liana.kern.event.SystemLog;
import de.gematik.liana.kern.terminal.TerminalRegistry;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * ReadVSD without Onlineprüfung ([gemSpec_FM_VSDM] 3.2.1) against the recorded egk-valid (Testhub
 * image EGK_80276883110000168584_gema5, slot 1) and smcb-valid (slot 2).
 */
class ReadVsdTest {

  private static final Context CTX = new Context("M1", "CS1", "WP1", null);
  private static final Path EGK_VALID_VSD =
      Path.of("liana-kern/src/test/resources/apdu/egk-valid-vsd.txt");
  private static final Path SMCB_VALID_PIN =
      Path.of("liana-kern/src/test/resources/apdu/smcb-valid-pin.txt");
  private static final String SELECT_DF_HCA = "00A4040C06D27600000102";

  private final RecordedCards kt01 = new RecordedCards("KT-01");
  private final TerminalRegistry registry = new TerminalRegistry(List.of(kt01));
  private final CardList cards = new CardList(registry, Clock.systemUTC());
  private final Infomodel infomodel =
      new Infomodel(
          List.of("M1"),
          List.of("CS1"),
          List.of(new Infomodel.Workplace("WP1", List.of("M1"), List.of("CS1"), List.of("KT-01"))));
  private final AuthState authState = new AuthState();
  private final CardLocks locks = new CardLocks();
  private final CardAccess access = new CardAccess(infomodel, cards, locks);

  /** Result of the offline check of C.CH.AUT that the port returns; {@code null} means valid. */
  private String autInvalid;

  private byte[] checkedAut;
  private final SystemLog systemLog = new SystemLog(Clock.systemUTC(), 100);

  /** Empty chain: only the spec fallback (default in the release image). */
  private final OnlineCheck onlineCheck =
      new OnlineCheck(
          List.of(), Duration.ofSeconds(30), () -> true, () -> false, systemLog, Clock.systemUTC());

  private final ReadVsd readVsd =
      new ReadVsd(
          access,
          locks,
          new EgkFiles(
              registry,
              der -> {
                checkedAut = der;
                return autInvalid;
              }),
          new PinVerification(access, registry, authState),
          onlineCheck);
  private String egk;
  private String smcb;

  @BeforeEach
  void stecken() {
    cards.start();
    kt01.insert(1, RecordedTerminal.EGK_VALID)
        .also(1, EGK_VALID_VSD)
        .insert(2, RecordedTerminal.SMCB_VALID)
        .also(2, SMCB_VALID_PIN);
    egk = cards.card("KT-01", 1).orElseThrow().cardHandle();
    smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();
    authState.verified(CTX, smcb, "PIN.SMC");
  }

  @Test
  @DisplayName(
      "VSDM-A_2567 / VSDM-A_2652 / VSDM-A_2784: PD, VD und Status-Container der eGK, gzip wie auf der "
          + "Karte; KVNR, Vor- und Nachname aus EF.PD, Kostenträgerkennung aus den VD zwischen den Offsets")
  void pdVdStatus() throws Exception {
    var result = readVsd.read(CTX, egk, smcb, false, false);

    String pd = gunzip(result.persoenlicheVersichertendaten());
    assertEquals("X110630769", element(pd, "Versicherten_ID"));
    assertEquals("Dörthe Abigail", element(pd, "Vorname"));
    assertEquals("Dåmmer-Ørsted", element(pd, "Nachname"));
    String vd = gunzip(result.allgemeineVersicherungsdaten());
    assertTrue(vd.contains("<UC_AllgemeineVersicherungsdatenXML"), vd);
    assertEquals("109500969", element(vd, "Kostentraegerkennung"));
    assertFalse(
        vd.contains("UC_GeschuetzteVersichertendatenXML"), "VSDM-A_2784: keine GVD aus EF.VD");
    // EF.StatusVD: '0', 20250407100158, Version_XML 0x0050020000 (Tab_FM_VSDM_21)
    assertEquals(new ReadVsd.Status("0", "2025-04-07T10:01:58", "5.2.0"), result.status());
  }

  @Test
  @DisplayName(
      "Tab_FM_VSDM_15 / TUC_KON_018: C.CH.AUT.E256 aus DF.ESIGN geht in die Offline-Prüfung; "
          + "die Reservierung der eGK ist danach aufgehoben")
  void sperrungUndReservierung() {
    readVsd.read(CTX, egk, smcb, false, false);

    assertEquals("3082", java.util.HexFormat.of().withUpperCase().formatHex(checkedAut, 0, 2));
    assertFalse(locks.locked(egk));
  }

  @Test
  @DisplayName(
      "VSDM-A_2568: DF.HCA gesperrt (SELECT → 6283) → 114, vor der Prüfung der SM-B; Reservierung "
          + "aufgehoben")
  void gesperrteGesundheitsanwendung() {
    kt01.answer(1, SELECT_DF_HCA, "6283");
    authState.notVerified(CTX, smcb, "PIN.SMC");
    autInvalid = "abgelaufen";

    assertError(ConnectorError.HCA_BLOCKED, () -> readVsd.read(CTX, egk, smcb, false, false));
    assertFalse(locks.locked(egk));
  }

  @Test
  @DisplayName("VSDM-A_2569 / A_23157: C.CH.AUT offline ungültig → 107")
  void autOfflineUngueltig() {
    autInvalid = "zeitlich nicht gültig";

    assertError(
        ConnectorError.EGK_CERT_OFFLINE_INVALID, () -> readVsd.read(CTX, egk, smcb, false, false));
  }

  @Test
  @DisplayName("Tab_FM_VSDM_15: PIN.SMC nicht verifiziert (GET PIN STATUS 63C3) → 3041")
  void smbNichtFreigeschaltet() {
    authState.notVerified(CTX, smcb, "PIN.SMC");

    assertError(ConnectorError.SMB_NOT_UNLOCKED, () -> readVsd.read(CTX, egk, smcb, false, false));
  }

  @Test
  @DisplayName("VSDM-A_2660: Status in EF.StatusVD ist „1“ → 3001")
  void inkonsistent() {
    kt01.answer(1, "00B08C00000000", "313230323530343037313030313538005002000000300000049000");

    assertError(ConnectorError.VSD_INCONSISTENT, () -> readVsd.read(CTX, egk, smcb, false, false));
  }

  @Test
  @DisplayName("VSDM-A_2571: EF.PD nicht lesbar → 3011")
  void technischerFehler() {
    kt01.answer(1, "00B08100000000", "6981");

    assertError(
        ConnectorError.VSD_PROCESSING_FAILED, () -> readVsd.read(CTX, egk, smcb, false, false));
  }

  @Test
  @DisplayName("TUC_KON_023: eGK von einer Kartensitzung reserviert → 4093")
  void reserviert() {
    CardLocks.Lock lock = locks.lock(egk);

    assertError(ConnectorError.CARD_LOCKED, () -> readVsd.read(CTX, egk, smcb, false, false));
    locks.unlock(lock);
  }

  @Test
  @DisplayName("TUC_KON_000: EhcHandle keine eGK oder HpcHandle keine SM-B → 4209")
  void kartentypen() {
    assertError(
        ConnectorError.CARD_TYPE_UNSUPPORTED, () -> readVsd.read(CTX, smcb, smcb, false, false));
    assertError(
        ConnectorError.CARD_TYPE_UNSUPPORTED, () -> readVsd.read(CTX, egk, egk, false, false));
  }

  @Test
  @DisplayName(
      "VSDM-A_2575 / VSDM-A_2578: PerformOnlineCheck und ReadOnlineReceipt, leere Kette → VSD von der Karte "
          + "und Prüfungsnachweis Ergebnis 3 ohne Prüfziffer")
  void onlinepruefungLeereKette() throws Exception {
    var result = readVsd.read(CTX, egk, smcb, true, true);

    assertEquals(
        "X110630769", element(gunzip(result.persoenlicheVersichertendaten()), "Versicherten_ID"));
    Pruefungsnachweis pn = result.pruefungsnachweis();
    assertEquals(Pruefungsnachweis.Ergebnis.AKTUALISIERUNG_TECHNISCH_NICHT_MOEGLICH, pn.ergebnis());
    assertNull(pn.pruefziffer());
    assertNull(pn.errorCode());
    OnlineCheck.Outcome outcome = onlineCheck.last().getFirst();
    assertEquals(OnlineCheck.FALLBACK, outcome.source());
    assertEquals(egk, outcome.cardHandle());
    assertFalse(locks.locked(egk));
  }

  @Test
  @DisplayName(
      "4.3.3: die Quelle bekommt ICCSN und KVNR der eGK, die SM-B des Aufrufs und die ProviderID aus "
          + "C.CH.AUT")
  void anfrageAnDieQuelle() {
    List<OnlineCheck.Request> requests = new java.util.ArrayList<>();
    OnlineCheck.Source recording =
        new OnlineCheck.Source() {
          @Override
          public String name() {
            return "recording";
          }

          @Override
          public Optional<OnlineCheck.Answer> ask(
              OnlineCheck.Request request, OnlineCheck.Notes notes) {
            requests.add(request);
            return Optional.of(new OnlineCheck.NoUpdate(null));
          }
        };
    var check =
        new OnlineCheck(
            List.of(recording),
            Duration.ofSeconds(30),
            () -> true,
            () -> false,
            systemLog,
            Clock.systemUTC());
    var result =
        new ReadVsd(
                access,
                locks,
                new EgkFiles(registry, der -> null),
                new PinVerification(access, registry, authState),
                check)
            .read(CTX, egk, smcb, true, true);

    assertEquals(
        Pruefungsnachweis.Ergebnis.KEINE_AKTUALISIERUNG_ERFORDERLICH,
        result.pruefungsnachweis().ergebnis());
    OnlineCheck.Request request = requests.getFirst();
    assertEquals("109500969", request.providerId());
    assertEquals("X110630769", request.kvnr());
    assertEquals(cards.card("KT-01", 1).orElseThrow().data().iccsn(), request.iccsn());
    assertEquals(smcb, request.smb().cardHandle());
  }

  @Test
  @DisplayName(
      "VSDM-A_2579: PerformOnlineCheck=true, ReadOnlineReceipt=false → geprüft, Prüfungsnachweis nicht in "
          + "der Antwort")
  void onlinepruefungOhneRueckgabe() {
    var result = readVsd.read(CTX, egk, smcb, true, false);

    assertNull(result.pruefungsnachweis());
    assertEquals(1, onlineCheck.last().size());
  }

  @Test
  @DisplayName(
      "VSDM-A_2577: ReadOnlineReceipt=true ohne Onlineprüfung (Prüfungsnachweis von der eGK) nicht "
          + "umgesetzt (LIANA-103), ohne Kartenzugriff; ungültiger Kontext geht vor (4021)")
  void pruefungsnachweisVonDerKarte() {
    kt01.sent.get(1).clear();

    var unsupported =
        assertThrows(ReadVsd.Unsupported.class, () -> readVsd.read(CTX, egk, smcb, false, true));
    assertTrue(unsupported.getMessage().contains("LIANA-103"), unsupported.getMessage());
    assertEquals(List.of(), kt01.sent.get(1));
    assertError(
        ConnectorError.CONTEXT_INCOMPLETE,
        () -> readVsd.read(new Context("M9", "CS1", "WP1", null), egk, smcb, false, true));
  }

  @Test
  @DisplayName("A_23020: eGK gesperrt → 114 ohne Onlineprüfung und ohne Prüfungsnachweis")
  void gesperrtOhneOnlinepruefung() {
    kt01.answer(1, SELECT_DF_HCA, "6283");

    assertError(ConnectorError.HCA_BLOCKED, () -> readVsd.read(CTX, egk, smcb, true, true));
    assertEquals(List.of(), onlineCheck.last());
  }

  private static void assertError(ConnectorError expected, Executable executable) {
    assertEquals(expected, assertThrows(ConnectorException.class, executable).error());
  }

  private static String gunzip(byte[] data) throws IOException {
    try (var in = new GZIPInputStream(new ByteArrayInputStream(data))) {
      return new String(in.readAllBytes(), Charset.forName("ISO-8859-15"));
    }
  }

  private static String element(String xml, String name) {
    Matcher m = Pattern.compile("<" + name + ">([^<]*)</" + name + ">").matcher(xml);
    assertTrue(m.find(), name + " fehlt in " + xml);
    return m.group(1);
  }
}
