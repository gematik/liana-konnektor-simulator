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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.card.CardData;
import de.gematik.liana.kern.card.CardObject;
import de.gematik.liana.kern.card.CardType;
import de.gematik.liana.kern.event.SystemLog;
import de.gematik.liana.kern.vsdm.Pruefungsnachweis.Ergebnis;
import java.io.IOException;
import java.net.ConnectException;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The chain of the Onlineprüfung (LIANA-141) with a stub UFS behind the port {@link
 * UpdateFlagService}.
 */
class OnlineCheckTest {

  private static final Context CTX = new Context("M1", "CS1", "WP1", null);
  private static final String ICCSN = "80276883110000168584";
  private static final String KVNR = "X110630769";
  private static final String PROVIDER = "109500969";
  private static final URI UFS_A = URI.create("http://ufs-a:8080/ufs");
  private static final URI UFS_B = URI.create("http://ufs-b:8080/ufs");
  private static final byte[] RECEIPT = Base64.getDecoder().decode("UHLDvGZ6aWZmZXIgZGVzIFVGUw==");

  private final ManualClock clock = new ManualClock();
  private final SystemLog log = new SystemLog(clock, 100);
  private final CardObject egk =
      new CardObject(
          "EGK-1",
          "KT-01",
          1,
          Instant.EPOCH,
          new CardData(CardType.EGK, ICCSN, null, "Dörthe", KVNR, null));
  private final CardObject smb =
      new CardObject(
          "SMB-1",
          "KT-01",
          2,
          Instant.EPOCH,
          new CardData(CardType.SMC_B, "80276883110000117894", null, "Praxis", null, null));
  private boolean strict;
  private boolean online = true;

  /** Stub UFS: one response or exception per URL; records the calls. */
  private final class StubUfs implements UpdateFlagService {

    final List<String> calls = new ArrayList<>();
    final java.util.Map<URI, Object> answers = new java.util.HashMap<>();
    Duration delay = Duration.ZERO;

    @Override
    public Answer getUpdateFlags(
        URI url,
        String iccsn,
        String providerId,
        Context context,
        CardObject card,
        Duration connectTimeout,
        Duration readTimeout)
        throws IOException {
      calls.add(
          url
              + " "
              + iccsn
              + " "
              + providerId
              + " "
              + card.cardHandle()
              + " "
              + readTimeout.toSeconds());
      clock.advance(delay);
      Object answer = answers.get(url);
      if (answer instanceof IOException e) {
        throw e;
      }
      return (Answer) answer;
    }
  }

  private final StubUfs ufs = new StubUfs();

  private UfsSource ufsSource(UfsSource.Endpoint... endpoints) {
    return new UfsSource(
        List.of(endpoints),
        ufs,
        Duration.ofSeconds(2),
        Duration.ofSeconds(10),
        Duration.ofSeconds(60),
        clock);
  }

  private OnlineCheck chain(OnlineCheck.Source... sources) {
    return new OnlineCheck(
        List.of(sources), Duration.ofSeconds(30), () -> online, () -> strict, log, clock);
  }

  private static UpdateFlagService.Flags noUpdate() {
    return new UpdateFlagService.Flags(List.of(), RECEIPT);
  }

  @Test
  @DisplayName(
      "Tab_FM_VSDM_05-01 / VSDM-A_2578: leere Kette → Ergebnis 3 ohne Prüfziffer, Stufe spec")
  void leereKette() {
    OnlineCheck.Outcome outcome = chain().check(CTX, egk, smb, PROVIDER);

    assertEquals(
        Ergebnis.AKTUALISIERUNG_TECHNISCH_NICHT_MOEGLICH, outcome.pruefungsnachweis().ergebnis());
    assertNull(outcome.pruefungsnachweis().pruefziffer());
    assertEquals(OnlineCheck.FALLBACK, outcome.source());
  }

  @Test
  @DisplayName(
      "Tab_FM_VSDM_04: UFS ohne Aktualisierungsauftrag → Ergebnis 2 mit der Prüfziffer des UFS "
          + "unverändert; GetUpdateFlags mit ICCSN, ProviderID, SM-B und TIMEOUT_VSDM")
  void ufsKeineAktualisierung() {
    ufs.answers.put(UFS_A, noUpdate());

    OnlineCheck.Outcome outcome =
        chain(ufsSource(new UfsSource.Endpoint(UFS_A, null))).check(CTX, egk, smb, PROVIDER);

    assertEquals(
        Ergebnis.KEINE_AKTUALISIERUNG_ERFORDERLICH, outcome.pruefungsnachweis().ergebnis());
    assertArrayEquals(RECEIPT, outcome.pruefungsnachweis().pruefziffer());
    assertEquals(clock.instant(), outcome.pruefungsnachweis().timestamp());
    assertEquals(UfsSource.CONFIG_NAME, outcome.source());
    assertEquals(List.of(UFS_A + " " + ICCSN + " " + PROVIDER + " SMB-1 10"), ufs.calls);
  }

  @Test
  @DisplayName(
      "VSDM-A_2597: UFS meldet einen Aktualisierungsauftrag (MANDATORY), kein CCS → Ergebnis 3, keine "
          + "weitere Stufe; nur OPTIONAL → Ergebnis 2")
  void ausstehendesUpdate() {
    var vsd = new UpdateFlagService.UpdateFlag("VSD", "GEMTK", "0A0B", true);
    ufs.answers.put(UFS_A, new UpdateFlagService.Flags(List.of(vsd), null));
    OnlineCheck check = chain(ufsSource(new UfsSource.Endpoint(UFS_A, null)), new FixedSource());

    OnlineCheck.Outcome outcome = check.check(CTX, egk, smb, PROVIDER);

    assertEquals(
        Ergebnis.AKTUALISIERUNG_TECHNISCH_NICHT_MOEGLICH, outcome.pruefungsnachweis().ergebnis());
    assertNull(outcome.pruefungsnachweis().pruefziffer());
    assertEquals(UfsSource.CONFIG_NAME, outcome.source());
    assertTrue(
        outcome.detail().contains("VSD") && outcome.detail().contains("LIANA-102"),
        outcome.detail());

    ufs.answers.put(
        UFS_A,
        new UpdateFlagService.Flags(
            List.of(new UpdateFlagService.UpdateFlag("VSD", "GEMTK", "0A0C", false)), RECEIPT));
    assertEquals(
        Ergebnis.KEINE_AKTUALISIERUNG_ERFORDERLICH,
        check.check(CTX, egk, smb, PROVIDER).pruefungsnachweis().ergebnis());
  }

  @Test
  @DisplayName(
      "Tab_FM_VSDM_04: Fault des UFS mit gematik-Fehlercode → Ergebnis 3, ErrorCode übernommen")
  void faultMitFehlercode() {
    ufs.answers.put(UFS_A, new UpdateFlagService.Fault(12105, "Karte unbekannt"));

    OnlineCheck.Outcome outcome =
        chain(ufsSource(new UfsSource.Endpoint(UFS_A, null)), new FixedSource())
            .check(CTX, egk, smb, PROVIDER);

    assertEquals(
        Ergebnis.AKTUALISIERUNG_TECHNISCH_NICHT_MOEGLICH, outcome.pruefungsnachweis().ergebnis());
    assertEquals(12105, outcome.pruefungsnachweis().errorCode());
    assertEquals(UfsSource.CONFIG_NAME, outcome.source());
  }

  @Test
  @DisplayName(
      "4.3.3: Endpunkte je ProviderID in Reihenfolge, ohne ProviderID für alle; nicht erreichbar → "
          + "nächster Endpunkt")
  void endpunkteJeProvider() {
    ufs.answers.put(UFS_A, new ConnectException("Connection refused"));
    ufs.answers.put(UFS_B, noUpdate());
    UfsSource source =
        ufsSource(
            new UfsSource.Endpoint(URI.create("http://andere:1/ufs"), "101575519"),
            new UfsSource.Endpoint(UFS_A, PROVIDER),
            new UfsSource.Endpoint(UFS_B, null));

    OnlineCheck.Outcome outcome = chain(source).check(CTX, egk, smb, PROVIDER);

    assertEquals(
        Ergebnis.KEINE_AKTUALISIERUNG_ERFORDERLICH, outcome.pruefungsnachweis().ergebnis());
    assertEquals(2, ufs.calls.size(), ufs.calls.toString());
    assertTrue(ufs.calls.get(0).startsWith(UFS_A.toString()), ufs.calls.toString());
    assertEquals(
        List.of("ufs: " + UFS_A + " nicht erreichbar: Connection refused"), outcome.skipped());
  }

  @Test
  @DisplayName(
      "LIANA-141: UFS nicht erreichbar → nächste Stufe (fixed); innerhalb retry-after übersprungen, "
          + "danach wieder gefragt")
  void nichtErreichbarNaechsteStufe() {
    ufs.answers.put(UFS_A, new ConnectException("Connection refused"));
    OnlineCheck check = chain(ufsSource(new UfsSource.Endpoint(UFS_A, null)), new FixedSource());

    OnlineCheck.Outcome first = check.check(CTX, egk, smb, PROVIDER);
    clock.advance(Duration.ofSeconds(30));
    OnlineCheck.Outcome second = check.check(CTX, egk, smb, PROVIDER);
    clock.advance(Duration.ofSeconds(31));
    check.check(CTX, egk, smb, PROVIDER);

    assertEquals(FixedSource.CONFIG_NAME, first.source());
    assertEquals(FixedSource.CONFIG_NAME, second.source());
    assertTrue(
        second.skipped().getFirst().contains("übersprungen bis"), second.skipped().toString());
    assertEquals(2, ufs.calls.size(), "zweiter Aufruf übersprungen, dritter wieder gefragt");
  }

  @Test
  @DisplayName(
      "VSDM-A_2998: UFS braucht länger als MAXTIME_VSDM → Abbruch, Ergebnis 3, keine weitere Stufe, "
          + "Warning im Systemprotokoll")
  void maxtime() {
    ufs.delay = Duration.ofSeconds(31);
    ufs.answers.put(UFS_A, new java.net.SocketTimeoutException("Read timed out"));

    OnlineCheck.Outcome outcome =
        chain(ufsSource(new UfsSource.Endpoint(UFS_A, null)), new FixedSource())
            .check(CTX, egk, smb, PROVIDER);

    assertEquals(
        Ergebnis.AKTUALISIERUNG_TECHNISCH_NICHT_MOEGLICH, outcome.pruefungsnachweis().ergebnis());
    assertEquals(OnlineCheck.FALLBACK, outcome.source());
    assertTrue(outcome.skipped().get(1).contains("MAXTIME_VSDM"), outcome.skipped().toString());
    SystemLog.Entry entry = log.entries(Instant.EPOCH, clock.instant()).getLast();
    assertEquals(SystemLog.Severity.WARN, entry.severity());
  }

  @Test
  @DisplayName(
      "LIANA-141: Stufe fixed → Ergebnis 2, Prüfziffer im Format des Testhub-Mocks (SHA-512 über die KVNR, "
          + "48 Byte), Timestamp aktuell")
  void fixed() {
    OnlineCheck.Outcome outcome = chain(new FixedSource()).check(CTX, egk, smb, PROVIDER);

    Pruefungsnachweis pn = outcome.pruefungsnachweis();
    assertEquals(Ergebnis.KEINE_AKTUALISIERUNG_ERFORDERLICH, pn.ergebnis());
    // vsdm-server-simservice ChecksumService.calculateChecksum("X110630769")
    assertEquals(
        "LxZ54CsBMSQaFMP04r_v_SGEItJtsElbiHZ9ES4eCMlCR-CfHOCgJJbjXcQV84tY",
        Base64.getUrlEncoder().encodeToString(pn.pruefziffer()));
    assertEquals(clock.instant(), pn.timestamp());
    assertEquals(FixedSource.CONFIG_NAME, outcome.source());
  }

  @Test
  @DisplayName(
      "LIANA-126 strict: kein Durchfallen zu fixed, Ergebnis 3 wie die Spec es vorschreibt")
  void strictOhneFixed() {
    strict = true;
    ufs.answers.put(UFS_A, new ConnectException("Connection refused"));

    OnlineCheck.Outcome outcome =
        chain(ufsSource(new UfsSource.Endpoint(UFS_A, null)), new FixedSource())
            .check(CTX, egk, smb, PROVIDER);

    assertEquals(
        Ergebnis.AKTUALISIERUNG_TECHNISCH_NICHT_MOEGLICH, outcome.pruefungsnachweis().ergebnis());
    assertEquals(OnlineCheck.FALLBACK, outcome.source());
    assertEquals("fixed: abgeschaltet (strict)", outcome.skipped().getLast());
  }

  @Test
  @DisplayName("TAB_KON_658: MGM_LU_ONLINE Disabled → keine Quelle gefragt, Ergebnis 3")
  void offline() {
    online = false;

    OnlineCheck.Outcome outcome =
        chain(ufsSource(new UfsSource.Endpoint(UFS_A, null)), new FixedSource())
            .check(CTX, egk, smb, PROVIDER);

    assertEquals(
        Ergebnis.AKTUALISIERUNG_TECHNISCH_NICHT_MOEGLICH, outcome.pruefungsnachweis().ergebnis());
    assertEquals(List.of(), ufs.calls);
  }

  @Test
  @DisplayName(
      "LIANA-141: antwortende Stufe und übersprungene im Systemprotokoll (ohne ICCSN und KVNR) und als "
          + "letztes Ergebnis je eGK")
  void nachvollziehbarkeit() {
    ufs.answers.put(UFS_A, new ConnectException("Connection refused"));
    OnlineCheck check = chain(ufsSource(new UfsSource.Endpoint(UFS_A, null)), new FixedSource());

    check.check(CTX, egk, smb, PROVIDER);
    check.check(CTX, egk, smb, PROVIDER);

    SystemLog.Entry entry = log.entries(Instant.EPOCH, clock.instant()).getLast();
    assertEquals(OnlineCheck.TOPIC, entry.topic());
    assertEquals(SystemLog.Severity.INFO, entry.severity());
    assertEquals("fixed", entry.parameters().get("Source"));
    assertEquals("2", entry.parameters().get("Ergebnis"));
    assertTrue(
        entry.parameters().get("Skipped").contains(UFS_A.toString()),
        entry.parameters().toString());
    assertTrue(
        entry.parameters().values().stream().noneMatch(v -> v.contains(ICCSN) || v.contains(KVNR)),
        entry.parameters().toString());
    assertEquals(1, check.last().size());
    assertEquals(ICCSN, check.last().getFirst().iccsn());
    check.clear();
    assertEquals(List.of(), check.last());
  }

  static final class ManualClock extends Clock {

    private Instant now = Instant.parse("2026-10-17T10:00:00Z");

    void advance(Duration duration) {
      now = now.plus(duration);
    }

    @Override
    public Instant instant() {
      return now;
    }

    @Override
    public java.time.ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(java.time.ZoneId zone) {
      return this;
    }
  }
}
