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
package de.gematik.liana.adapter.fake;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.terminal.NoCardException;
import de.gematik.liana.kern.terminal.PinCommand;
import de.gematik.liana.kern.terminal.PinDialog;
import de.gematik.liana.kern.terminal.SlotListener;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class FakeTerminalTest {

  static final HexFormat HEX = HexFormat.of().withUpperCase();

  /**
   * Card without kartos: ATR 3B00, answers everything with 9000; counts starts and stops and
   * records the commands.
   */
  static final class StubEngine implements CardEngine {
    final List<Path> opened = new ArrayList<>();
    final List<String> commands = new ArrayList<>();
    int closed;

    @Override
    public Card open(Path image) {
      opened.add(image);
      return new Card() {
        @Override
        public byte[] atr() {
          return HEX.parseHex("3B00");
        }

        @Override
        public byte[] transmit(byte[] commandApdu) {
          commands.add(HEX.formatHex(commandApdu));
          return HEX.parseHex("9000");
        }

        @Override
        public void close() {
          closed++;
        }
      };
    }
  }

  private final StubEngine engine = new StubEngine();
  private final FakeTerminal terminal = new FakeTerminal("KT-01", 2, engine);

  @Test
  @DisplayName(
      "signature-time: PSO COMPUTE DIGITAL SIGNATURE antwortet erst nach der Rechenzeit, andere Kommandos "
          + "sofort (Konnektor-QES KUC_1602_072, LIANA-112.05)")
  void signatureTime() throws Exception {
    terminal.signatureTime(Duration.ofMillis(200));
    terminal.insert(1, Path.of("hba.xml"));
    long start = System.nanoTime();
    terminal.transmit(1, HEX.parseHex("00A4040C06D27600006601"));
    assertTrue(System.nanoTime() - start < 150_000_000L, "SELECT ohne Rechenzeit");
    start = System.nanoTime();
    assertArrayEquals(
        HEX.parseHex("9000"),
        terminal.transmit(1, HEX.parseHex("002A9E9A20" + "00".repeat(32) + "00")));
    assertTrue(System.nanoTime() - start >= 200_000_000L, "PSO CDS mit Rechenzeit");
    assertThrows(
        IllegalArgumentException.class, () -> terminal.signatureTime(Duration.ofMillis(-1)));
  }

  @Test
  @DisplayName("Karte startet erst beim ersten Zugriff, reset startet sie neu")
  void lazyStartAndReset() throws Exception {
    terminal.insert(1, Path.of("egk.xml"));
    assertTrue(terminal.cardPresent(1));
    assertEquals(List.of(), engine.opened);
    assertArrayEquals(HEX.parseHex("9000"), terminal.transmit(1, HEX.parseHex("00A4040C")));
    assertArrayEquals(HEX.parseHex("3B00"), terminal.reset(1));
    assertEquals(2, engine.opened.size());
    assertEquals(1, engine.closed);
  }

  @Test
  @DisplayName("Ziehen beendet die Karte, danach ist der Slot leer")
  void eject() throws Exception {
    terminal.insert(2, Path.of("egk.xml"));
    terminal.reset(2);
    terminal.eject(2);
    assertEquals(1, engine.closed);
    assertFalse(terminal.cardPresent(2));
    NoCardException e =
        assertThrows(NoCardException.class, () -> terminal.transmit(2, HEX.parseHex("00A4040C")));
    assertEquals("KT-01/2: keine Karte gesteckt", e.getMessage());
  }

  @Test
  @DisplayName("Belegter Slot und Slot außerhalb von slots() werden abgewiesen")
  void invalidSlots() {
    terminal.insert(1, Path.of("egk.xml"));
    assertThrows(IllegalStateException.class, () -> terminal.insert(1, Path.of("other.xml")));
    assertThrows(IllegalArgumentException.class, () -> terminal.insert(3, Path.of("egk.xml")));
    assertThrows(IllegalArgumentException.class, () -> terminal.reset(0));
    assertThrows(NoCardException.class, () -> terminal.eject(2));
  }

  /** Records slot events as {@code IN_USE KT-01/1} or {@code FREE KT-01/1}. */
  static final class Recorder implements SlotListener {
    final List<String> events = new ArrayList<>();

    @Override
    public void slotInUse(String ctId, int slot) {
      events.add("IN_USE " + ctId + "/" + slot);
    }

    @Override
    public void slotFree(String ctId, int slot) {
      events.add("FREE " + ctId + "/" + slot);
    }
  }

  @Test
  @DisplayName(
      "TIP1-A_4563 / TIP1-A_4562: Stecken, Ziehen und close melden CT/SLOT_IN_USE und CT/SLOT_FREE")
  void slotEreignisse() {
    Recorder recorder = new Recorder();
    terminal.addSlotListener(recorder);
    terminal.insert(1, Path.of("egk.xml"));
    terminal.insert(2, Path.of("egk.xml"));
    terminal.eject(1);
    assertThrows(IllegalStateException.class, () -> terminal.insert(2, Path.of("other.xml")));
    terminal.close();
    assertEquals(
        List.of("IN_USE KT-01/1", "IN_USE KT-01/2", "FREE KT-01/1", "FREE KT-01/2"),
        recorder.events);
  }

  @Test
  @DisplayName(
      "LIANA-41 Störung status-word: nur Kommandos mit commandPrefix, count-mal, die Karte sieht sie nicht")
  void stoerungStatuswort() throws Exception {
    terminal.insert(1, Path.of("egk.xml"));
    terminal.fault(1, Fault.statusWord("6a82").onlyFor("00b0").times(2));
    assertArrayEquals(HEX.parseHex("9000"), terminal.transmit(1, HEX.parseHex("00A4040C")));
    assertArrayEquals(HEX.parseHex("6A82"), terminal.transmit(1, HEX.parseHex("00B0910000")));
    assertEquals(Optional.of(Fault.statusWord("6A82").onlyFor("00B0").times(1)), terminal.fault(1));
    assertArrayEquals(HEX.parseHex("6A82"), terminal.transmit(1, HEX.parseHex("00B0820000")));
    assertEquals(Optional.empty(), terminal.fault(1));
    assertArrayEquals(HEX.parseHex("9000"), terminal.transmit(1, HEX.parseHex("00B0820000")));
    assertArrayEquals(HEX.parseHex("3B00"), terminal.reset(1));
  }

  @Test
  @DisplayName(
      "LIANA-67 Störung response (CATS manipulateSignatureResponse): PSO CDS bekommt die ganze Ersatzantwort, "
          + "andere Kommandos und der Reset nicht")
  void stoerungResponse() throws Exception {
    terminal.insert(1, Path.of("egk.xml"));
    terminal.fault(1, Fault.response("5bf94e879000").onlyFor("002A9E9A"));
    assertArrayEquals(
        HEX.parseHex("5BF94E879000"), terminal.transmit(1, HEX.parseHex("002A9E9A2011")));
    assertArrayEquals(HEX.parseHex("9000"), terminal.transmit(1, HEX.parseHex("00A4040C")));
    assertArrayEquals(HEX.parseHex("3B00"), terminal.reset(1));
    assertThrows(IllegalArgumentException.class, () -> Fault.response("90"));
    assertThrows(
        IllegalArgumentException.class,
        () -> new Fault(Fault.Type.RESPONSE, "9000", null, null, null, null));
  }

  @Test
  @DisplayName(
      "LIANA-41 Störung io-error: Reset, APDU und PIN-Eingabe scheitern mit IOException, bis sie gelöscht ist")
  void stoerungIoFehler() throws Exception {
    terminal.insert(1, Path.of("egk.xml"));
    terminal.fault(1, Fault.ioError());
    assertThrows(IOException.class, () -> terminal.reset(1));
    assertThrows(IOException.class, () -> terminal.transmit(1, HEX.parseHex("00A4040C")));
    assertThrows(IOException.class, () -> terminal.verifyPin(1, 1, PinDialog.pinSmc(1)));
    terminal.insert(2, Path.of("egk.xml"));
    assertArrayEquals(HEX.parseHex("9000"), terminal.transmit(2, HEX.parseHex("00A4040C")));
    terminal.clearFault(1);
    assertArrayEquals(HEX.parseHex("9000"), terminal.transmit(1, HEX.parseHex("00A4040C")));
  }

  @Test
  @DisplayName(
      "LIANA-41 Störung delay: Antwort erst nach der Verzögerung, der andere Slot antwortet währenddessen; "
          + "Unterbrechen bricht ab, ohne die Karte zu starten")
  void stoerungVerzoegerung() throws Exception {
    terminal.insert(1, Path.of("egk.xml"));
    terminal.insert(2, Path.of("egk.xml"));
    terminal.fault(1, Fault.delay(Duration.ofMillis(300)).times(1));
    long start = System.nanoTime();
    CompletableFuture<byte[]> slow =
        CompletableFuture.supplyAsync(
            () -> {
              try {
                return terminal.transmit(1, HEX.parseHex("00A4040C"));
              } catch (IOException e) {
                throw new IllegalStateException(e);
              }
            });
    Thread.sleep(50);
    assertArrayEquals(HEX.parseHex("9000"), terminal.transmit(2, HEX.parseHex("00A4040C")));
    assertTrue(Duration.ofNanos(System.nanoTime() - start).toMillis() < 300);
    assertArrayEquals(HEX.parseHex("9000"), slow.get());
    assertTrue(Duration.ofNanos(System.nanoTime() - start).toMillis() >= 300);

    terminal.fault(1, Fault.delay(Duration.ofSeconds(10)));
    int opened = engine.opened.size();
    Thread.currentThread().interrupt();
    assertThrows(
        InterruptedIOException.class, () -> terminal.transmit(1, HEX.parseHex("00B0910000")));
    assertTrue(Thread.interrupted());
    assertEquals(opened, engine.opened.size());
  }

  @Test
  @DisplayName(
      "LIANA-50: eine APDU belegt nur ihre Karte – während die Karte in Slot 1 rechnet, antworten Slot 2 "
          + "und das Ziehen einer anderen Karte; die hängende APDU endet mit ihrer Antwort")
  void apduBelegtNurIhreKarte() throws Exception {
    CountDownLatch arrived = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    CardEngine slowEngine =
        image ->
            image.toString().equals("slow.xml")
                ? new Card() {
                  @Override
                  public byte[] atr() {
                    return HEX.parseHex("3B00");
                  }

                  @Override
                  public synchronized byte[] transmit(byte[] commandApdu) {
                    arrived.countDown();
                    try {
                      release.await();
                    } catch (InterruptedException e) {
                      Thread.currentThread().interrupt();
                    }
                    return HEX.parseHex("9000");
                  }

                  @Override
                  public void close() {}
                }
                : engine.open(image);
    FakeTerminal kt = new FakeTerminal("KT-01", 3, slowEngine);
    kt.insert(1, Path.of("slow.xml"));
    kt.insert(2, Path.of("egk.xml"));
    kt.insert(3, Path.of("egk.xml"));
    CompletableFuture<byte[]> slow =
        CompletableFuture.supplyAsync(
            () -> {
              try {
                return kt.transmit(1, HEX.parseHex("002A9E9A"));
              } catch (IOException e) {
                throw new IllegalStateException(e);
              }
            });
    try {
      assertTrue(arrived.await(5, TimeUnit.SECONDS));
      assertTimeoutPreemptively(
          Duration.ofSeconds(2),
          () -> {
            assertArrayEquals(HEX.parseHex("9000"), kt.transmit(2, HEX.parseHex("00A4040C")));
            assertArrayEquals(HEX.parseHex("3B00"), kt.reset(2));
            kt.eject(3);
          });
      assertFalse(slow.isDone());
    } finally {
      release.countDown();
    }
    assertArrayEquals(HEX.parseHex("9000"), slow.get(5, TimeUnit.SECONDS));
  }

  @Test
  @DisplayName("LIANA-41: close löscht alle Störungen; ungültige Störungen werden abgewiesen")
  void stoerungCloseUndPruefung() {
    terminal.fault(2, Fault.ioError());
    terminal.close();
    assertEquals(Optional.empty(), terminal.fault(2));
    assertThrows(IllegalArgumentException.class, () -> Fault.statusWord("9G00"));
    assertThrows(IllegalArgumentException.class, () -> Fault.statusWord("900"));
    assertThrows(IllegalArgumentException.class, () -> Fault.ioError().onlyFor("0"));
    assertThrows(IllegalArgumentException.class, () -> Fault.ioError().times(0));
    assertThrows(IllegalArgumentException.class, () -> Fault.delay(Duration.ZERO));
    assertThrows(
        IllegalArgumentException.class,
        () -> new Fault(Fault.Type.IO_ERROR, "6A82", null, null, null, null));
    assertThrows(IllegalArgumentException.class, () -> terminal.fault(3, Fault.ioError()));
  }

  @Test
  @DisplayName(
      "LIANA-110 TUC_KON_056: RequestCard zeigt die Aufforderung, bis eine Karte gesteckt ist (Admin-API, "
          + "Robot); steckt schon eine, ohne Anzeige; ohne Karte nach der Wartezeit false")
  void anfordern() throws Exception {
    CompletableFuture<Boolean> request =
        CompletableFuture.supplyAsync(
            () -> {
              try {
                return terminal.requestCard(1, "Bitte Karte stecken", Duration.ofSeconds(10));
              } catch (IOException e) {
                throw new java.io.UncheckedIOException(e);
              }
            });
    assertTimeoutPreemptively(
        Duration.ofSeconds(5),
        () -> {
          while (terminal.display().isEmpty()) {
            Thread.sleep(10);
          }
        });
    assertEquals(Optional.of("Bitte Karte stecken"), terminal.display());
    terminal.insert(1, Path.of("egk.xml"));
    assertTrue(request.get(5, TimeUnit.SECONDS));
    assertEquals(Optional.empty(), terminal.display());

    assertTrue(terminal.requestCard(1, "Bitte Karte stecken", Duration.ofMillis(1)));
    assertFalse(terminal.requestCard(2, "Bitte Karte stecken", Duration.ofMillis(50)));
    assertEquals(Optional.empty(), terminal.display());
  }

  @Test
  @DisplayName(
      "LIANA-110 TUC_KON_057: EjectCard deaktiviert die Karte und zeigt die Aufforderung, bis sie gezogen "
          + "ist; bleibt sie stecken, false nach der Wartezeit; ein leerer Slot ist sofort frei")
  void auswerfen() throws Exception {
    terminal.insert(1, Path.of("egk.xml"));
    terminal.reset(1);
    assertFalse(terminal.ejectCard(1, "Bitte entnehmen", Duration.ofMillis(50)));
    assertEquals(1, engine.closed, "Karte deaktiviert");
    assertTrue(terminal.cardPresent(1), "nicht entnommen");

    CompletableFuture<Boolean> eject =
        CompletableFuture.supplyAsync(
            () -> {
              try {
                return terminal.ejectCard(1, "Bitte entnehmen", Duration.ofSeconds(10));
              } catch (IOException e) {
                throw new java.io.UncheckedIOException(e);
              }
            });
    assertTimeoutPreemptively(
        Duration.ofSeconds(5),
        () -> {
          while (terminal.display().isEmpty()) {
            Thread.sleep(10);
          }
        });
    terminal.eject(1);
    assertTrue(eject.get(5, TimeUnit.SECONDS));
    assertTrue(terminal.ejectCard(2, "Bitte entnehmen", Duration.ofMillis(1)));
  }

  @Test
  @DisplayName(
      "LIANA-110: eine zweite Aufforderung, während das Display eine zeigt, scheitert mit DisplayBusyException")
  void displayBelegt() throws Exception {
    CompletableFuture<Boolean> first =
        CompletableFuture.supplyAsync(
            () -> {
              try {
                return terminal.requestCard(1, "erste", Duration.ofSeconds(10));
              } catch (IOException e) {
                throw new java.io.UncheckedIOException(e);
              }
            });
    assertTimeoutPreemptively(
        Duration.ofSeconds(5),
        () -> {
          while (terminal.display().isEmpty()) {
            Thread.sleep(10);
          }
        });
    assertThrows(
        de.gematik.liana.kern.terminal.DisplayBusyException.class,
        () -> terminal.requestCard(2, "zweite", Duration.ofSeconds(1)));
    terminal.insert(1, Path.of("egk.xml"));
    assertTrue(first.get(5, TimeUnit.SECONDS));
  }

  private String verify(int slot) throws IOException {
    return HEX.formatHex(terminal.verifyPin(slot, 1, PinDialog.pinSmc(slot)));
  }

  private CompletableFuture<String> verifyAsync(int slot) {
    return CompletableFuture.supplyAsync(
        () -> {
          try {
            return verify(slot);
          } catch (IOException e) {
            throw new java.io.UncheckedIOException(e);
          }
        });
  }

  private void awaitDisplay() {
    assertTimeoutPreemptively(
        Duration.ofSeconds(5),
        () -> {
          while (terminal.display().isEmpty()) {
            Thread.sleep(10);
          }
        });
  }

  @Test
  @DisplayName(
      "LIANA-68 PIN-Script wie kartos terminal: ohne Eintrag die konfigurierte PIN; correct, wrong (jede Ziffer "
          + "geändert), digits, puk und transport als VERIFY im Format-2-PIN-Block, cancel 6401 und timeout 6400 ohne "
          + "Kommando an die Karte; ein Eintrag für Slot 2 wartet auf den PIN-Dialog an Slot 2")
  void pinScript() throws Exception {
    terminal.insert(1, Path.of("smcb.xml"));
    terminal.insert(2, Path.of("hba.xml"));
    terminal.enterPin(
        List.of(
            new FakeTerminal.ScriptedPinInput(2, PinInput.of(PinInput.Outcome.CANCEL)),
            new FakeTerminal.ScriptedPinInput(null, PinInput.of(PinInput.Outcome.WRONG)),
            new FakeTerminal.ScriptedPinInput(1, new PinInput(PinInput.Outcome.DIGITS, "4711")),
            new FakeTerminal.ScriptedPinInput(null, PinInput.of(PinInput.Outcome.PUK)),
            new FakeTerminal.ScriptedPinInput(null, PinInput.of(PinInput.Outcome.TRANSPORT)),
            new FakeTerminal.ScriptedPinInput(null, PinInput.of(PinInput.Outcome.TIMEOUT))));
    assertEquals(6, terminal.pinScript().size());
    assertEquals("9000", verify(1));
    assertEquals("9000", verify(1));
    assertEquals("9000", verify(1));
    assertEquals("9000", verify(1));
    assertEquals("6400", verify(1));
    assertEquals("6401", verify(2), "der Eintrag für Slot 2 blieb stehen");
    assertEquals(List.of(), terminal.pinScript());
    assertEquals("9000", verify(1));
    assertEquals(
        List.of(
            "002000010826234567FFFFFFFF",
            "0020000108244711FFFFFFFFFF",
            "00200001082812345678FFFFFF",
            "00200001082554321FFFFFFFFF",
            "002000010826123456FFFFFFFF"),
        engine.commands);
  }

  @Test
  @DisplayName(
      "LIANA-68 Modus await (Robot): das PIN-Pad zeigt die Aufforderung und wartet auf die Eingabe; ohne "
          + "Eingabe 6400 nach dem PIN-Timeout (TIP1-A_3086), Karte gezogen 64A1")
  void pinAwait() throws Exception {
    terminal.insert(1, Path.of("smcb.xml"));
    terminal.awaitPinInput(true);
    CompletableFuture<String> verify = verifyAsync(1);
    awaitDisplay();
    assertEquals(Optional.of(PinDialog.pinSmc(1).prompt()), terminal.display());
    assertEquals(List.of(), engine.commands, "noch keine Eingabe");
    terminal.enterPin(null, PinInput.of(PinInput.Outcome.CORRECT));
    assertEquals("9000", verify.get(5, TimeUnit.SECONDS));
    assertEquals(Optional.empty(), terminal.display());

    terminal.pinTimeout(Duration.ofMillis(100));
    assertEquals("6400", verify(1));
    terminal.pinTimeout(Duration.ofSeconds(10));
    CompletableFuture<String> pulled = verifyAsync(1);
    awaitDisplay();
    terminal.eject(1);
    assertEquals("64A1", pulled.get(5, TimeUnit.SECONDS));
    assertEquals(List.of("002000010826123456FFFFFFFF"), engine.commands);
  }

  @Test
  @DisplayName(
      "LIANA-68 incomplete: Ziffern ohne Bestätigung, das KT wartet bis zum PIN-Timeout (6400) oder bis die Karte "
          + "gezogen ist (64A1), die Karte sieht kein Kommando; close verwirft das PIN-Script")
  void pinUnvollstaendig() throws Exception {
    terminal.insert(1, Path.of("smcb.xml"));
    terminal.pinTimeout(Duration.ofMillis(100));
    terminal.enterPin(null, PinInput.of(PinInput.Outcome.INCOMPLETE));
    assertEquals("6400", verify(1));
    terminal.pinTimeout(Duration.ofSeconds(10));
    terminal.enterPin(null, PinInput.of(PinInput.Outcome.INCOMPLETE));
    CompletableFuture<String> pulled = verifyAsync(1);
    awaitDisplay();
    terminal.eject(1);
    assertEquals("64A1", pulled.get(5, TimeUnit.SECONDS));
    assertEquals(List.of(), engine.commands);

    terminal.enterPin(null, PinInput.of(PinInput.Outcome.CANCEL));
    terminal.close();
    assertEquals(List.of(), terminal.pinScript());
  }

  @Test
  @DisplayName(
      "LIANA-68: ungültige PIN-Eingaben werden abgewiesen, ein Script mit unbekanntem Slot hängt nichts an")
  void pinUngueltig() {
    assertThrows(IllegalArgumentException.class, () -> new PinInput(PinInput.Outcome.DIGITS, null));
    assertThrows(
        IllegalArgumentException.class, () -> new PinInput(PinInput.Outcome.DIGITS, "12a4"));
    assertThrows(
        IllegalArgumentException.class, () -> new PinInput(PinInput.Outcome.WRONG, "1234"));
    assertThrows(IllegalArgumentException.class, () -> PinInput.Outcome.of("falsch"));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            terminal.enterPin(
                List.of(
                    new FakeTerminal.ScriptedPinInput(null, PinInput.of(PinInput.Outcome.CANCEL)),
                    new FakeTerminal.ScriptedPinInput(3, PinInput.of(PinInput.Outcome.CANCEL)))));
    assertEquals(List.of(), terminal.pinScript());
    assertEquals(
        "digits", new PinInput(PinInput.Outcome.DIGITS, "4711").toString(), "Ziffern nie im Log");
  }

  private static PinCommand change(PinCommand.Mode mode, String header) {
    return new PinCommand(
        HEX.parseHex(header),
        mode,
        mode == PinCommand.Mode.NEW ? List.of("neu", "nochmal") : List.of("alt", "neu", "nochmal"),
        PinCommand.CHANGED,
        PinDialog.WRONG,
        PinCommand.MISMATCH_TEXT);
  }

  @Test
  @DisplayName(
      "LIANA-109 MODIFY VERIFICATION DATA: alte PIN, neue PIN und Wiederholung je eine PIN-Eingabe, "
          + "CHANGE REFERENCE DATA mit zwei PIN-Blöcken; PUK und neue PIN ebenso; nur neue PIN mit einem Block")
  void pinAendern() throws Exception {
    terminal.insert(1, Path.of("smcb.xml"));
    terminal.enterPin(
        List.of(
            new FakeTerminal.ScriptedPinInput(null, PinInput.of(PinInput.Outcome.CORRECT)),
            new FakeTerminal.ScriptedPinInput(
                null, new PinInput(PinInput.Outcome.DIGITS, "654321")),
            new FakeTerminal.ScriptedPinInput(
                null, new PinInput(PinInput.Outcome.DIGITS, "654321")),
            new FakeTerminal.ScriptedPinInput(null, PinInput.of(PinInput.Outcome.PUK))));
    assertEquals(
        "9000", HEX.formatHex(terminal.pinCommand(1, change(PinCommand.Mode.OLD_NEW, "00240001"))));
    assertEquals(
        "9000", HEX.formatHex(terminal.pinCommand(1, change(PinCommand.Mode.OLD_NEW, "002C0001"))));
    assertEquals(
        "9000", HEX.formatHex(terminal.pinCommand(1, change(PinCommand.Mode.NEW, "0024010D"))));
    assertEquals(
        List.of(
            "002400011026123456FFFFFFFF26654321FFFFFFFF",
            "002C0001102812345678FFFFFF26123456FFFFFFFF",
            "0024010D0826123456FFFFFFFF"),
        engine.commands);
  }

  @Test
  @DisplayName(
      "LIANA-109: ungleiche Wiederholung der neuen PIN → PinMismatchException, Abbruch bei der zweiten "
          + "Eingabe → 6401; die Karte sieht in beiden Fällen kein Kommando")
  void pinAendernFehler() throws Exception {
    terminal.insert(1, Path.of("smcb.xml"));
    terminal.enterPin(
        List.of(
            new FakeTerminal.ScriptedPinInput(null, PinInput.of(PinInput.Outcome.CORRECT)),
            new FakeTerminal.ScriptedPinInput(
                null, new PinInput(PinInput.Outcome.DIGITS, "654321")),
            new FakeTerminal.ScriptedPinInput(
                null, new PinInput(PinInput.Outcome.DIGITS, "111111"))));
    assertThrows(
        de.gematik.liana.kern.terminal.PinMismatchException.class,
        () -> terminal.pinCommand(1, change(PinCommand.Mode.OLD_NEW, "00240001")));
    terminal.enterPin(
        List.of(
            new FakeTerminal.ScriptedPinInput(null, PinInput.of(PinInput.Outcome.CORRECT)),
            new FakeTerminal.ScriptedPinInput(null, PinInput.of(PinInput.Outcome.CANCEL))));
    assertEquals(
        "6401", HEX.formatHex(terminal.pinCommand(1, change(PinCommand.Mode.OLD_NEW, "00240001"))));
    assertEquals(List.of(), engine.commands);
    assertEquals(List.of(), terminal.pinScript());
  }
}
