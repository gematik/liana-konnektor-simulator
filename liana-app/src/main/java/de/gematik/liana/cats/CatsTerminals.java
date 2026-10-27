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
package de.gematik.liana.cats;

import de.gematik.liana.adapter.fake.CardImage;
import de.gematik.liana.adapter.fake.FakeTerminal;
import de.gematik.liana.adapter.fake.FakeTerminals;
import de.gematik.liana.adapter.fake.Fault;
import de.gematik.liana.adapter.sicct.SicctTerminals;
import jakarta.inject.Singleton;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

/**
 * Content of the CATS REST interface (LIANA-67), independent of the HTTP transport in {@link
 * CatsServer}: a CATS terminal acts on a LIANA CT. As with CATS, an image is first loaded for a
 * slot and then inserted; inserting and removing go through {@link FakeTerminals} like the admin
 * API, with the same slot events and CardHandles. Everything is volatile (decision-4), {@link
 * #reset()} forgets the loaded images.
 *
 * <p>Errors: invalid request or invalid image {@link IllegalArgumentException}, unknown slot {@link
 * NoSuchSlot}, insert without a loaded image {@link IllegalStateException}, eHealth CT {@link
 * UnsupportedOperationException} (decision-12, forwarding to kartos: LIANA-93).
 */
@Singleton
public class CatsTerminals {

  /** PSO COMPUTE DIGITAL SIGNATURE (gemSpec_COS), the command behind CATS „ComputeSignature“. */
  static final String PSO_CDS = "002A9E9A";

  private final FakeTerminals terminals;
  private final SicctTerminals sicctTerminals;

  /** Loaded images per CT and slot. */
  private final Map<String, Map<Integer, Path>> loaded = new HashMap<>();

  private final AtomicLong uploads = new AtomicLong();

  /** Pending delayed insert per {@code KT/Slot}. */
  private final Map<String, Pending> pending = new HashMap<>();

  private final ScheduledExecutorService scheduler =
      Executors.newSingleThreadScheduledExecutor(
          r -> {
            Thread thread = new Thread(r, "liana-cats-insert");
            thread.setDaemon(true);
            return thread;
          });
  private Path uploadDir;

  /** A delayed insert: what it does and when. */
  private record Pending(String terminal, Runnable plug, ScheduledFuture<?> future) {}

  CatsTerminals(FakeTerminals terminals, SicctTerminals sicctTerminals) {
    this.terminals = terminals;
    this.sicctTerminals = sicctTerminals;
  }

  /**
   * {@code PUT /config/card/slot/{n}/cardImage}: the image XML as bytes, LIANA stores it in a file.
   * If a card is still inserted in the slot (boot state from the YAML), it is removed; only {@code
   * POST /config/card/insert} inserts the new image. That way CARD/INSERTED comes after the insert
   * as with an empty CATS slot („CATS steckt die Karte …“, then „TGR warte auf eine neue
   * Nachricht“, LIANA-91 HSK_1601_008).
   */
  @SuppressWarnings("java:S5443") // test card images of a simulator, no confidential data
  public synchronized void loadImage(String terminal, int slot, byte[] image) {
    FakeTerminal kt = fake(terminal, slot);
    if (image == null || image.length == 0) {
      throw new IllegalArgumentException("Image fehlt im Body");
    }
    Path file;
    try {
      if (uploadDir == null) {
        uploadDir = Files.createTempDirectory("liana-cats-");
        uploadDir.toFile().deleteOnExit();
      }
      file = uploadDir.resolve(terminal + "-" + slot + "-" + uploads.incrementAndGet() + ".xml");
      Files.write(file, image);
      file.toFile().deleteOnExit();
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
    try {
      CardImage.check(file);
    } catch (IllegalArgumentException e) {
      delete(file);
      throw new IllegalArgumentException(terminal + "/" + slot + ": " + e.getMessage(), e);
    }
    if (kt.cardPresent(slot)) {
      terminals.remove(terminal, slot);
    }
    load(kt, slot, file);
  }

  /**
   * {@code PUT /config/card/slot/{n}} with {@code cardConfigPath}: a CATS card configuration
   * ({@code <configuration>} with {@code cardImageFile}) or directly an image. The path must be
   * valid where LIANA runs; if it is not a file, LIANA selects by file name or ICCSN from the card
   * images as everywhere (LIANA-98).
   */
  public synchronized void loadConfiguration(String terminal, int slot, String cardConfigPath) {
    FakeTerminal kt = fake(terminal, slot);
    if (cardConfigPath == null || cardConfigPath.isBlank()) {
      throw new IllegalArgumentException("cardConfigPath fehlt");
    }
    Path config = Path.of(cardConfigPath);
    Path image = Files.isRegularFile(config) ? imageOf(config) : known(cardConfigPath);
    try {
      CardImage.check(image);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException(terminal + "/" + slot + ": " + e.getMessage(), e);
    }
    load(kt, slot, image.toAbsolutePath());
  }

  /** {@code POST /config/card/insert}: inserts the loaded image or removes the card. */
  public void insert(String terminal, int slot, boolean inserted) {
    insert(terminal, slot, inserted, Duration.ZERO);
  }

  /**
   * Like {@link #insert(String, int, boolean)}; if {@code delay} is positive, the card is inserted
   * only afterwards ({@code liana.cats.terminals[].insert-delay}). Removing, reset and a new insert
   * discard a pending one. If another insert is still pending at the same CT, both come only {@code
   * delay} after this call, together as with the CATS robot: Konnektor-QES KUC_1602_072/073 insert
   * gSMC-KT and HBA, wait for a CARD/INSERTED and then look for the HBA (LIANA-112.05).
   */
  public synchronized void insert(String terminal, int slot, boolean inserted, Duration delay) {
    FakeTerminal kt = fake(terminal, slot);
    cancelPending(terminal + "/" + slot);
    if (!inserted) {
      terminals.remove(terminal, slot);
      return;
    }
    Path image = loaded.getOrDefault(terminal, Map.of()).get(slot);
    if (image == null) {
      throw new IllegalStateException(
          terminal
              + "/"
              + slot
              + ": kein Image geladen (PUT /config/card/slot/"
              + slot
              + "/cardImage)");
    }
    if (delay.isZero() || delay.isNegative()) {
      plug(kt, slot, image);
      return;
    }
    String key = terminal + "/" + slot;
    Runnable plug =
        () -> {
          synchronized (this) {
            if (pending.remove(key) != null
                && image.equals(loaded.getOrDefault(terminal, Map.of()).get(slot))) {
              plug(kt, slot, image);
            }
          }
        };
    pending.replaceAll(
        (k, other) ->
            other.terminal().equals(terminal)
                ? schedule(other.terminal(), other.plug(), delay, other.future())
                : other);
    pending.put(key, schedule(terminal, plug, delay, null));
  }

  private Pending schedule(
      String terminal, Runnable plug, Duration delay, ScheduledFuture<?> previous) {
    if (previous != null) {
      previous.cancel(false);
    }
    return new Pending(
        terminal, plug, scheduler.schedule(plug, delay.toMillis(), TimeUnit.MILLISECONDS));
  }

  private void plug(FakeTerminal kt, int slot, Path image) {
    if (kt.image(slot).filter(image::equals).isEmpty()) {
      terminals.put(kt.id(), slot, image.toString());
    }
  }

  private void cancelPending(String key) {
    Pending scheduled = pending.remove(key);
    if (scheduled != null) {
      scheduled.future().cancel(false);
    }
  }

  /**
   * {@code POST /config/card/slots/reset}: removes all cards of the CT, clears faults and loaded
   * images.
   */
  public synchronized void resetSlots(String terminal) {
    FakeTerminal kt = fake(terminal, 1);
    for (int slot = 1; slot <= kt.slots(); slot++) {
      cancelPending(terminal + "/" + slot);
      terminals.remove(terminal, slot);
      kt.clearFault(slot);
    }
    Map<Integer, Path> images = loaded.remove(terminal);
    if (images != null) {
      images.values().forEach(this::deleteUpload);
    }
  }

  /**
   * {@code GET /cardsim/slot/{n}/delay/{ms}}: every response of the card delayed by {@code ms}, 0
   * lifts it.
   */
  public synchronized void delay(String terminal, int slot, long ms) {
    FakeTerminal kt = fake(terminal, slot);
    if (ms < 0) {
      throw new IllegalArgumentException("Verzögerung " + ms + " ms ist negativ");
    }
    if (ms == 0) {
      kt.clearFault(slot);
    } else {
      kt.fault(slot, Fault.delay(Duration.ofMillis(ms)));
    }
  }

  /**
   * {@code POST /cardsim/slot/{n}/manipulateSignatureResponse}: PSO COMPUTE DIGITAL SIGNATURE
   * responds with {@code responseReplacement} (hex, data and status word), fault response from
   * LIANA-41/LIANA-67.
   */
  public synchronized void manipulateSignatureResponse(
      String terminal, int slot, String responseReplacement) {
    FakeTerminal kt = fake(terminal, slot);
    if (responseReplacement == null || responseReplacement.isBlank()) {
      throw new IllegalArgumentException("responseReplacement fehlt");
    }
    kt.fault(slot, Fault.response(responseReplacement.strip()).onlyFor(PSO_CDS));
  }

  /**
   * Admin reset (decision-4): forgets the loaded images of all CTs; {@link FakeTerminals} restores
   * the cards.
   */
  public synchronized void reset() {
    pending.keySet().stream().toList().forEach(this::cancelPending);
    loaded.values().forEach(images -> images.values().forEach(this::deleteUpload));
    loaded.clear();
  }

  private void load(FakeTerminal kt, int slot, Path image) {
    Path previous = loaded.computeIfAbsent(kt.id(), id -> new HashMap<>()).put(slot, image);
    // If a card is already inserted, it switches the image as with CATS
    if (kt.cardPresent(slot)) {
      terminals.put(kt.id(), slot, image.toString());
    }
    if (previous != null && !previous.equals(image)) {
      deleteUpload(previous);
    }
  }

  private FakeTerminal fake(String terminal, int slot) {
    if (sicctTerminals.terminals().stream().anyMatch(kt -> kt.id().equals(terminal))) {
      throw new UnsupportedOperationException(
          terminal
              + " ist ein eHealth-KT (SICCT): CATS-Endpunkte nur für "
              + "Fake-KTs, Weiterleitung an kartos terminal ist LIANA-93");
    }
    FakeTerminal kt = terminals.terminal(terminal);
    if (slot < 1 || slot > kt.slots()) {
      throw new NoSuchSlot(terminal + ": Slot " + slot + " außerhalb 1.." + kt.slots());
    }
    return kt;
  }

  /**
   * An image from {@code liana.card-images} by file name or ICCSN; otherwise the missing path as
   * before.
   */
  private Path known(String value) {
    try {
      return terminals.images().resolve(value);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException(
          "cardConfigPath "
              + value
              + " nicht gefunden (der Pfad muss bei LIANA "
              + "gelten; Dateiname oder ICCSN aus liana.card-images geht auch): "
              + e.getMessage(),
          e);
    }
  }

  /** The image of a CATS card configuration; if the file itself is an image, that one. */
  private static Path imageOf(Path config) {
    if (!Files.isRegularFile(config)) {
      throw new IllegalArgumentException(
          "cardConfigPath " + config + " nicht gefunden (der Pfad muss bei LIANA " + "gelten)");
    }
    try (InputStream in = Files.newInputStream(config)) {
      XMLInputFactory factory = XMLInputFactory.newDefaultFactory();
      factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
      XMLStreamReader xml = factory.createXMLStreamReader(in);
      while (xml.hasNext()) {
        if (xml.next() != XMLStreamReader.START_ELEMENT) {
          continue;
        }
        if (!"configuration".equals(xml.getLocalName())) {
          return config;
        }
        break;
      }
      while (xml.hasNext()) {
        if (xml.next() == XMLStreamReader.START_ELEMENT
            && "attribute".equals(xml.getLocalName())
            && "cardImageFile".equals(xml.getAttributeValue(null, "id"))) {
          Path image = Path.of(xml.getElementText().strip());
          return image.isAbsolute() ? image : config.toAbsolutePath().getParent().resolve(image);
        }
      }
      throw new IllegalArgumentException("Kartenkonfiguration " + config + " ohne cardImageFile");
    } catch (XMLStreamException e) {
      throw new IllegalArgumentException(
          "cardConfigPath " + config + " ist kein XML: " + e.getMessage());
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /**
   * Uploaded images live in their own directory; LIANA deletes only these, not an inserted card.
   */
  private void deleteUpload(Path image) {
    if (uploadDir != null
        && image.startsWith(uploadDir)
        && loaded.values().stream().noneMatch(images -> images.containsValue(image))
        && terminals.terminals().stream().noneMatch(kt -> imageInUse(kt, image))) {
      delete(image);
    }
  }

  private static boolean imageInUse(FakeTerminal kt, Path image) {
    for (int slot = 1; slot <= kt.slots(); slot++) {
      if (kt.image(slot).filter(image::equals).isPresent()) {
        return true;
      }
    }
    return false;
  }

  private static void delete(Path file) {
    try {
      Files.deleteIfExists(file);
    } catch (IOException e) {
      // stays until the process exits (deleteOnExit)
    }
  }

  /** Unknown slot → 404. */
  public static final class NoSuchSlot extends RuntimeException {
    NoSuchSlot(String message) {
      super(message);
    }
  }
}
