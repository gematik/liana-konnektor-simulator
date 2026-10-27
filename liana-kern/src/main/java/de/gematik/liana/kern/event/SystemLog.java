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
package de.gematik.liana.kern.event;

import de.gematik.liana.kern.card.CardEvent;
import de.gematik.liana.kern.card.CardObject;
import de.gematik.liana.kern.card.CardSessions;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Systemprotokoll per TIP1-A_4715 (TUC_KON_271 „Schreibe Protokolleintrag“, gemSpec_Kon
 * 4.1.10.4.1): entries with timestamp, type, severity, topic and parameters. Fed by TUC_KON_256
 * „Systemereignis absetzen“ (TIP1-A_4598-02, step 2, doLog = true as default): {@link
 * #cardEvent(CardEvent)} and {@link #sessionTimeout(CardSessions.Timeout)}. Rolling, the oldest
 * entries drop out first; there is no LOG_LEVEL_SYSLOG, every severity is written. Only the
 * Systemprotokoll (eventType Op without fmName); security and Fachmodul logs are missing.
 */
public final class SystemLog {

  /** Type of the entry per TUC_KON_271: Op from Operation and Infrastructure, Sec from Security. */
  public enum Type {
    OP("Op"),
    SEC("Sec");

    private final String value;

    Type(String value) {
      this.value = value;
    }

    public String value() {
      return value;
    }
  }

  /** Severity per EventService.xsd, plus Debug (TUC_KON_271). */
  public enum Severity {
    DEBUG("Debug"),
    INFO("Info"),
    WARN("Warning"),
    ERR("Error"),
    FATAL("Fatal");

    private final String value;

    Severity(String value) {
      this.value = value;
    }

    public String value() {
      return value;
    }
  }

  /** A log entry: date and time and the event passed in (TUC_KON_271). */
  public record Entry(
      Instant time, Type type, Severity severity, String topic, Map<String, String> parameters) {}

  /** Default size: enough for long test runs, limits memory. */
  public static final int DEFAULT_CAPACITY = 10_000;

  private final Clock clock;
  private final int capacity;
  private final Deque<Entry> entries = new ArrayDeque<>();
  private final List<Consumer<Entry>> listeners = new CopyOnWriteArrayList<>();

  public SystemLog(Clock clock, int capacity) {
    this.clock = clock;
    this.capacity = capacity;
  }

  /**
   * From now on reports every new entry to {@code listener}, after writing (Admin API, LIANA-150).
   */
  public void addListener(Consumer<Entry> listener) {
    listeners.add(listener);
  }

  /** TUC_KON_271 with eventType Op or Sec; parameters in the order passed. */
  public Entry write(Type type, Severity severity, String topic, Map<String, String> parameters) {
    Entry entry;
    synchronized (this) {
      entry =
          new Entry(
              clock.instant(),
              type,
              severity,
              topic,
              Collections.unmodifiableMap(new LinkedHashMap<>(parameters)));
      if (entries.size() == capacity) {
        entries.removeFirst();
      }
      entries.addLast(entry);
    }
    listeners.forEach(listener -> listener.accept(entry));
    return entry;
  }

  /**
   * CARD/INSERTED and CARD/REMOVED (Op, Info). TIP1-A_4710-02: ICCSN, CardHolderName and KVNR are
   * personal data and are missing from the entry; CardVersion is missing as well, LIANA does not
   * log it.
   */
  public void cardEvent(CardEvent event) {
    CardObject card = event.card();
    Map<String, String> parameters = new LinkedHashMap<>();
    parameters.put("CardHandle", card.cardHandle());
    parameters.put("CardType", card.data().type().value());
    parameters.put("CtID", card.ctId());
    parameters.put("SlotID", String.valueOf(card.slotNo()));
    parameters.put("InsertTime", card.insertTime().toString());
    write(Type.OP, Severity.INFO, event.topic().topic(), parameters);
  }

  /** CARD/SESSION/TIMEOUT (A_25860-01: Op, Info, CardType, SessionID, Timer). */
  public void sessionTimeout(CardSessions.Timeout timeout) {
    Map<String, String> parameters = new LinkedHashMap<>();
    parameters.put("CardType", timeout.cardType());
    parameters.put("SessionID", timeout.sessionId());
    parameters.put("Timer", timeout.timer());
    write(Type.OP, Severity.INFO, CardSessions.Timeout.TOPIC, parameters);
  }

  /**
   * CT/DISCONNECTED (TIP1-A_4537: Op, Info, CtID and Hostname); attached to the SICCT terminals as
   * {@code TerminalConnectionListener}.
   */
  public void ctDisconnected(String ctId, String hostname, String reason) {
    Map<String, String> parameters = new LinkedHashMap<>();
    parameters.put("CtID", ctId);
    parameters.put("Hostname", hostname);
    write(Type.OP, Severity.INFO, "CT/DISCONNECTED", parameters);
  }

  /** Entries with {@code from <= time <= to}, oldest first; {@code null} means unbounded. */
  public synchronized List<Entry> entries(Instant from, Instant to) {
    return entries.stream()
        .filter(e -> from == null || !e.time().isBefore(from))
        .filter(e -> to == null || !e.time().isAfter(to))
        .toList();
  }

  /** Clears the log (Admin API reset, decision-4). */
  public synchronized void clear() {
    entries.clear();
  }
}
