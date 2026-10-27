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

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.card.CardObject;
import de.gematik.liana.kern.event.SystemLog;
import de.gematik.liana.kern.vsdm.Pruefungsnachweis.Ergebnis;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BooleanSupplier;

/**
 * Onlineprüfung of ReadVSD with PerformOnlineCheck=true ([gemSpec_FM_VSDM] 3.2.1,
 * „Aktualisierungsaufträge ermitteln“ in Tab_FM_VSDM_15) via a configurable chain of sources
 * (LIANA-141): per call in order until one answers. If none answers, the spec fallback applies:
 * result 3 without Prüfziffer (Tab_FM_VSDM_05-01, VSDM-A_2578).
 *
 * <ul>
 *   <li>MGM_LU_ONLINE Disabled: no online connection, no source is asked (result 3)
 *   <li>MAXTIME_VSDM limits the whole chain; expired → abort with result 3, Warning (VSDM-A_2998)
 *   <li>Sources that deviate from the spec ({@link Source#deviatesFromSpec()}, the fixed response)
 *       drop out of the chain with {@code liana.strict}
 *   <li>A pending update without CCS (VSDD/CMS, LIANA-102) and a fault of the UFS end the chain
 *       with result 3, the gematik error code goes into ErrorCode (Tab_FM_VSDM_04)
 * </ul>
 *
 * <p>Every check is in the Systemprotokoll (topic {@value #TOPIC}, with source and the reasons why
 * the preceding sources did not answer; without ICCSN and KVNR as per TIP1-A_4710-02) and as the
 * last result per eGK in {@link #last()}.
 */
public final class OnlineCheck {

  public static final String TOPIC = "LIANA/VSDM/ONLINE_CHECK";

  /** Name of the answering stage if no source answered. */
  public static final String FALLBACK = "spec";

  /**
   * What a source needs about the eGK; {@code smb} is the SM-B of the call (MANDANT_SMB,
   * TUC_KON_000 R7).
   */
  public record Request(
      Context context, CardObject egk, CardObject smb, String providerId, Budget budget) {

    public String iccsn() {
      return egk.data().iccsn();
    }

    public String kvnr() {
      return egk.data().kvnr();
    }
  }

  /** The remaining time in MAXTIME_VSDM. */
  public static final class Budget {

    private final Clock clock;
    private final Instant deadline;

    Budget(Clock clock, Instant deadline) {
      this.clock = clock;
      this.deadline = deadline;
    }

    public Duration remaining() {
      Duration left = Duration.between(clock.instant(), deadline);
      return left.isNegative() ? Duration.ZERO : left;
    }

    public boolean exhausted() {
      return remaining().isZero();
    }
  }

  /** Response of a source. */
  public sealed interface Answer {}

  /** No update required (result 2) with the Prüfziffer, {@code null} for none. */
  public record NoUpdate(byte[] pruefziffer) implements Answer {}

  /** Aktualisierungsaufträge determined but not executable (result 3). */
  public record UpdatePending(List<UpdateFlagService.UpdateFlag> flags) implements Answer {}

  /**
   * The Fachdienst answered with a fault (result 3, {@code errorCode} only for a gematik error).
   */
  public record Fault(Integer errorCode, String text) implements Answer {}

  /** A stage of the chain. */
  public interface Source {

    /** Name in configuration, log and Admin API. */
    String name();

    /**
     * Whether the source deliberately deviates from the spec; with {@code liana.strict} it drops
     * out of the chain.
     */
    default boolean deviatesFromSpec() {
      return false;
    }

    /**
     * Asks the source. {@link Optional#empty()} if it could not answer; it enters the reason (and
     * the reasons of individual endpoints) in {@code notes}.
     */
    Optional<Answer> ask(Request request, Notes notes);

    /** Discard runtime state ({@code POST /admin/reset}). */
    default void reset() {}
  }

  /** Why sources did not answer, in the order of the chain. */
  public static final class Notes {

    private final List<String> entries = new ArrayList<>();

    public void add(String source, String reason) {
      entries.add(source + ": " + reason);
    }

    List<String> entries() {
      return List.copyOf(entries);
    }
  }

  /**
   * Result of a check: the Prüfungsnachweis, the answering stage ({@value #FALLBACK} for the spec
   * fallback) and why the preceding stages did not answer.
   */
  public record Outcome(
      Instant time,
      String cardHandle,
      String iccsn,
      Pruefungsnachweis pruefungsnachweis,
      String source,
      String detail,
      List<String> skipped) {}

  private final List<Source> sources;
  private final Duration maxTime;
  private final BooleanSupplier online;
  private final BooleanSupplier strict;
  private final SystemLog log;
  private final Clock clock;
  private final Map<String, Outcome> last = new ConcurrentHashMap<>();

  /**
   * @param maxTime MAXTIME_VSDM (Tab_FM_VSDM_14)
   * @param online MGM_LU_ONLINE
   * @param strict {@code liana.strict}, switchable at runtime
   */
  public OnlineCheck(
      List<Source> sources,
      Duration maxTime,
      BooleanSupplier online,
      BooleanSupplier strict,
      SystemLog log,
      Clock clock) {
    this.sources = List.copyOf(sources);
    this.maxTime = maxTime;
    this.online = online;
    this.strict = strict;
    this.log = log;
    this.clock = clock;
  }

  /** The names of the stages in the order of the chain, without the spec fallback. */
  public List<String> sources() {
    return sources.stream().map(Source::name).toList();
  }

  /**
   * Checks the eGK; {@code providerId} from C.CH.AUT, {@code null} if the certificate carries none.
   */
  public Outcome check(Context context, CardObject egk, CardObject smb, String providerId) {
    Instant start = clock.instant();
    Budget budget = new Budget(clock, start.plus(maxTime));
    Request request = new Request(context, egk, smb, providerId, budget);
    Notes notes = new Notes();
    String source = FALLBACK;
    Answer answer = null;
    boolean aborted = false;
    if (!online.getAsBoolean()) {
      notes.add("online", "MGM_LU_ONLINE Disabled, keine Online-Verbindung");
    } else {
      for (Source candidate : sources) {
        if (budget.exhausted()) {
          aborted = true;
          notes.add(candidate.name(), "MAXTIME_VSDM (" + maxTime.toSeconds() + " s) abgelaufen");
          break;
        }
        if (candidate.deviatesFromSpec() && strict.getAsBoolean()) {
          notes.add(candidate.name(), "abgeschaltet (strict)");
          continue;
        }
        Optional<Answer> found = candidate.ask(request, notes);
        if (found.isPresent()) {
          answer = found.get();
          source = candidate.name();
          break;
        }
      }
      aborted |= answer == null && budget.exhausted() && !sources.isEmpty();
    }
    Outcome outcome = outcome(egk, start, answer, source, notes);
    last.put(egk.data().iccsn() != null ? egk.data().iccsn() : egk.cardHandle(), outcome);
    log(outcome, aborted);
    return outcome;
  }

  /** The Prüfungsnachweis with the current timestamp at its creation (Tab_FM_VSDM_04). */
  private Outcome outcome(
      CardObject egk, Instant start, Answer answer, String source, Notes notes) {
    Instant now = clock.instant();
    Pruefungsnachweis pn;
    String detail;
    switch (answer) {
      case NoUpdate noUpdate -> {
        pn =
            new Pruefungsnachweis(
                now, Ergebnis.KEINE_AKTUALISIERUNG_ERFORDERLICH, null, noUpdate.pruefziffer());
        detail = "keine Aktualisierung erforderlich";
      }
      case UpdatePending pending -> {
        pn =
            new Pruefungsnachweis(
                now, Ergebnis.AKTUALISIERUNG_TECHNISCH_NICHT_MOEGLICH, null, null);
        detail =
            pending.flags().size()
                + " Aktualisierungsauftrag/-aufträge ("
                + String.join(
                    ", ", pending.flags().stream().map(UpdateFlagService.UpdateFlag::type).toList())
                + "), kein CCS konfiguriert (LIANA-102)";
      }
      case Fault fault -> {
        pn =
            new Pruefungsnachweis(
                now, Ergebnis.AKTUALISIERUNG_TECHNISCH_NICHT_MOEGLICH, fault.errorCode(), null);
        detail =
            "Fault " + (fault.errorCode() != null ? fault.errorCode() + " " : "") + fault.text();
      }
      case null -> {
        pn =
            new Pruefungsnachweis(
                now, Ergebnis.AKTUALISIERUNG_TECHNISCH_NICHT_MOEGLICH, null, null);
        detail = "keine Quelle hat geantwortet";
      }
    }
    return new Outcome(
        start, egk.cardHandle(), egk.data().iccsn(), pn, source, detail, notes.entries());
  }

  private void log(Outcome outcome, boolean aborted) {
    Map<String, String> parameters = new LinkedHashMap<>();
    parameters.put("CardHandle", outcome.cardHandle());
    parameters.put("Ergebnis", String.valueOf(outcome.pruefungsnachweis().ergebnis().code()));
    if (outcome.pruefungsnachweis().errorCode() != null) {
      parameters.put("ErrorCode", String.valueOf(outcome.pruefungsnachweis().errorCode()));
    }
    parameters.put("Source", outcome.source());
    parameters.put("Detail", outcome.detail());
    if (!outcome.skipped().isEmpty()) {
      parameters.put("Skipped", String.join("; ", outcome.skipped()));
    }
    log.write(
        SystemLog.Type.OP,
        aborted ? SystemLog.Severity.WARN : SystemLog.Severity.INFO,
        TOPIC,
        parameters);
  }

  /** The last result per eGK (by ICCSN), oldest first. */
  public List<Outcome> last() {
    return last.values().stream().sorted(Comparator.comparing(Outcome::time)).toList();
  }

  /** {@code POST /admin/reset}: last results and runtime state of the sources. */
  public void clear() {
    last.clear();
    sources.forEach(Source::reset);
  }
}
