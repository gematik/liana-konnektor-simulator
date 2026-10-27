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
package de.gematik.liana.kern.vendor;

import de.gematik.liana.kern.event.SystemLog;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The global switch {@code liana.strict} for deviations of peers (LIANA-126), alongside the {@link
 * VendorProfile}: the profile determines which connector LIANA emulates, this switch whether LIANA
 * tolerates known spec deviations of CT, card engine or Fachdienst. It does not affect LIANA's own
 * vendor deviations.
 *
 * <p>Code that detects a {@link Deviation} asks {@link #tolerate(Deviation, String, Map)} and falls
 * back only on {@code true}. Every detected deviation is in the Systemprotokoll (TUC_KON_271, type
 * Op, topic {@value #TOPIC}): as Warning when tolerated, as Error with {@code strict}. Only logged,
 * not delivered to Clientsysteme (TUC_KON_256 doDisp = false), so that the suites see no foreign
 * events. Only {@code kern.vendor} and the Admin API read the switch itself ({@code
 * StrictArchitectureTest}).
 *
 * <p>Switchable at runtime (Admin API), {@link #reset()} restores the boot state from the YAML
 * (decision-4).
 */
public final class PeerDeviations {

  /** Topic of the log entries; not a topic from gemSpec_Kon but LIANA's own. */
  public static final String TOPIC = "LIANA/DEVIATION";

  private final boolean boot;
  private final SystemLog log;
  private volatile boolean strict;

  public PeerDeviations(boolean boot, SystemLog log) {
    this.boot = boot;
    this.log = log;
    this.strict = boot;
  }

  /**
   * Reports the detected {@code deviation} of the peer {@code peer} (e.g. the CT ID) to the system
   * log and says whether LIANA may fall back: {@code true} without {@code strict}, otherwise the
   * operation fails as the spec prescribes for the deviating response. {@code details} supplement
   * the observation (e.g. the status word).
   */
  public boolean tolerate(Deviation deviation, String peer, Map<String, String> details) {
    boolean tolerated = !strict;
    Map<String, String> parameters = new LinkedHashMap<>();
    parameters.put("Deviation", deviation.name());
    parameters.put("Peer", peer);
    parameters.put("Spec", deviation.spec());
    parameters.put("Observed", deviation.observed());
    parameters.putAll(details);
    parameters.put("Action", tolerated ? deviation.fallback() : "abgewiesen (strict)");
    log.write(
        SystemLog.Type.OP,
        tolerated ? SystemLog.Severity.WARN : SystemLog.Severity.ERR,
        TOPIC,
        parameters);
    return tolerated;
  }

  /** The active switch, for display; do not branch on it, use {@link #tolerate} instead. */
  public boolean strict() {
    return strict;
  }

  /** The boot state from {@code liana.strict}. */
  public boolean boot() {
    return boot;
  }

  /** Switches volatilely. */
  public void setStrict(boolean strict) {
    this.strict = strict;
  }

  /** Restores the boot state. */
  public void reset() {
    strict = boot;
  }
}
