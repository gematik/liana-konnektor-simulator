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

import de.gematik.liana.kern.trace.Traffic;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The channels of the traffic push, each switchable at runtime (LIANA-195.05): every channel
 * reports through {@link #traffic(String)}, which asks per message whether the channel is on. At
 * startup every channel is on; switching is volatile like every change through the Admin API,
 * {@code POST /admin/reset} switches all on again.
 */
public final class TraceChannels {

  /** Konnektor interface, HTTP and HTTPS. */
  public static final String KONNEKTOR = "konnektor";

  /** Management port: KMS and CATS, not the Admin API. */
  public static final String MANAGEMENT = "management";

  /** KMS on its compatibility port ({@code liana.kms.port}). */
  public static final String KMS_PORT = "kms-port";

  /** Robot interface ({@code liana.robot.port}). */
  public static final String ROBOT = "robot";

  /** CETP to the Ereignissenken. */
  public static final String CETP = "cetp";

  /** VSDM online check: GetUpdateFlags at the UFS. */
  public static final String UFS = "ufs";

  /** Fetching the online TSL. */
  public static final String TSL = "tsl";

  private final Traffic traffic;
  private final Set<String> off = ConcurrentHashMap.newKeySet();

  public TraceChannels(Traffic traffic) {
    this.traffic = traffic;
  }

  /** CATS on its own port for card terminal {@code ct}. */
  public static String cats(String ct) {
    return "cats:" + ct;
  }

  /** APDUs of a fake CT, SICCT of an eHealth CT. */
  public static String terminal(String ct) {
    return "kt:" + ct;
  }

  /** The traffic of {@code channel}. */
  public Traffic traffic(String channel) {
    return traffic.gated(() -> on(channel));
  }

  public boolean on(String channel) {
    return !off.contains(channel);
  }

  public void set(String channel, boolean on) {
    if (on) {
      off.remove(channel);
    } else {
      off.add(channel);
    }
  }

  /** The channels switched off, sorted. */
  public Set<String> off() {
    return new TreeSet<>(off);
  }

  /** All channels on, as at startup. */
  public void reset() {
    off.clear();
  }
}
