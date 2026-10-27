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
package de.gematik.liana.kern.signature;

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.error.ConnectorError;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

/**
 * TIP1-A_5667 GetJobNumber: Jobnummern from a random value (TIP1-A_4642) of the form {@code
 * ABC-123} (TIP1-A_4643, TIP1-A_4645), unique across the last 1000 calls regardless of the call
 * context (TIP1-A_4644); SignDocument may use a Jobnummer only once ({@link #use}).
 */
public final class JobNumbers {

  /** TIP1-A_4644: uniqueness across this many calls. */
  static final int UNIQUE_CALLS = 1000;

  private final Random random;
  private final Deque<String> recent = new ArrayDeque<>();
  private final Set<String> recentSet = new HashSet<>();
  private final Deque<String> used = new ArrayDeque<>();
  private final Set<String> usedSet = new HashSet<>();

  public JobNumbers() {
    this(new SecureRandom());
  }

  JobNumbers(Random random) {
    this.random = random;
  }

  /**
   * TAB_KON_844: checkArguments (TAB_KON_843: MandantId, ClientSystemId, WorkplaceId mandatory,
   * UserId not evaluated, otherwise 4000; the flow provides no access check), then a Jobnummer that
   * did not occur among the last 1000.
   */
  public synchronized String next(Context context) {
    if (blank(context.mandantId())
        || blank(context.clientSystemId())
        || blank(context.workplaceId())) {
      throw ConnectorError.SYNTAX.exception("GetJobNumber ohne vollständigen Kontext: " + context);
    }
    String number;
    do {
      number = candidate();
    } while (recentSet.contains(number));
    recent.addLast(number);
    recentSet.add(number);
    if (recent.size() > UNIQUE_CALLS) {
      recentSet.remove(recent.removeFirst());
    }
    return number;
  }

  /**
   * TAB_KON_757: Jobnummer of a SignDocument. If it already occurred in the last 1000 SignDocument
   * calls, the operation aborts with 4252.
   */
  public synchronized void use(String jobNumber) {
    if (usedSet.contains(jobNumber)) {
      throw ConnectorError.JOB_NUMBER_USED.exception(jobNumber);
    }
    used.addLast(jobNumber);
    usedSet.add(jobNumber);
    if (used.size() > UNIQUE_CALLS) {
      usedSet.remove(used.removeFirst());
    }
  }

  private static boolean blank(String value) {
    return value == null || value.isBlank();
  }

  private String candidate() {
    StringBuilder number = new StringBuilder(7);
    for (int i = 0; i < 3; i++) {
      number.append((char) ('A' + random.nextInt(26)));
    }
    number.append('-');
    for (int i = 0; i < 3; i++) {
      number.append((char) ('0' + random.nextInt(10)));
    }
    return number.toString();
  }
}
