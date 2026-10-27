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

import de.gematik.rbellogger.data.RbelElement;
import de.gematik.rbellogger.testutil.RbelElementAssertion;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * A request from the trace, the request sent to LIANA, the response recorded in the trace and
 * LIANA's response – as {@link RbelElement} so that tests address them with RbelPath. {@code
 * replaced} are the replaced values (trace value → LIANA value), {@code adjustments} all
 * adjustments to the request as sentences with a reason.
 */
public record Exchange(
    RbelElement request,
    RbelElement sentRequest,
    Map<String, String> replaced,
    List<String> adjustments,
    RbelElement traceResponse,
    RbelElement lianaResponse) {

  /** Assertions with RbelPath on the request as it went to LIANA after the replacements. */
  public RbelElementAssertion assertThatSentRequest() {
    return RbelElementAssertion.assertThat(sentRequest);
  }

  /** Assertions with RbelPath on LIANA's response, for values fixed in the test. */
  public RbelElementAssertion assertThatLianaResponse() {
    return RbelElementAssertion.assertThat(lianaResponse);
  }

  /**
   * Checks that LIANA returns the same values as the trace at each RbelPath. A path that finds
   * nothing in the trace is a bug in the test, not a match.
   */
  public void assertSameAt(String... rbelPaths) {
    var failures = new ArrayList<String>();
    for (var path : rbelPaths) {
      var expected = values(traceResponse, path);
      var actual = values(lianaResponse, path);
      if (expected.isEmpty()) {
        failures.add(path + "\n    trifft im Trace nichts – Pfad prüfen");
      } else if (!expected.equals(actual)) {
        failures.add(path + "\n    Trace: " + expected + "\n    LIANA: " + actual);
      }
    }
    if (!failures.isEmpty()) {
      var message = "Antwort von LIANA weicht vom Trace ab:\n  " + String.join("\n  ", failures);
      if (!adjustments.isEmpty()) {
        message +=
            "\n  Request für LIANA angepasst:\n    - " + String.join("\n    - ", adjustments);
      }
      throw new AssertionError(message);
    }
  }

  private static List<String> values(RbelElement message, String rbelPath) {
    return message.findRbelPathMembers(rbelPath).stream()
        .map(RbelElement::getRawStringContent)
        .toList();
  }
}
