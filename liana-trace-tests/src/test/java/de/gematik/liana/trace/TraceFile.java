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

import de.gematik.rbellogger.RbelLogger;
import de.gematik.rbellogger.data.RbelElement;
import de.gematik.rbellogger.facets.http.RbelHttpRequestFacet;
import de.gematik.rbellogger.facets.http.RbelHttpResponseFacet;
import de.gematik.rbellogger.file.RbelFileReader;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

/** A {@code .tgr} parsed with Rbel: all messages in trace order. */
record TraceFile(Path path, RbelLogger rbel, List<RbelElement> messages) {

  static TraceFile read(Path path) {
    var rbel = RbelLogger.build();
    try {
      var messages =
          new RbelFileReader(rbel.getRbelConverter())
              .convertFromRbelFile(Files.readString(path), Optional.empty());
      return new TraceFile(path, rbel, messages);
    } catch (IOException e) {
      throw new UncheckedIOException("Trace " + path.toAbsolutePath() + " nicht lesbar", e);
    }
  }

  /** HTTP requests in trace order. */
  List<RbelElement> requests() {
    return messages.stream().filter(m -> m.hasFacet(RbelHttpRequestFacet.class)).toList();
  }

  /** The next HTTP response after the request. */
  RbelElement responseTo(RbelElement request) {
    return messages.subList(messages.indexOf(request) + 1, messages.size()).stream()
        .filter(m -> m.hasFacet(RbelHttpResponseFacet.class))
        .findFirst()
        .orElseThrow(
            () ->
                new IllegalStateException(
                    path
                        + ": keine Antwort auf "
                        + request.getRawStringContent().lines().findFirst().orElse("<leer>")));
  }

  /** Another file (e.g. a blueprint JSON) parsed with the same Rbel, for RbelPath comparisons. */
  RbelElement parse(Path file) {
    try {
      return rbel.getRbelConverter().convertElement(Files.readString(file), null);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }
}
