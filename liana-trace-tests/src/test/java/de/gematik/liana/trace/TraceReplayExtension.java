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
import de.gematik.rbellogger.data.RbelMessageMetadata;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolver;
import org.junit.platform.commons.support.AnnotationSupport;

/**
 * Reads the trace from {@link TraceReplay}, starts LIANA (or a stub with {@link GegenStub}), sends
 * each HTTP request from the trace there after the adjustments ({@link Adjustments}) and parses
 * trace and LIANA responses with Rbel. Request and response belong together if the response is the
 * next HTTP response after the request in the trace.
 *
 * <p>One replay per test class: {@code @Nested} classes inherit it from the store of the outer
 * class, without their own LIANA start (LIANA-124).
 */
class TraceReplayExtension implements BeforeAllCallback, ParameterResolver {

  private static final ExtensionContext.Namespace NAMESPACE =
      ExtensionContext.Namespace.create(TraceReplayExtension.class);

  /** Headers the HTTP client sets itself (or does not allow to be set). */
  private static final Set<String> CLIENT_HEADERS =
      Set.of("connection", "content-length", "expect", "host", "upgrade");

  @Override
  public void beforeAll(ExtensionContext context) {
    if (context.getStore(NAMESPACE).get(Replay.class) != null) {
      return;
    }
    var testClass = context.getRequiredTestClass();
    var trace =
        TraceFile.read(
            Path.of(
                AnnotationSupport.findAnnotation(testClass, TraceReplay.class)
                    .orElseThrow()
                    .value()));
    var config =
        AnnotationSupport.findRepeatableAnnotations(testClass, LianaConfig.class).stream()
            .flatMap(c -> Arrays.stream(c.value()))
            .toList();
    var carries = AnnotationSupport.findRepeatableAnnotations(testClass, Carry.class);

    var stub = AnnotationSupport.findAnnotation(testClass, GegenStub.class);
    ReplayTarget liana =
        stub.isPresent()
            ? StubServer.start(Path.of(stub.get().value()))
            : LianaProcess.start(testClass.getSimpleName(), config);
    context.getStore(NAMESPACE).put(ReplayTarget.class, (AutoCloseable) liana);

    var client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
    var converter = trace.rbel().getRbelConverter();
    var adjustments =
        new Adjustments(
            AnnotationSupport.findRepeatableAnnotations(testClass, Replace.class),
            AnnotationSupport.findRepeatableAnnotations(testClass, ReplaceSteps.class));
    var exchanges = new ArrayList<Exchange>();
    for (var request : trace.requests()) {
      var applied = adjustments.apply(request.getRawContent());
      var sent = converter.parseMessage(applied.raw(), new RbelMessageMetadata());
      var lianaResponse =
          converter.parseMessage(send(client, liana, sent), new RbelMessageMetadata());
      var traceResponse = trace.responseTo(request);
      exchanges.add(
          new Exchange(
              request,
              sent,
              applied.replaced(),
              applied.adjustments(),
              traceResponse,
              lianaResponse));
      for (var carry : carries) {
        carry(adjustments, carry, traceResponse, lianaResponse);
      }
    }
    context
        .getStore(NAMESPACE)
        .put(Replay.class, new Replay(trace.path().toString(), List.copyOf(exchanges)));
  }

  @Override
  public boolean supportsParameter(ParameterContext parameter, ExtensionContext context) {
    return parameter.getParameter().getType() == Replay.class;
  }

  @Override
  public Object resolveParameter(ParameterContext parameter, ExtensionContext context) {
    return context.getStore(NAMESPACE).get(Replay.class, Replay.class);
  }

  /**
   * Pairs the values at the RbelPath of {@code carry} from trace and LIANA response by position and
   * remembers them.
   */
  private static void carry(
      Adjustments adjustments, Carry carry, RbelElement traceResponse, RbelElement lianaResponse) {
    var traceValues = traceResponse.findRbelPathMembers(carry.value());
    var lianaValues = lianaResponse.findRbelPathMembers(carry.value());
    for (int i = 0; i < Math.min(traceValues.size(), lianaValues.size()); i++) {
      adjustments.put(
          traceValues.get(i).getRawStringContent(),
          lianaValues.get(i).getRawStringContent(),
          carry.why());
    }
  }

  /** Sends the recorded request to LIANA and returns the response as a raw HTTP message. */
  private static byte[] send(HttpClient client, ReplayTarget liana, RbelElement request) {
    var builder = HttpRequest.newBuilder(URI.create(liana.baseUrl() + text(request, "$.path")));
    headerLines(request)
        .forEach(
            line -> {
              int colon = line.indexOf(':');
              var name = line.substring(0, colon).trim();
              if (!CLIENT_HEADERS.contains(name.toLowerCase())) {
                builder.header(name, line.substring(colon + 1).trim());
              }
            });
    var body = request.findElement("$.body").map(RbelElement::getRawContent).orElse(new byte[0]);
    builder.method(
        text(request, "$.method"),
        body.length == 0
            ? HttpRequest.BodyPublishers.noBody()
            : HttpRequest.BodyPublishers.ofByteArray(body));
    try {
      var response = client.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
      return raw(response);
    } catch (IOException e) {
      throw new UncheckedIOException(describe(request) + " an LIANA fehlgeschlagen", e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException(e);
    }
  }

  /** Raw HTTP/1.1 response; the client has already reassembled a possibly chunked body. */
  private static byte[] raw(HttpResponse<byte[]> response) {
    var head = new StringBuilder("HTTP/1.1 ").append(response.statusCode()).append("\r\n");
    response
        .headers()
        .map()
        .forEach(
            (name, values) -> {
              if (!name.equalsIgnoreCase("transfer-encoding")
                  && !name.equalsIgnoreCase("content-length")) {
                values.forEach(
                    value -> head.append(name).append(": ").append(value).append("\r\n"));
              }
            });
    head.append("content-length: ").append(response.body().length).append("\r\n\r\n");
    var out = new ByteArrayOutputStream();
    out.writeBytes(head.toString().getBytes(StandardCharsets.ISO_8859_1));
    out.writeBytes(response.body());
    return out.toByteArray();
  }

  private static List<String> headerLines(RbelElement request) {
    var raw = new String(request.getRawContent(), StandardCharsets.ISO_8859_1);
    int end = raw.indexOf("\r\n\r\n");
    return raw.substring(0, end < 0 ? raw.length() : end)
        .lines()
        .skip(1)
        .filter(l -> l.contains(":"))
        .toList();
  }

  private static String text(RbelElement element, String rbelPath) {
    return element
        .findElement(rbelPath)
        .map(RbelElement::getRawStringContent)
        .orElseThrow(() -> new IllegalStateException(rbelPath + " fehlt in " + describe(element)));
  }

  private static String describe(RbelElement message) {
    return message.getRawStringContent().lines().findFirst().orElse("<leer>");
  }
}
