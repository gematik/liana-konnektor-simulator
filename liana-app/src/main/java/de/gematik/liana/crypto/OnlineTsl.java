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
package de.gematik.liana.crypto;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import org.jboss.logging.Logger;

/**
 * Online retrieval of the TSL at startup (LIANA-180, {@code liana.pki.tsl-online}). The default is
 * the baked-in TSL; a retrieval may prevent LIANA from starting only in {@link Mode#ENFORCE}. The
 * fetched TSL replaces the loaded one via {@link TrustSpace#replaceTsl} if it is readable and not
 * older; as with the baked-in one, LIANA does not verify its signature.
 */
public final class OnlineTsl {

  private static final Logger LOG = Logger.getLogger(OnlineTsl.class);

  public enum Mode {
    /** Only the baked-in TSL. */
    OFF,
    /** Fetch and swap after startup; if retrieval fails, the baked-in one stays (warning). */
    BACKGROUND,
    /** Fetch at startup; without a readable TSL, startup aborts. */
    ENFORCE
  }

  private OnlineTsl() {}

  /**
   * Performs the retrieval according to {@code mode}: {@link Mode#ENFORCE} synchronously, {@link
   * Mode#BACKGROUND} on its own thread. The result is the header data of the new TSL, empty if
   * nothing was swapped.
   *
   * @throws IllegalStateException in {@link Mode#ENFORCE} if the TSL cannot be loaded
   */
  public static CompletableFuture<Optional<TrustSpace.TslInfo>> start(
      TrustSpace trustSpace, Mode mode, URI url, Duration timeout) {
    return switch (mode) {
      case OFF -> CompletableFuture.completedFuture(Optional.empty());
      case ENFORCE -> {
        try {
          yield CompletableFuture.completedFuture(load(trustSpace, url, timeout));
        } catch (IOException | RuntimeException e) {
          throw new IllegalStateException(
              "liana.pki.tsl-online.mode=enforce: TSL " + url + " nicht geladen: " + reason(e), e);
        }
      }
      case BACKGROUND -> {
        CompletableFuture<Optional<TrustSpace.TslInfo>> result = new CompletableFuture<>();
        Thread thread =
            new Thread(
                () -> {
                  try {
                    result.complete(load(trustSpace, url, timeout));
                  } catch (IOException | RuntimeException e) {
                    LOG.warnf(
                        "TSL %s nicht geladen (%s), LIANA arbeitet mit %s weiter",
                        url, reason(e), trustSpace.tsl().source());
                    result.complete(Optional.empty());
                  }
                },
                "liana-tsl-online");
        thread.setDaemon(true);
        thread.start();
        yield result;
      }
    };
  }

  private static Optional<TrustSpace.TslInfo> load(TrustSpace trustSpace, URI url, Duration timeout)
      throws IOException {
    TrustSpace.TslInfo before = trustSpace.tsl();
    Optional<TrustSpace.TslInfo> replaced =
        trustSpace.replaceTsl(fetch(url, timeout), url.toString());
    replaced.ifPresentOrElse(
        tsl ->
            LOG.infof(
                "TSL %s: SequenceNumber %s, NextUpdate %s, %d CA-Zertifikate; "
                    + "ersetzt %s (SequenceNumber %s)",
                tsl.source(),
                tsl.sequenceNumber(),
                tsl.nextUpdate(),
                tsl.caCount(),
                before.source(),
                before.sequenceNumber()),
        () ->
            LOG.infof(
                "TSL %s ist älter als %s (SequenceNumber %s), die geladene bleibt",
                url, before.source(), before.sequenceNumber()));
    return replaced;
  }

  /**
   * HTTPS with SunJSSE and the JDK's CA certificates: the globally registered BCJSSE (TI TLS,
   * Brainpool) has no trust anchor for the download server in the native image ({@code
   * certificate_unknown}).
   */
  static byte[] fetch(URI url, Duration timeout) throws IOException {
    HttpClient http =
        HttpClient.newBuilder()
            .connectTimeout(timeout)
            .sslContext(jdkTls())
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();
    HttpResponse<byte[]> response;
    try {
      response =
          http.send(
              HttpRequest.newBuilder(url).timeout(timeout).GET().build(),
              HttpResponse.BodyHandlers.ofByteArray());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException("Abruf unterbrochen", e);
    }
    if (response.statusCode() != 200) {
      throw new IOException("HTTP " + response.statusCode());
    }
    return response.body();
  }

  private static javax.net.ssl.SSLContext jdkTls() throws IOException {
    try {
      javax.net.ssl.TrustManagerFactory trust =
          javax.net.ssl.TrustManagerFactory.getInstance("PKIX", "SunJSSE");
      trust.init((java.security.KeyStore) null);
      javax.net.ssl.SSLContext context = javax.net.ssl.SSLContext.getInstance("TLS", "SunJSSE");
      context.init(null, trust.getTrustManagers(), null);
      return context;
    } catch (java.security.GeneralSecurityException e) {
      throw new IOException("TLS-Kontext (SunJSSE): " + e.getMessage(), e);
    }
  }

  private static String reason(Exception e) {
    return e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
  }
}
