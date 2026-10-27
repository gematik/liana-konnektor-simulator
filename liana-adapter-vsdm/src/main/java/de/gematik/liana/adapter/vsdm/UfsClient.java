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
package de.gematik.liana.adapter.vsdm;

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.card.CardObject;
import de.gematik.liana.kern.vsdm.UpdateFlagService;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;

/**
 * GetUpdateFlags to a UFS over HTTP/1.1 ({@code Connection: close}, one request per connection).
 * The {@link Connector} opens the connection: TCP for {@code http}, TLS with the SM-B for {@code
 * https} (TUC_KON_110). The response must be complete within {@code readTimeout}, measured with the
 * same {@link Clock} as MAXTIME_VSDM in {@code OnlineCheck}: if reading aborts because the
 * remaining MAXTIME_VSDM has elapsed, it has elapsed there too (VSDM-A_2998).
 */
public final class UfsClient implements UpdateFlagService {

  /**
   * Opens the connection to {@code url} (host, port, scheme), including the TLS handshake; {@code
   * smb} in the context {@code context} authenticates the client.
   */
  public interface Connector {
    Socket connect(URI url, Context context, CardObject smb, Duration timeout) throws IOException;
  }

  private static final int MAX_BODY = 1 << 20;

  private final Connector connector;
  private final Clock clock;

  public UfsClient(Connector connector, Clock clock) {
    this.connector = connector;
    this.clock = clock;
  }

  @Override
  public Answer getUpdateFlags(
      URI url,
      String iccsn,
      String providerId,
      Context context,
      CardObject smb,
      Duration connectTimeout,
      Duration readTimeout)
      throws IOException {
    byte[] body = UfsXml.request(iccsn, providerId);
    Instant deadline = clock.instant().plus(readTimeout);
    try (Socket socket = connector.connect(url, context, smb, connectTimeout)) {
      OutputStream out = socket.getOutputStream();
      out.write(head(url, body.length).getBytes(StandardCharsets.US_ASCII));
      out.write(body);
      out.flush();
      Response response = read(socket, deadline, clock);
      // SOAP 1.1: fault with HTTP 500, response with 200
      if (response.status != 200 && response.status != 500) {
        throw new IOException("HTTP " + response.status + " von " + url);
      }
      return UfsXml.response(response.body);
    }
  }

  private static String head(URI url, int length) {
    String path = url.getRawPath() == null || url.getRawPath().isEmpty() ? "/" : url.getRawPath();
    if (url.getRawQuery() != null) {
      path += "?" + url.getRawQuery();
    }
    String host = url.getPort() < 0 ? url.getHost() : url.getHost() + ":" + url.getPort();
    return "POST "
        + path
        + " HTTP/1.1\r\nHost: "
        + host
        + "\r\nContent-Type: text/xml; charset=utf-8\r\n"
        + "SOAPAction: \""
        + UfsXml.SOAP_ACTION
        + "\"\r\nContent-Length: "
        + length
        + "\r\nConnection: close\r\n\r\n";
  }

  private record Response(int status, byte[] body) {}

  /** Status line, headers, body by Content-Length, chunked or until the end of the connection. */
  private static Response read(Socket socket, Instant deadline, Clock clock) throws IOException {
    Input in = new Input(socket, deadline, clock);
    String status = in.line();
    String[] parts = status.split(" ", 3);
    if (parts.length < 2 || !parts[0].startsWith("HTTP/1.")) {
      throw new IOException("keine HTTP-Antwort: " + status);
    }
    int code;
    try {
      code = Integer.parseInt(parts[1]);
    } catch (NumberFormatException e) {
      throw new IOException("keine HTTP-Antwort: " + status, e);
    }
    long length = -1;
    boolean chunked = false;
    for (String header = in.line(); !header.isEmpty(); header = in.line()) {
      int colon = header.indexOf(':');
      if (colon < 0) {
        continue;
      }
      String name = header.substring(0, colon).trim().toLowerCase(Locale.ROOT);
      String value = header.substring(colon + 1).trim();
      if (name.equals("content-length")) {
        length = Long.parseLong(value);
      } else if (name.equals("transfer-encoding")
          && value.toLowerCase(Locale.ROOT).contains("chunked")) {
        chunked = true;
      }
    }
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    if (chunked) {
      for (long size = Long.parseLong(in.line().split(";")[0].trim(), 16);
          size > 0;
          size = Long.parseLong(in.line().split(";")[0].trim(), 16)) {
        in.copy(body, size);
        in.line();
      }
    } else if (length >= 0) {
      in.copy(body, length);
    } else {
      in.copy(body, MAX_BODY);
    }
    return new Response(code, body.toByteArray());
  }

  /** Reads with read timeout until {@code deadline}. */
  private static final class Input {

    private final Socket socket;
    private final InputStream in;
    private final Instant deadline;
    private final Clock clock;
    private long total;

    Input(Socket socket, Instant deadline, Clock clock) throws IOException {
      this.socket = socket;
      this.in = socket.getInputStream();
      this.deadline = deadline;
      this.clock = clock;
    }

    /** Ends with a timeout only once the clock has reached {@code deadline}, never earlier. */
    private int read(byte[] buffer, int length) throws IOException {
      int n;
      while (true) {
        long left = Duration.between(clock.instant(), deadline).toNanos();
        if (left <= 0) {
          throw new SocketTimeoutException("Antwort nicht innerhalb TIMEOUT_VSDM");
        }
        // round up: SO_TIMEOUT in ms must not expire before deadline
        socket.setSoTimeout((int) Math.min(Integer.MAX_VALUE, (left + 999_999) / 1_000_000));
        try {
          n = in.read(buffer, 0, length);
          break;
        } catch (SocketTimeoutException e) {
          // socket stays valid; the socket's nanoTime and the clock can drift apart
        }
      }
      total += Math.max(n, 0);
      if (total > MAX_BODY) {
        throw new IOException("Antwort größer als " + MAX_BODY + " Byte");
      }
      return n;
    }

    String line() throws IOException {
      ByteArrayOutputStream line = new ByteArrayOutputStream();
      byte[] one = new byte[1];
      while (true) {
        if (read(one, 1) < 0) {
          throw new IOException("Verbindung vor Ende der HTTP-Antwort geschlossen");
        }
        if (one[0] == '\n') {
          break;
        }
        if (one[0] != '\r') {
          line.write(one[0]);
        }
      }
      return line.toString(StandardCharsets.ISO_8859_1);
    }

    /** Copies {@code count} bytes, with {@link #MAX_BODY} until the end of the connection. */
    void copy(ByteArrayOutputStream out, long count) throws IOException {
      byte[] buffer = new byte[8192];
      long left = count;
      while (left > 0) {
        int n = read(buffer, (int) Math.min(buffer.length, left));
        if (n < 0) {
          if (count == MAX_BODY) {
            return;
          }
          throw new IOException("Verbindung vor Ende der HTTP-Antwort geschlossen");
        }
        out.write(buffer, 0, n);
        left -= n;
      }
    }
  }
}
