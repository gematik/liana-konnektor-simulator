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
package de.gematik.liana.adapter.fake;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Sends card APDUs as raw data to a Tiger proxy ({@code POST /traffic}, TrafficPushController): per
 * APDU the command and the response, sender, receiver and time in the headers {@code tgr-sender},
 * {@code tgr-receiver}, {@code tgr-timestamp}.
 *
 * <p>Rbel knows no bare APDUs, only SICCT. Therefore each APDU is put into a SICCT envelope (10
 * bytes, SICCT 6.1.4.2 according to {@code RbelSicctEnvelopeConverter}): type ({@link #C_COMMAND}
 * or {@link #R_RESPONSE}), slot address, sequence number, RFU, length. This way the trace in phase
 * 0/1 looks like the SICCT traffic from phase 2 on.
 *
 * <p>Sending is asynchronous and in order; a slow or missing proxy holds up no APDU. If the queue
 * runs full, messages are lost. An error is reported once until the push works again.
 */
public final class TrafficPush implements AutoCloseable {

  static final byte C_COMMAND = 0x6B;
  static final byte R_RESPONSE = (byte) 0x83;
  static final String SENDER_HEADER = "tgr-sender";
  static final String RECEIVER = "tgr-receiver";
  static final String TIMESTAMP = "tgr-timestamp";

  /** Sender of the commands and receiver of the responses in the Tiger log. */
  static final String LIANA = "liana";

  /**
   * Sender of the plaintext commands and receiver of the plaintext responses with terminated SM
   * (LIANA-28).
   */
  static final String LIANA_PLAINTEXT = "liana-sm-klartext";

  private static final int QUEUE = 10_000;
  private static final System.Logger LOG = System.getLogger(TrafficPush.class.getName());

  private final URI target;
  private final Duration timeout;
  private final HttpClient http;
  private final ThreadPoolExecutor sender;
  private final AtomicInteger sequence = new AtomicInteger();
  private volatile boolean failing;

  /**
   * {@code proxy} is the base URL of the Tiger proxy (admin port), e.g. {@code http://tiger:18080}.
   */
  public TrafficPush(URI proxy, Duration timeout) {
    this.target = proxy.resolve("/traffic");
    this.timeout = timeout;
    this.http = HttpClient.newBuilder().connectTimeout(timeout).build();
    this.sender =
        new ThreadPoolExecutor(
            1,
            1,
            0,
            TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<>(QUEUE),
            runnable -> {
              Thread thread = new Thread(runnable, "liana-traffic-push");
              thread.setDaemon(true);
              return thread;
            },
            new ThreadPoolExecutor.DiscardPolicy());
  }

  public URI target() {
    return target;
  }

  /** Command to the card in {@code terminal}/{@code slot} and its response: two messages. */
  public void apdu(
      String terminal, int slot, byte[] command, Instant sent, byte[] response, Instant received) {
    int seq = sequence.getAndIncrement() & 0xFFFF;
    String card = address(terminal, slot);
    byte[] commandMessage = envelope(C_COMMAND, slot, seq, command);
    byte[] responseMessage = envelope(R_RESPONSE, slot, seq, response);
    sender.execute(
        () -> {
          post(commandMessage, LIANA, card, sent);
          post(responseMessage, card, LIANA, received);
        });
  }

  /**
   * Plaintext of an SM APDU that LIANA has terminated (LIANA-28): own sender and receiver ({@value
   * #LIANA_PLAINTEXT}, {@code <KT>-sm-klartext:<Slot>}), so that the Tiger log separates it from
   * the ciphertext.
   */
  public void plaintext(
      String terminal, int slot, byte[] command, Instant sent, byte[] response, Instant received) {
    int seq = sequence.getAndIncrement() & 0xFFFF;
    String card = address(terminal + "-sm-klartext", slot);
    byte[] commandMessage = envelope(C_COMMAND, slot, seq, command);
    byte[] responseMessage = envelope(R_RESPONSE, slot, seq, response);
    sender.execute(
        () -> {
          post(commandMessage, LIANA_PLAINTEXT, card, sent);
          post(responseMessage, card, LIANA_PLAINTEXT, received);
        });
  }

  /**
   * Receiver in the format of {@code RbelSocketAddress.fromString}: KT ID as host, slot as port.
   */
  static String address(String terminal, int slot) {
    return terminal + ":" + slot;
  }

  /**
   * SICCT envelope: type, slot address (2 bytes), sequence number (2 bytes), RFU, length (4 bytes),
   * APDU.
   */
  static byte[] envelope(byte type, int slot, int seq, byte[] apdu) {
    return ByteBuffer.allocate(10 + apdu.length)
        .put(type)
        .putShort((short) slot)
        .putShort((short) seq)
        .put((byte) 0)
        .putInt(apdu.length)
        .put(apdu)
        .array();
  }

  private void post(byte[] body, String from, String to, Instant time) {
    HttpRequest request =
        HttpRequest.newBuilder(target)
            .timeout(timeout)
            .header("Content-Type", "application/octet-stream")
            .header(SENDER_HEADER, from)
            .header(RECEIVER, to)
            .header(TIMESTAMP, time.toString())
            .POST(HttpRequest.BodyPublishers.ofByteArray(body))
            .build();
    try {
      int status = http.send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
      if (status / 100 != 2) {
        fail("HTTP " + status);
      } else if (failing) {
        failing = false;
        LOG.log(System.Logger.Level.INFO, "Traffic-Push an " + target + " geht wieder");
      }
    } catch (IOException e) {
      fail(e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage()));
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  private void fail(String reason) {
    if (!failing) {
      failing = true;
      LOG.log(
          System.Logger.Level.WARNING,
          "Traffic-Push an "
              + target
              + " fehlgeschlagen ("
              + reason
              + "); weitere Fehler werden nicht gemeldet, bis der Push wieder geht");
    }
  }

  @Override
  public void close() {
    sender.shutdown();
    try {
      if (!sender.awaitTermination(timeout.toMillis() * 2 + 100, TimeUnit.MILLISECONDS)) {
        sender.shutdownNow();
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      sender.shutdownNow();
    }
    http.close();
  }
}
