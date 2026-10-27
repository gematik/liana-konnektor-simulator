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
package de.gematik.liana.adapter.sicct;

import de.gematik.liana.kern.terminal.CardTimeoutException;
import de.gematik.liana.kern.terminal.TerminalConnectionListener;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * A SICCT connection to an eHealth card terminal over an already established (TLS) socket
 * (TUC_KON_050 step 3).
 *
 * <p>A reader thread receives the envelopes: it matches R-commands to the waiting {@link #transmit}
 * via the sequence number (SICCT 1.2.3 §6.2.4.3: the R-command carries the address and sequence
 * number of the C-command), and passes event messages (§6.2.4.4) to {@code events}. If the data
 * stream ends, breaks off or the connection is closed, all waiting commands fail with {@link
 * IOException} and the core learns of it exactly once via {@link
 * TerminalConnectionListener#ctDisconnected} (TIP1-A_4537).
 */
public final class SicctConnection implements AutoCloseable {

  private static final System.Logger LOG = System.getLogger(SicctConnection.class.getName());

  private final String ctId;
  private final String hostname;
  private final Socket socket;
  private final OutputStream out;
  private final Consumer<SicctEnvelope> events;
  private final TerminalConnectionListener connection;
  private final Map<Integer, CompletableFuture<SicctEnvelope>> pending = new ConcurrentHashMap<>();
  private final AtomicBoolean closed = new AtomicBoolean();
  private final Thread reader;
  private int nextSeq = 1;
  private volatile String closeReason;
  private volatile long lastReceived = System.nanoTime();
  private volatile long lastCommand = System.nanoTime();

  /**
   * Takes over {@code socket} (TLS handshake completed) and starts the reader thread.
   *
   * @param events event messages of the card terminal, called in the reader thread
   * @param connection is notified of the end of the connection
   */
  public SicctConnection(
      String ctId,
      String hostname,
      Socket socket,
      Consumer<SicctEnvelope> events,
      TerminalConnectionListener connection)
      throws IOException {
    this.ctId = ctId;
    this.hostname = hostname;
    this.socket = socket;
    this.out = socket.getOutputStream();
    this.events = events;
    this.connection = connection;
    InputStream in = socket.getInputStream();
    this.reader = new Thread(() -> read(in), "liana-sicct-" + ctId);
    reader.setDaemon(true);
    reader.start();
  }

  public String ctId() {
    return ctId;
  }

  /**
   * How long nothing has arrived from the card terminal, neither response nor event (keep-alive,
   * TIP1-A_4536).
   */
  public java.time.Duration quietFor() {
    return java.time.Duration.ofNanos(System.nanoTime() - lastReceived);
  }

  /**
   * How long LIANA has not sent a command. A card terminal with KEEP ALIVE drops the connection
   * after 120 s without a command (SICCT 1.2.3 §6.2.4.5), so the heartbeat is based on this and not
   * on {@link #quietFor()}.
   */
  public java.time.Duration sinceLastCommand() {
    return java.time.Duration.ofNanos(System.nanoTime() - lastCommand);
  }

  /** Whether the connection still exists (CT.CONNECTED from the transport's point of view). */
  public boolean connected() {
    return !closed.get();
  }

  /**
   * Sends {@code apdu} as a C-command to {@code fu} and returns abCmd of the R-command (data and
   * status word).
   *
   * @throws CardTimeoutException without a response within {@code timeout}
   * @throws IOException if the connection ends or has already ended
   */
  public byte[] transmit(int fu, byte[] apdu, Duration timeout) throws IOException {
    if (closed.get()) {
      throw new IOException(ctId + ": SICCT-Verbindung beendet (" + closeReason + ")");
    }
    CompletableFuture<SicctEnvelope> response = new CompletableFuture<>();
    int seq;
    synchronized (out) {
      seq = allocate(response);
      try {
        out.write(SicctEnvelope.command(fu, seq, apdu).encode());
        out.flush();
        lastCommand = System.nanoTime();
      } catch (IOException e) {
        pending.remove(seq);
        close("Senden fehlgeschlagen: " + e.getMessage());
        throw e;
      }
    }
    if (closed.get()) {
      // The reader thread may have terminated between the check and the entry.
      response.completeExceptionally(
          new IOException(ctId + ": SICCT-Verbindung beendet (" + closeReason + ")"));
    }
    try {
      return response.get(timeout.toMillis(), TimeUnit.MILLISECONDS).payload();
    } catch (TimeoutException e) {
      pending.remove(seq);
      throw new CardTimeoutException(
          String.format(
              "%s: keine Antwort auf seq %04X an FU %04X nach %d ms",
              ctId, seq, fu, timeout.toMillis()));
    } catch (ExecutionException e) {
      throw e.getCause() instanceof IOException io ? io : new IOException(e.getCause());
    } catch (InterruptedException e) {
      pending.remove(seq);
      Thread.currentThread().interrupt();
      throw new java.io.InterruptedIOException(ctId + ": Warten auf SICCT-Antwort unterbrochen");
    }
  }

  /** Next free command sequence number 0001–FCFF; called under the send lock. */
  private int allocate(CompletableFuture<SicctEnvelope> response) throws IOException {
    for (int tries = 0; tries < SicctEnvelope.MAX_COMMAND_SEQ; tries++) {
      int seq = nextSeq;
      nextSeq = seq == SicctEnvelope.MAX_COMMAND_SEQ ? 1 : seq + 1;
      if (pending.putIfAbsent(seq, response) == null) {
        return seq;
      }
    }
    throw new IOException(ctId + ": keine freie SICCT-Sequenznummer");
  }

  private void read(InputStream in) {
    String reason = "Verbindung vom KT geschlossen";
    try {
      for (SicctEnvelope envelope; (envelope = SicctEnvelope.read(in)) != null; ) {
        lastReceived = System.nanoTime();
        switch (envelope.type()) {
          case R_COMMAND -> {
            CompletableFuture<SicctEnvelope> waiting = pending.remove(envelope.seq());
            if (waiting == null) {
              LOG.log(
                  System.Logger.Level.WARNING,
                  ctId + ": R-Kommando ohne offenes Kommando: " + envelope);
            } else {
              waiting.complete(envelope);
            }
          }
          case EVENT -> deliver(envelope);
          case C_COMMAND ->
              LOG.log(
                  System.Logger.Level.WARNING, ctId + ": C-Kommando vom KT ignoriert: " + envelope);
        }
      }
    } catch (IOException e) {
      reason = closed.get() ? closeReason : "Lesefehler: " + e.getMessage();
    }
    close(reason);
  }

  private void deliver(SicctEnvelope event) {
    try {
      events.accept(event);
    } catch (RuntimeException e) {
      LOG.log(System.Logger.Level.WARNING, ctId + ": Ereignis " + event + " nicht verarbeitet", e);
    }
  }

  /** Closes the connection; waiting commands fail, the core is notified (once). */
  @Override
  public void close() {
    close("vom Konnektor beendet");
  }

  /** Closes the connection with {@code reason} for the log. */
  public void close(String reason) {
    if (!closed.compareAndSet(false, true)) {
      return;
    }
    closeReason = reason;
    try {
      socket.close();
    } catch (IOException e) {
      LOG.log(System.Logger.Level.DEBUG, ctId + ": Schließen: " + e.getMessage());
    }
    IOException failure = new IOException(ctId + ": SICCT-Verbindung beendet (" + reason + ")");
    pending.values().forEach(waiting -> waiting.completeExceptionally(failure));
    pending.clear();
    LOG.log(System.Logger.Level.INFO, "CT/DISCONNECTED " + ctId + " (" + hostname + "): " + reason);
    connection.ctDisconnected(ctId, hostname, reason);
  }
}
