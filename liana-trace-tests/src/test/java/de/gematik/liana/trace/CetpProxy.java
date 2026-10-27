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

import java.io.DataInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Ereignissenke like the Tiger proxy {@code cetpProxy} of Konnektor-QES, collects the raw bytes of
 * each message starting at „CETP“. LIANA runs with ANCL_TLS_MANDATORY Disabled and therefore
 * delivers over TCP without TLS (TAB_KON_852 CETP2, LIANA-117); the suites' cetpProxy accepts this
 * just like TLS.
 */
final class CetpProxy implements AutoCloseable {
  private final ServerSocket server;
  private final BlockingQueue<byte[]> messages = new LinkedBlockingQueue<>();

  CetpProxy() throws IOException {
    server = new ServerSocket(0, 10, InetAddress.getLoopbackAddress());
    Thread thread = new Thread(this::accept, "cetp-proxy");
    thread.setDaemon(true);
    thread.start();
  }

  String eventTo() {
    return "cetp://127.0.0.1:" + server.getLocalPort();
  }

  byte[] next(int seconds) throws InterruptedException {
    return messages.poll(seconds, TimeUnit.SECONDS);
  }

  private void accept() {
    while (!server.isClosed()) {
      try (Socket socket = server.accept()) {
        socket.setSoTimeout(5000);
        DataInputStream in = new DataInputStream(socket.getInputStream());
        byte[] header = in.readNBytes(8);
        if (header.length == 8) {
          byte[] xml = in.readNBytes(ByteBuffer.wrap(header, 4, 4).getInt());
          messages.add(ByteBuffer.allocate(8 + xml.length).put(header).put(xml).array());
        }
      } catch (SocketException e) {
        // closed
      } catch (IOException e) {
        // connection aborted; the test waits for the next one
      }
    }
  }

  @Override
  public void close() throws IOException {
    server.close();
  }
}
