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
package de.gematik.liana.soap;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Ereignissenke of a Clientsystem like the {@code cetpProxy} of Konnektor-QES, reads CETP messages
 * per connection (TIP1-A_4596). {@link #tls()}: TLS server with the test certificate CS1 ({@code
 * support/pki/clients/cs1-p256.p12}) that requests a client certificate (TIP1-A_4595, TAB_KON_852
 * CETP1); {@link #plain()}: TCP without TLS (CETP2, LIANA-117).
 */
final class CetpReceiver implements AutoCloseable {

  /**
   * A received event message, whether it came via TLS, and the certificate with which the Konnektor
   * authenticated itself ({@code null} without TLS).
   */
  record Message(String xml, boolean tls, X509Certificate client) {}

  private final ServerSocket server;
  private final BlockingQueue<Message> messages = new LinkedBlockingQueue<>();

  private CetpReceiver(ServerSocket server) {
    this.server = server;
    Thread thread = new Thread(this::accept, "cetp-receiver");
    thread.setDaemon(true);
    thread.start();
  }

  /** CETP1: TLS server, requests a client certificate. */
  static CetpReceiver tls() throws Exception {
    KeyStore keys = KeyStore.getInstance("PKCS12", "BC");
    try (InputStream in = Files.newInputStream(Path.of("support/pki/clients/cs1-p256.p12"))) {
      keys.load(in, "liana".toCharArray());
    }
    KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509", "SunJSSE");
    kmf.init(keys, "liana".toCharArray());
    SSLContext context = SSLContext.getInstance("TLSv1.2", "SunJSSE");
    context.init(
        kmf.getKeyManagers(),
        new TrustManager[] {
          new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {}

            @Override
            public X509Certificate[] getAcceptedIssuers() {
              return new X509Certificate[0];
            }
          }
        },
        null);
    SSLServerSocket server =
        (SSLServerSocket)
            context
                .getServerSocketFactory()
                .createServerSocket(0, 10, InetAddress.getLoopbackAddress());
    server.setWantClientAuth(true);
    return new CetpReceiver(server);
  }

  /** CETP2: TCP without TLS. */
  static CetpReceiver plain() throws IOException {
    return new CetpReceiver(new ServerSocket(0, 10, InetAddress.getLoopbackAddress()));
  }

  /** {@code cetp://127.0.0.1:port} for Subscribe. */
  String eventTo() {
    return "cetp://127.0.0.1:" + server.getLocalPort();
  }

  /** Next message or {@code null} after {@code seconds}. */
  Message next(int seconds) throws InterruptedException {
    Message message = messages.poll(seconds, TimeUnit.SECONDS);
    if (message != null && message.xml().startsWith("FEHLER ")) {
      throw new AssertionError(message.xml());
    }
    return message;
  }

  private void accept() {
    while (!server.isClosed()) {
      try (Socket socket = server.accept()) {
        socket.setSoTimeout(5000);
        X509Certificate client = null;
        if (socket instanceof SSLSocket tls) {
          tls.startHandshake();
          try {
            client = (X509Certificate) tls.getSession().getPeerCertificates()[0];
          } catch (SSLPeerUnverifiedException e) {
            // without client certificate
          }
        }
        DataInputStream in = new DataInputStream(socket.getInputStream());
        byte[] magic = new byte[4];
        while (in.read(magic, 0, 1) == 1) {
          in.readFully(magic, 1, 3);
          if (!Arrays.equals(magic, "CETP".getBytes(StandardCharsets.US_ASCII))) {
            throw new IOException("keine CETP-Nachricht: " + Arrays.toString(magic));
          }
          byte[] xml = in.readNBytes(in.readInt());
          messages.add(
              new Message(
                  new String(xml, StandardCharsets.UTF_8), socket instanceof SSLSocket, client));
        }
      } catch (SocketException e) {
        // closed
      } catch (IOException e) {
        messages.add(new Message("FEHLER " + e, false, null));
      }
    }
  }

  @Override
  public void close() throws IOException {
    server.close();
  }
}
