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
package de.gematik.liana.konnektor;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLSocket;

/**
 * TLS 1.2 server for the client tests with the test identities from {@code support/pki/server}
 * (ID.AK.AUT p256, bp256, rsa): restricted to one ECDHE group, optionally with client
 * authentication. Answers every request with {@code body} and remembers request lines and headers.
 */
final class TlsServer implements AutoCloseable {

  static final Path SERVER = Path.of("support/pki/server");
  static final Path CLIENTS = Path.of("support/pki/clients");
  static final char[] PASSWORD = "liana".toCharArray();

  private final SSLServerSocket socket;
  private final Thread thread;
  private final List<String> requests = new ArrayList<>();
  volatile String negotiatedGroup;
  volatile X509Certificate clientCertificate;

  TlsServer(String identity, String group, boolean clientAuth, int status, byte[] body)
      throws Exception {
    KeyStore store = KeyStore.getInstance("PKCS12", Bc.PROVIDER);
    try (InputStream in = Files.newInputStream(SERVER.resolve(identity))) {
      store.load(in, PASSWORD);
    }
    KeyManagerFactory keys = KeyManagerFactory.getInstance("PKIX", Bc.JSSE);
    keys.init(store, PASSWORD);
    SSLContext context = SSLContext.getInstance("TLSv1.2", Bc.JSSE);
    context.init(keys.getKeyManagers(), new TrustManager[] {new AcceptAll()}, new SecureRandom());
    socket =
        (SSLServerSocket)
            context
                .getServerSocketFactory()
                .createServerSocket(0, 5, InetAddress.getLoopbackAddress());
    thread = new Thread(() -> serve(group, clientAuth, status, body), "tls-server");
    thread.setDaemon(true);
    thread.start();
  }

  int port() {
    return socket.getLocalPort();
  }

  synchronized List<String> requests() {
    return List.copyOf(requests);
  }

  private void serve(String group, boolean clientAuth, int status, byte[] body) {
    while (!socket.isClosed()) {
      try (SSLSocket client = (SSLSocket) socket.accept()) {
        BCSSLSocket bc = (BCSSLSocket) client;
        BCSSLParameters parameters = bc.getParameters();
        parameters.setNamedGroups(new String[] {group});
        parameters.setNeedClientAuth(clientAuth);
        bc.setParameters(parameters);
        client.startHandshake();
        negotiatedGroup = group;
        if (clientAuth) {
          clientCertificate = (X509Certificate) client.getSession().getPeerCertificates()[0];
        }
        BufferedReader reader =
            new BufferedReader(
                new InputStreamReader(client.getInputStream(), StandardCharsets.ISO_8859_1));
        StringBuilder request = new StringBuilder();
        int length = 0;
        for (String line = reader.readLine();
            line != null && !line.isEmpty();
            line = reader.readLine()) {
          request.append(line).append('\n');
          if (line.toLowerCase().startsWith("content-length:")) {
            length = Integer.parseInt(line.substring(15).trim());
          }
        }
        char[] content = new char[length];
        for (int read = 0; read < length; ) {
          int n = reader.read(content, read, length - read);
          if (n < 0) {
            break;
          }
          read += n;
        }
        synchronized (this) {
          requests.add(request + "\n" + new String(content));
        }
        OutputStream out = client.getOutputStream();
        out.write(
            ("HTTP/1.1 "
                    + status
                    + " X\r\nContent-Type: text/xml\r\nContent-Length: "
                    + body.length
                    + "\r\nConnection: close\r\n\r\n")
                .getBytes(StandardCharsets.ISO_8859_1));
        out.write(body);
        out.flush();
      } catch (Exception e) {
        // Handshake errors are part of the tests
      }
    }
  }

  @Override
  public void close() throws Exception {
    socket.close();
    thread.join(2000);
  }

  private static final class AcceptAll implements X509TrustManager {
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {}

    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return new X509Certificate[0];
    }
  }
}
