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

import java.security.KeyManagementException;
import java.security.SecureRandom;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

/**
 * {@code SSLContext} over a BCJSSE context whose engines carry the TLS groups and signature schemes
 * from {@link ClientTls} (LIANA-133). The JDK {@code HttpClient} creates its engines only via
 * {@link SSLContext#createSSLEngine(String, int)}.
 */
final class GroupsContext extends SSLContext {

  GroupsContext(SSLContext delegate) {
    super(new Spi(delegate), delegate.getProvider(), delegate.getProtocol());
  }

  private static final class Spi extends SSLContextSpi {

    private final SSLContext delegate;

    Spi(SSLContext delegate) {
      this.delegate = delegate;
    }

    @Override
    protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr)
        throws KeyManagementException {
      delegate.init(km, tm, sr);
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {
      return delegate.getSocketFactory();
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory() {
      return delegate.getServerSocketFactory();
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {
      return new GroupsEngine(delegate.createSSLEngine());
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String host, int port) {
      return new GroupsEngine(delegate.createSSLEngine(host, port));
    }

    @Override
    protected SSLSessionContext engineGetServerSessionContext() {
      return delegate.getServerSessionContext();
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext() {
      return delegate.getClientSessionContext();
    }

    @Override
    protected SSLParameters engineGetDefaultSSLParameters() {
      return delegate.getDefaultSSLParameters();
    }

    @Override
    protected SSLParameters engineGetSupportedSSLParameters() {
      return delegate.getSupportedSSLParameters();
    }
  }
}
