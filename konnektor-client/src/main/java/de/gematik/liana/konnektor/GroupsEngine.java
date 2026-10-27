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

import java.nio.ByteBuffer;
import java.util.List;
import java.util.function.BiFunction;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import org.bouncycastle.jsse.BCSSLEngine;
import org.bouncycastle.jsse.BCSSLParameters;

/**
 * BCJSSE engine that sets the TLS groups and signature schemes from {@link ClientTls} again after
 * every {@link #setSSLParameters} (LIANA-133); otherwise BCJSSE falls back to its default without
 * brainpoolP256r1.
 */
final class GroupsEngine extends SSLEngine {

  private final SSLEngine delegate;

  GroupsEngine(SSLEngine delegate) {
    super(delegate.getPeerHost(), delegate.getPeerPort());
    this.delegate = delegate;
    restrict();
  }

  private void restrict() {
    BCSSLEngine bc = (BCSSLEngine) delegate;
    BCSSLParameters parameters = bc.getParameters();
    parameters.setNamedGroups(ClientTls.NAMED_GROUPS);
    parameters.setSignatureSchemes(ClientTls.SIGNATURE_SCHEMES);
    bc.setParameters(parameters);
  }

  @Override
  public void setSSLParameters(SSLParameters params) {
    delegate.setSSLParameters(params);
    restrict();
  }

  @Override
  public SSLParameters getSSLParameters() {
    return delegate.getSSLParameters();
  }

  @Override
  public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst)
      throws SSLException {
    return delegate.wrap(srcs, offset, length, dst);
  }

  @Override
  public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length)
      throws SSLException {
    return delegate.unwrap(src, dsts, offset, length);
  }

  @Override
  public Runnable getDelegatedTask() {
    return delegate.getDelegatedTask();
  }

  @Override
  public void closeInbound() throws SSLException {
    delegate.closeInbound();
  }

  @Override
  public boolean isInboundDone() {
    return delegate.isInboundDone();
  }

  @Override
  public void closeOutbound() {
    delegate.closeOutbound();
  }

  @Override
  public boolean isOutboundDone() {
    return delegate.isOutboundDone();
  }

  @Override
  public String[] getSupportedCipherSuites() {
    return delegate.getSupportedCipherSuites();
  }

  @Override
  public String[] getEnabledCipherSuites() {
    return delegate.getEnabledCipherSuites();
  }

  @Override
  public void setEnabledCipherSuites(String[] suites) {
    delegate.setEnabledCipherSuites(suites);
  }

  @Override
  public String[] getSupportedProtocols() {
    return delegate.getSupportedProtocols();
  }

  @Override
  public String[] getEnabledProtocols() {
    return delegate.getEnabledProtocols();
  }

  @Override
  public void setEnabledProtocols(String[] protocols) {
    delegate.setEnabledProtocols(protocols);
  }

  @Override
  public SSLSession getSession() {
    return delegate.getSession();
  }

  @Override
  public SSLSession getHandshakeSession() {
    return delegate.getHandshakeSession();
  }

  @Override
  public void beginHandshake() throws SSLException {
    delegate.beginHandshake();
  }

  @Override
  public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
    return delegate.getHandshakeStatus();
  }

  @Override
  public void setUseClientMode(boolean mode) {
    delegate.setUseClientMode(mode);
  }

  @Override
  public boolean getUseClientMode() {
    return delegate.getUseClientMode();
  }

  @Override
  public void setNeedClientAuth(boolean need) {
    delegate.setNeedClientAuth(need);
  }

  @Override
  public boolean getNeedClientAuth() {
    return delegate.getNeedClientAuth();
  }

  @Override
  public void setWantClientAuth(boolean want) {
    delegate.setWantClientAuth(want);
  }

  @Override
  public boolean getWantClientAuth() {
    return delegate.getWantClientAuth();
  }

  @Override
  public void setEnableSessionCreation(boolean flag) {
    delegate.setEnableSessionCreation(flag);
  }

  @Override
  public boolean getEnableSessionCreation() {
    return delegate.getEnableSessionCreation();
  }

  @Override
  public String getApplicationProtocol() {
    return delegate.getApplicationProtocol();
  }

  @Override
  public String getHandshakeApplicationProtocol() {
    return delegate.getHandshakeApplicationProtocol();
  }

  @Override
  public void setHandshakeApplicationProtocolSelector(
      BiFunction<SSLEngine, List<String>, String> selector) {
    delegate.setHandshakeApplicationProtocolSelector(selector);
  }

  @Override
  public BiFunction<SSLEngine, List<String>, String> getHandshakeApplicationProtocolSelector() {
    return delegate.getHandshakeApplicationProtocolSelector();
  }
}
