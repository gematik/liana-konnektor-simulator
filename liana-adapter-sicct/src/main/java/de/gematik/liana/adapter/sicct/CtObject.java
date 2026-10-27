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

import java.net.InetAddress;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * An entry in CTM_CT_LIST: the attributes of an eHealth card terminal per gemSpec_Kon TAB_KON_522
 * (device data, pairing data, connection data); LIANA does not model the admin credentials. The
 * shared secret appears in the view only as present or absent, CT.SMKT_AUT with subject and SHA-256
 * fingerprint. Changes go through {@link SicctTerminals}; readers get a copy ({@link #snapshot()}).
 */
public final class CtObject {

  /** CT.CORRELATION */
  public enum Correlation {
    BEKANNT,
    ZUGEWIESEN,
    GEPAIRT,
    AKTIV,
    AKTUALISIEREND
  }

  /** CT.DISPLAY_CAPABILITIES from the DSPLC DO (SICCT 1.2.3 §5.5.10.17). */
  public record DisplayCapabilities(
      int visibleCharacters,
      int visibleLines,
      int virtualCharacters,
      int virtualLines,
      boolean beeper) {

    /** As a map for views that do not serialize their own types (Admin API, native image). */
    public Map<String, Object> toMap() {
      Map<String, Object> map = new LinkedHashMap<>();
      map.put("visibleCharacters", visibleCharacters);
      map.put("visibleLines", visibleLines);
      map.put("virtualCharacters", virtualCharacters);
      map.put("virtualLines", virtualLines);
      map.put("beeper", beeper);
      return map;
    }
  }

  private final String ctId;
  private String mac;
  private String hostname;
  private InetAddress ip;
  private int tcpPort;
  private int slotCount;
  private List<Integer> slotsUsed = List.of();
  private Map<String, String> productInformation = Map.of();
  private String ehealthInterfaceVersion;
  private boolean validVersion;
  private DisplayCapabilities displayCapabilities;
  private java.security.cert.X509Certificate smktAut;
  private byte[] sharedSecret;
  private Correlation correlation;
  private boolean connected;
  private String activeRole;

  CtObject(String ctId, String mac, Correlation correlation) {
    this.ctId = ctId;
    this.mac = mac;
    this.correlation = correlation;
  }

  /** Immutable view of all attributes, keys as in TAB_KON_522. */
  public synchronized Map<String, Object> snapshot() {
    Map<String, Object> view = new LinkedHashMap<>();
    view.put("CTID", ctId);
    view.put("IS_PHYSICAL", true);
    view.put("MAC_ADRESS", mac);
    view.put("HOSTNAME", hostname);
    view.put("IP_ADRESS", ip == null ? null : ip.getHostAddress());
    view.put("TCP_PORT", tcpPort);
    view.put("SLOTCOUNT", slotCount);
    view.put("SLOTS_USED", slotsUsed);
    view.put("PRODUCTINFORMATION", productInformation);
    view.put("EHEALTH_INTERFACE_VERSION", ehealthInterfaceVersion);
    view.put("VALID_VERSION", validVersion);
    view.put(
        "DISPLAY_CAPABILITIES", displayCapabilities == null ? null : displayCapabilities.toMap());
    view.put(
        "SMKT_AUT",
        smktAut == null
            ? null
            : Map.of(
                "subject", smktAut.getSubjectX500Principal().getName(),
                "fingerprint", fingerprint(smktAut)));
    view.put("SHARED_SECRET", sharedSecret != null);
    view.put("CORRELATION", correlation.name().toLowerCase(java.util.Locale.ROOT));
    view.put("CONNECTED", connected);
    view.put("ACTIVEROLE", activeRole);
    return java.util.Collections.unmodifiableMap(view);
  }

  public String ctId() {
    return ctId;
  }

  public synchronized String mac() {
    return mac;
  }

  public synchronized String hostname() {
    return hostname;
  }

  public synchronized InetAddress ip() {
    return ip;
  }

  public synchronized int tcpPort() {
    return tcpPort;
  }

  public synchronized int slotCount() {
    return slotCount;
  }

  public synchronized Correlation correlation() {
    return correlation;
  }

  public synchronized boolean validVersion() {
    return validVersion;
  }

  /** CT.PRODUCTINFORMATION from GET STATUS (TUC_KON_055), empty before the first query. */
  public synchronized Map<String, String> productInformation() {
    return productInformation;
  }

  public synchronized boolean connected() {
    return connected;
  }

  public synchronized java.security.cert.X509Certificate smktAut() {
    return smktAut;
  }

  synchronized byte[] sharedSecret() {
    return sharedSecret == null ? null : sharedSecret.clone();
  }

  /** Sets the pairing data or (with {@code null}) deletes it. */
  synchronized void pairing(java.security.cert.X509Certificate smktAut, byte[] sharedSecret) {
    this.smktAut = smktAut;
    this.sharedSecret = sharedSecret == null ? null : sharedSecret.clone();
  }

  /**
   * SHA-256 fingerprint of a certificate, {@code AA:BB:…}, as TUC_KON_053 step 3 shows it to the
   * administrator.
   */
  public static String fingerprint(java.security.cert.X509Certificate certificate) {
    try {
      byte[] digest =
          java.security.MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
      return ServiceDiscovery.mac(digest);
    } catch (java.security.GeneralSecurityException e) {
      throw new IllegalStateException("Fingerprint nicht berechenbar", e);
    }
  }

  synchronized void address(InetAddress ip, int tcpPort, String hostname) {
    this.ip = ip;
    this.tcpPort = tcpPort;
    this.hostname = hostname;
  }

  synchronized void mac(String mac) {
    this.mac = mac;
  }

  synchronized void correlation(Correlation correlation) {
    this.correlation = correlation;
  }

  synchronized void connected(boolean connected, String role) {
    this.connected = connected;
    this.activeRole = connected ? role : null;
  }

  synchronized void status(GetStatus.Terminal status, boolean validVersion) {
    this.slotCount = status.slotCount();
    this.slotsUsed = status.slotsUsed();
    this.productInformation = status.productInformation();
    this.ehealthInterfaceVersion = status.ehealthInterfaceVersion();
    this.displayCapabilities = status.display();
    this.validVersion = validVersion;
  }
}
