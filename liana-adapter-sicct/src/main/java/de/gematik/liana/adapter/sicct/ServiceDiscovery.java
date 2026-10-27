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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/**
 * Packets of SICCT service discovery, protocol version 1.20 (SICCT 1.2.3 §6.2.3): service enquiry
 * (table 13) of the Konnektor and service announcement (table 14) of the card terminal, each a TLV
 * packet over UDP.
 */
public final class ServiceDiscovery {

  /** §6.2.3: protocol version 1.20 in network byte order. */
  static final byte[] PROTOCOL_VERSION = {0x01, 0x14};

  private static final int ENQUIRY = 0xA0;
  private static final int ANNOUNCEMENT = 0xA1;
  private static final int VERSION = 0x80;
  private static final int IP = 0x81;
  private static final int PORT = 0x82;
  private static final int MAC = 0x83;
  private static final int NAME = 0x84;
  private static final int SECURITY = 0xA3;
  private static final int TLS = 0x8A;

  private ServiceDiscovery() {}

  /**
   * Service description of a card terminal (table 14).
   *
   * @param ip IP address of the card terminal
   * @param mac MAC address, {@code AA:BB:CC:DD:EE:FF}
   * @param name SICCT terminal name (CT.HOSTNAME)
   * @param port TCP port of the command interpreter
   * @param tlsVersions bytes of the offered TLS versions ({@code 30} = TLS 1.2); empty =
   *     unencrypted
   */
  public record Announcement(
      InetAddress ip, String mac, String name, int port, List<Integer> tlsVersions) {}

  /**
   * Service enquiry (table 13): the card terminals respond to {@code clientIp}:{@code clientPort}.
   */
  public static byte[] enquiry(InetAddress clientIp, int clientPort) {
    ByteArrayOutputStream content = new ByteArrayOutputStream();
    content.writeBytes(new Tlv(VERSION, PROTOCOL_VERSION).encode());
    content.writeBytes(new Tlv(IP, clientIp.getAddress()).encode());
    content.writeBytes(
        new Tlv(PORT, new byte[] {(byte) (clientPort >> 8), (byte) clientPort}).encode());
    return new Tlv(ENQUIRY, content.toByteArray()).encode();
  }

  /** Reads a service description; IOException for a service enquiry or an incomplete packet. */
  public static Announcement announcement(byte[] packet) throws IOException {
    List<Tlv> outer = Tlv.parse(packet);
    if (outer.size() != 1 || outer.getFirst().tag() != ANNOUNCEMENT) {
      throw new IOException("keine Dienstbeschreibung (A1): " + HexFormat.of().formatHex(packet));
    }
    List<Tlv> fields = Tlv.parse(outer.getFirst().value());
    byte[] ip = required(fields, IP, 4);
    byte[] mac = required(fields, MAC, 6);
    byte[] port = required(fields, PORT, 2);
    String name = new String(required(fields, NAME, -1), StandardCharsets.US_ASCII);
    List<Integer> tls = new ArrayList<>();
    for (Tlv security : fields.stream().filter(f -> f.tag() == SECURITY).toList()) {
      for (Tlv version : Tlv.parse(security.value())) {
        if (version.tag() == TLS && version.value().length == 1) {
          tls.add(version.value()[0] & 0xFF);
        }
      }
    }
    return new Announcement(
        ipv4(ip), mac(mac), name, ((port[0] & 0xFF) << 8) | (port[1] & 0xFF), tls);
  }

  /** A service description as a packet, for tests and test card terminals. */
  public static byte[] encode(Announcement announcement) {
    ByteArrayOutputStream content = new ByteArrayOutputStream();
    content.writeBytes(new Tlv(VERSION, PROTOCOL_VERSION).encode());
    content.writeBytes(new Tlv(IP, announcement.ip().getAddress()).encode());
    content.writeBytes(
        new Tlv(MAC, HexFormat.of().parseHex(announcement.mac().replace(":", ""))).encode());
    content.writeBytes(
        new Tlv(NAME, announcement.name().getBytes(StandardCharsets.US_ASCII)).encode());
    int port = announcement.port();
    content.writeBytes(new Tlv(PORT, new byte[] {(byte) (port >> 8), (byte) port}).encode());
    if (!announcement.tlsVersions().isEmpty()) {
      ByteArrayOutputStream security = new ByteArrayOutputStream();
      announcement
          .tlsVersions()
          .forEach(v -> security.writeBytes(new Tlv(TLS, new byte[] {v.byteValue()}).encode()));
      content.writeBytes(new Tlv(SECURITY, security.toByteArray()).encode());
    }
    return new Tlv(ANNOUNCEMENT, content.toByteArray()).encode();
  }

  private static byte[] required(List<Tlv> fields, int tag, int length) throws IOException {
    byte[] value =
        Tlv.find(fields, tag)
            .orElseThrow(
                () ->
                    new IOException(String.format("Dienstbeschreibung ohne Pflichtfeld %02X", tag)))
            .value();
    if (length >= 0 && value.length != length) {
      throw new IOException(
          String.format(
              "Dienstbeschreibung: Feld %02X hat %d statt %d Byte", tag, value.length, length));
    }
    return value;
  }

  private static InetAddress ipv4(byte[] address) throws IOException {
    try {
      return (Inet4Address) InetAddress.getByAddress(address);
    } catch (UnknownHostException e) {
      throw new IOException("Dienstbeschreibung: IP-Adresse unlesbar", e);
    }
  }

  static String mac(byte[] mac) {
    StringBuilder text = new StringBuilder();
    for (byte b : mac) {
      if (!text.isEmpty()) {
        text.append(':');
      }
      text.append(String.format("%02X", b));
    }
    return text.toString();
  }
}
