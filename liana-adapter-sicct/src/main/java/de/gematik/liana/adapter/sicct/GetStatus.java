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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * SICCT GET STATUS ({@code 80 13 P1 P2}, SICCT 1.2.3 §5.15) for TUC_KON_055 "Befülle CT-Object"
 * (populate CT object): CT.SLOTCOUNT and CT.SLOTS_USED from the CTS DO ({@code P2=63}),
 * CT.PRODUCTINFORMATION and CT.EHEALTH_INTERFACE_VERSION from the CTM DO ({@code 46}) with the
 * Discretionary Data DO (gemSpec_KT TIP1-A_3118, DO_KT_0001/0002), CT.DISPLAY_CAPABILITIES from the
 * DSPLC DO ({@code 67}, §5.5.10.17).
 */
public final class GetStatus {

  /** GET STATUS to the terminal with data object {@code p2}. */
  public static byte[] command(int p2) {
    return new byte[] {(byte) 0x80, 0x13, 0x00, (byte) p2, 0x00};
  }

  public static final int CTS_DO = 0x63;
  public static final int CTM_DO = 0x46;
  public static final int DSPLC_DO = 0x67;
  private static final int FU_DO = 0x81;
  private static final int ICCS_DO = 0x80;
  private static final int DD_DO = 0xD7;

  /** ICCS: no card (SICCT §5.5.10.7). */
  private static final int ICC_ABSENT = 0x00;

  private GetStatus() {}

  /** What TUC_KON_055 step 2 writes from GET STATUS into the CT object. */
  public record Terminal(
      int slotCount,
      List<Integer> slotsUsed,
      Map<String, String> productInformation,
      String ehealthInterfaceVersion,
      CtObject.DisplayCapabilities display) {}

  /**
   * Evaluates the responses to GET STATUS CTS DO, CTM DO and DSPLC DO (each abCmd with status
   * word). A DSPLC DO may be missing (§5.5.10.17: "darf unterstützt werden"), then
   * CT.DISPLAY_CAPABILITIES stays empty.
   */
  public static Terminal parse(byte[] cts, byte[] ctm, byte[] dsplc) throws IOException {
    List<Tlv> ctsDo =
        Tlv.parse(
            Tlv.find(Tlv.parse(body(cts, "CTS DO")), CTS_DO)
                .orElseThrow(() -> new IOException("GET STATUS: kein CTS DO"))
                .value());
    byte[] fus = Tlv.find(ctsDo, FU_DO).map(Tlv::value).orElse(new byte[0]);
    byte[] iccs = Tlv.find(ctsDo, ICCS_DO).map(Tlv::value).orElse(new byte[0]);
    List<Integer> slots = new ArrayList<>();
    for (int i = 0; i + 1 < fus.length; i += 2) {
      // FU number: type 00, index n = ICC n (table 16)
      if (fus[i] == 0 && fus[i + 1] != 0) {
        slots.add(fus[i + 1] & 0xFF);
      }
    }
    List<Integer> used = new ArrayList<>();
    for (int i = 0; i < Math.min(iccs.length, slots.size()); i++) {
      if ((iccs[i] & 0xFF) != ICC_ABSENT) {
        used.add(slots.get(i));
      }
    }

    byte[] ctmDo =
        Tlv.find(Tlv.parse(body(ctm, "CTM DO")), CTM_DO)
            .orElseThrow(() -> new IOException("GET STATUS: kein CTM DO"))
            .value();
    if (ctmDo.length < 15) {
      throw new IOException("GET STATUS: CTM DO zu kurz");
    }
    Map<String, String> product = new LinkedHashMap<>();
    product.put("ProductVendorID", ascii(ctmDo, 0, 5));
    product.put("ProductType", ascii(ctmDo, 5, 5));
    product.put("SoftwareVersion", ascii(ctmDo, 10, 5));
    String version = null;
    Optional<Tlv> dd = Tlv.find(Tlv.parse(Arrays.copyOfRange(ctmDo, 15, ctmDo.length)), DD_DO);
    if (dd.isPresent()) {
      byte[] d = dd.get().value();
      // DO_KT_0002: VER 9, PT 2, PTV 9, MODN 8, FWV 9, HWV 9, FWG 5, VEN
      version = version(raw(d, 0, 9));
      product.put("ProductCode", ascii(d, 20, 8));
      product.put("ProductTypeVersion", version(raw(d, 11, 9)));
      product.put("FWVersion", version(raw(d, 28, 9)));
      product.put("HWVersion", version(raw(d, 37, 9)));
    }

    CtObject.DisplayCapabilities display = null;
    if (dsplc != null && dsplc.length >= 2 && ok(dsplc)) {
      Optional<Tlv> dsplcDo = Tlv.find(Tlv.parse(body(dsplc, "DSPLC DO")), DSPLC_DO);
      if (dsplcDo.isPresent()) {
        List<Tlv> fields = Tlv.parse(dsplcDo.get().value());
        display =
            new CtObject.DisplayCapabilities(
                number(fields, 0x80),
                number(fields, 0x81),
                number(fields, 0x82),
                number(fields, 0x83),
                (number(fields, 0x84) & 0x01) != 0);
      }
    }
    return new Terminal(slots.size(), List.copyOf(used), product, version, display);
  }

  /**
   * {@code " 1 0 0"} → {@code "1.0.0"}: three right-aligned groups of three (DD DO, element VER);
   * anything else is returned unchanged.
   */
  static String version(String field) {
    if (field.length() != 9) {
      return field.trim();
    }
    return field.substring(0, 3).trim()
        + "."
        + field.substring(3, 6).trim()
        + "."
        + field.substring(6, 9).trim();
  }

  /**
   * TUC_KON_055 step 3: supported if an entry of CTM_SUPPORTED_KT_VERSIONS has the same major and
   * minor version and its third component is not greater.
   */
  public static boolean supported(String version, List<String> supportedVersions) {
    if (version == null) {
      return false;
    }
    String[] kt = version.split("\\.");
    for (String entry : supportedVersions) {
      String[] supported = entry.split("\\.");
      if (kt.length == 3
          && supported.length == 3
          && kt[0].equals(supported[0])
          && kt[1].equals(supported[1])) {
        try {
          return Integer.parseInt(kt[2]) >= Integer.parseInt(supported[2]);
        } catch (NumberFormatException e) {
          return false;
        }
      }
    }
    return false;
  }

  private static boolean ok(byte[] response) {
    return (response[response.length - 2] & 0xFF) == 0x90 && response[response.length - 1] == 0;
  }

  private static byte[] body(byte[] response, String what) throws IOException {
    if (response.length < 2 || !ok(response)) {
      throw new IOException(
          "GET STATUS "
              + what
              + ": Statuswort "
              + java.util.HexFormat.of()
                  .withUpperCase()
                  .formatHex(response, Math.max(0, response.length - 2), response.length));
    }
    return Arrays.copyOf(response, response.length - 2);
  }

  private static String raw(byte[] bytes, int offset, int length) {
    if (offset + length > bytes.length) {
      return "";
    }
    return new String(bytes, offset, length, StandardCharsets.US_ASCII);
  }

  private static String ascii(byte[] bytes, int offset, int length) {
    return raw(bytes, offset, length).trim();
  }

  private static int number(List<Tlv> fields, int tag) {
    return Tlv.find(fields, tag)
        .map(Tlv::value)
        .filter(v -> v.length == 1)
        .map(v -> v[0] & 0xFF)
        .orElse(0);
  }
}
