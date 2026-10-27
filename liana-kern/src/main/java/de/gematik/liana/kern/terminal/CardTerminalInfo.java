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
package de.gematik.liana.kern.terminal;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.zip.CRC32;

/**
 * What GetCardTerminals returns about a CT (TIP1-A_4604, TAB_KON_563, CardTerminalInfoType): only
 * the state managed in the connector, without querying the CT.
 *
 * @param name descriptive name
 * @param macAddress MAC address, bytes separated by {@code -} (schema CT:mac)
 * @param ipAddress IPv4 address; optional in the schema, but Clientsysteme such as the connector
 *     client of the eHealth CT suite require it, hence {@link #UNKNOWN_IP} as long as it is unknown
 * @param slots CT.SLOTCOUNT
 * @param physical IS_PHYSICAL (TAB_KON_522)
 * @param connected availability, for the eHealth CT CT.CONNECTED
 * @param product product information per gemSpec_OM / ProductInformation.xsd
 */
public record CardTerminalInfo(
    String ctId,
    String name,
    String macAddress,
    String ipAddress,
    int slots,
    boolean physical,
    boolean connected,
    Product product) {

  /** IP address of a CT whose address LIANA does not know (yet). */
  public static final String UNKNOWN_IP = "0.0.0.0";

  /** The fake CT runs in the LIANA process. */
  public static final String FAKE_IP = "127.0.0.1";

  public CardTerminalInfo {
    ipAddress = ipAddress == null ? UNKNOWN_IP : ipAddress;
  }

  /** Fields of PI:ProductInformation; versions in the format {@code x.y.z}. */
  public record Product(
      String vendorId,
      String productType,
      String productTypeVersion,
      String productCode,
      String hwVersion,
      String fwVersion,
      String vendorName,
      String productName) {

    /** LIANA's fake CT (decision-3, card engine kartos). */
    public static final Product FAKE =
        new Product(
            "LIANA",
            "eHealth-KT",
            "1.0.0",
            "FAKEKT",
            "1.0.0",
            "1.0.0",
            "gematik",
            "LIANA Fake-Kartenterminal");

    /**
     * From CT.PRODUCTINFORMATION (GET STATUS CTM DO and product information of the CT, SICCT
     * §5.5.10); missing values are filled from {@code fallback}.
     */
    public static Product of(Map<String, String> info, Product fallback) {
      return new Product(
          info.getOrDefault("ProductVendorID", fallback.vendorId()),
          info.getOrDefault("ProductType", fallback.productType()),
          info.getOrDefault("ProductTypeVersion", fallback.productTypeVersion()),
          info.getOrDefault("ProductCode", fallback.productCode()),
          info.getOrDefault("HWVersion", fallback.hwVersion()),
          info.getOrDefault("FWVersion", fallback.fwVersion()),
          info.getOrDefault(
              "ProductVendorName", info.getOrDefault("ProductVendorID", fallback.vendorName())),
          info.getOrDefault(
              "ProductName", info.getOrDefault("ProductCode", fallback.productName())));
    }
  }

  /**
   * Fake CT: name = CtId, a locally administered MAC ({@code 02-…}, stable from the CtId), IP
   * address {@value #FAKE_IP}, physical from the Clientsysteme' point of view and always connected.
   */
  public static CardTerminalInfo fake(String ctId, int slots) {
    return new CardTerminalInfo(
        ctId, ctId, localMac(ctId), FAKE_IP, slots, true, true, Product.FAKE);
  }

  /**
   * {@code 02-4C-xx-xx-xx-xx}: locally administered, unicast, the remaining four bytes from CRC32
   * of the CtId.
   */
  static String localMac(String ctId) {
    CRC32 crc = new CRC32();
    crc.update(ctId.getBytes(StandardCharsets.UTF_8));
    long v = crc.getValue();
    return "02-4C-%02X-%02X-%02X-%02X"
        .formatted((v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF);
  }

  /**
   * {@code 02:00:00:4C:49:01} (SICCT service description) in schema format {@code
   * 02-00-00-4C-49-01}.
   */
  public static String schemaMac(String mac) {
    return mac.replace(':', '-').toUpperCase(java.util.Locale.ROOT);
  }
}
