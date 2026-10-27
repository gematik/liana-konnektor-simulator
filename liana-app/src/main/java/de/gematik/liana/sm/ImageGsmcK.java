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
package de.gematik.liana.sm;

import de.gematik.liana.kern.card.GsmcK;
import java.nio.file.Path;
import java.util.HexFormat;

/**
 * Port {@link GsmcK} from the gSMC-K image (LIANA-188): ICCSN from EF.GDO, C.NK.VPN from DF.NK, RSA
 * in EF.C.NK.VPN.R2048, ECC in EF.C.NK.VPN2.XXXX (empty in the gsmc-k image).
 */
public final class ImageGsmcK implements GsmcK {

  private static final HexFormat HEX = HexFormat.of();

  private final ImageObjects image;
  private final String iccsn;

  public ImageGsmcK(Path image) {
    this.image = ImageObjects.load(image);
    byte[] gdo =
        this.image
            .body("EF.GDO")
            .orElseThrow(
                () -> new IllegalArgumentException(image + ": EF.GDO fehlt oder ist leer"));
    // EF.GDO: tag 5A, length, ICCSN (BCD)
    if (gdo.length < 2 || gdo[0] != 0x5A || gdo.length < 2 + gdo[1]) {
      throw new IllegalArgumentException(image + ": EF.GDO ohne ICCSN (Tag 5A)");
    }
    this.iccsn = HEX.formatHex(gdo, 2, 2 + gdo[1]);
  }

  @Override
  public String iccsn() {
    return iccsn;
  }

  @Override
  public byte[] nkVpn(String crypt) {
    return image.body(crypt.equals("RSA") ? "EF.C.NK.VPN.R2048" : "EF.C.NK.VPN2.XXXX").orElse(null);
  }

  @Override
  public String toString() {
    return image.image().getFileName() + " (ICCSN " + iccsn + ")";
  }
}
