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

import static de.gematik.liana.sm.Apdus.apdu;
import static de.gematik.liana.sm.Apdus.concat;
import static de.gematik.liana.sm.Apdus.tlv;

import de.gematik.liana.kern.card.CardToCard;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.terminal.CardTerminal;
import de.gematik.liana.kern.terminal.SecureChannel;
import java.io.IOException;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;

/**
 * Port {@link CardToCard} with LIANA as source card (LIANA-112.13): the gSMC-K from {@code
 * infrastructure.konnektor.gsmc-k.image}, the gSMC-KT per KT from {@code
 * infrastructure.terminals.<id>.gsmc-kt}, each with the keys from its image ({@link
 * TerminalIdentity}); cross CVCs from the TSL. The target card checks the chain; LIANA takes the
 * public key from its end-entity CVC without checking its chain.
 */
public final class ImageCardToCard implements CardToCard {

  private static final System.Logger LOG = System.getLogger(ImageCardToCard.class.getName());
  private static final HexFormat HEX = HexFormat.of().withUpperCase();

  /** algId elcSessionkey4SM in MSE SET AT (tag 80). */
  private static final int ELC_SESSIONKEY_4_SM = 0x54;

  private final Optional<TerminalIdentity> gsmcK;
  private final Map<String, TerminalIdentity> gsmcKts;

  public ImageCardToCard(Optional<TerminalIdentity> gsmcK, Map<String, TerminalIdentity> gsmcKts) {
    this.gsmcK = gsmcK;
    this.gsmcKts = Map.copyOf(gsmcKts);
  }

  @Override
  public boolean available(Source source, String ctId, StringBuilder why) {
    boolean available = identity(source, ctId).isPresent();
    if (!available) {
      why.append(
          source == Source.GSMC_K
              ? "kein gSMC-K-Image (infrastructure.konnektor.gsmc-k.image)"
              : "keine gSMC-KT an " + ctId + " (infrastructure.terminals." + ctId + ".gsmc-kt)");
    }
    return available;
  }

  @Override
  public SecureChannel authenticate(Source source, CardTerminal terminal, int slot, Target target)
      throws IOException {
    TerminalIdentity identity =
        identity(source, terminal.id())
            .orElseThrow(
                () ->
                    ConnectorError.C2C_SOURCE_FAILED.exception(
                        source + " an " + terminal.id() + " fehlt"));
    Cvc cvc;
    try {
      cvc = Cvc.parse(target.cvc());
    } catch (IllegalArgumentException e) {
      throw ConnectorError.C2C_TARGET_FAILED.exception("CVC der Zielkarte: " + e.getMessage());
    }
    // MSE SET AT (gemSpec_COS 14.9.9.2): private key of the target card (84), algId
    // elcSessionkey4SM (80)
    byte[] setAt =
        apdu(
            0x00,
            0x22,
            0x41,
            0xA4,
            concat(
                tlv(0x84, new byte[] {(byte) target.keyReference()}),
                tlv(0x80, new byte[] {ELC_SESSIONKEY_4_SM})));
    SecureMessaging.Session session;
    try {
      session =
          SourceCard.authenticate(
              terminal, slot, identity, identity.chains(), setAt, cvc.publicKey());
    } catch (SourceCard.Failed e) {
      throw ConnectorError.C2C_TARGET_FAILED.exception(
          terminal.id() + "/" + slot + " " + source + ": " + e.getMessage());
    }
    LOG.log(
        System.Logger.Level.INFO,
        "{0}/{1}: Trusted Channel {2} mit CHR {3} zur Karte CHR {4}",
        terminal.id(),
        slot,
        source,
        HEX.formatHex(identity.endEntity().chr()),
        HEX.formatHex(cvc.chr()));
    return new SmChannel(session);
  }

  private Optional<TerminalIdentity> identity(Source source, String ctId) {
    return source == Source.GSMC_K ? gsmcK : Optional.ofNullable(gsmcKts.get(ctId));
  }
}
