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
package de.gematik.liana.kern.card;

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.terminal.TerminalRegistry;

/**
 * ExternalAuthenticate (TIP1-A_5439-02, TAB_KON_781/782) with TUC_KON_218 „Signiere“ ({@link
 * CardSignature}): ECDSA with PrK.HCI.AUT.E256 of the SM-B or PrK.HP.AUT.E256 of the HBAx
 * (TAB_KON_784, both keyIdentifier 06 in DF.ESIGN) over a SHA-256 hash.
 */
public final class ExternalAuthentication {

  /** dss:Base64Signature/@Type of the ECDSA signature. */
  public static final String ECDSA = "urn:bsi:tr:03111:ecdsa";

  private final CardAccess access;
  private final AuthState authState;
  private final CardSignature cardSignature;

  public ExternalAuthentication(
      CardAccess access, TerminalRegistry terminals, AuthState authState) {
    this.access = access;
    this.authState = authState;
    this.cardSignature = new CardSignature(terminals);
  }

  /** TAB_KON_782; {@code binaryString} is the hash (32 bytes for SHA-256). */
  public byte[] sign(Context context, String cardHandle, byte[] binaryString) {
    if (binaryString == null || binaryString.length != 32) {
      throw ConnectorError.SYNTAX.exception(
          "BinaryString muss ein SHA-256-Hash (32 Byte) sein, ist "
              + (binaryString == null ? "leer" : binaryString.length + " Byte"));
    }
    // TAB_KON_782 steps 2 and 3: TUC_KON_000, TUC_KON_026 (4093 while a card session is running,
    // A_25895)
    CardObject card = access.cardSession(context, cardHandle);
    CardType type = card.data().type();
    if (type != CardType.SMC_B && !type.matches("HBAx")) {
      throw ConnectorError.CALL_NOT_ALLOWED.exception(
          type.value() + " hat keinen Schlüssel nach TAB_KON_784");
    }
    // TUC_KON_218 step 3: the PIN that releases the key (PWD(01) in the MF: PIN.SMC or PIN.CH)
    String pin = type == CardType.SMC_B ? "PIN.SMC" : "PIN.CH";
    if (!authState.isVerified(context, cardHandle, pin)) {
      throw ConnectorError.ACCESS_CONDITIONS.exception(
          pin + " in der Kartensitzung nicht verifiziert");
    }
    return cardSignature.sign(card, CardSignature.Key.AUT_E256, binaryString);
  }
}
