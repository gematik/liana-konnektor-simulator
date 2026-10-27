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

import de.gematik.liana.konnektor.ws.conn.cardservicecommon.v2_0.PinResponseType;
import java.math.BigInteger;

/**
 * PIN operations of the CardService (TUC_KON_012 VerifyPin, TUC_KON_022 GetPinStatus, TUC_KON_019
 * ChangePin, TUC_KON_021 UnblockPin, TUC_KON_027 Enable-/DisablePin; LIANA-135), each in the
 * highest matching service version. The user enters the PIN at the card terminal; the calls are
 * {@link Timing#LONG}.
 */
public final class PinScope {

  private final Konnektor kon;
  private final String handle;
  private final String pinType;

  PinScope(Konnektor kon, String handle, String pinType) {
    this.kon = kon;
    this.handle = handle;
    this.pinType = pinType;
  }

  /** GetPinStatus. */
  public PinStatus status() {
    ServiceDirectory.Selection selection = kon.select(Operation.GET_PIN_STATUS);
    Object response =
        kon.invoke(
            selection,
            request(selection, "GetPinStatus"),
            Jaxb.type(selection.binding(), "GetPinStatusResponse"));
    Object status = Jaxb.get(response, "PinStatus");
    BigInteger left = (BigInteger) Jaxb.get(response, "LeftTries");
    return new PinStatus(
        status == null ? null : ((Enum<?>) status).name(), left == null ? null : left.intValue());
  }

  /** VerifyPin. */
  public PinResult verify() {
    return pin(Operation.VERIFY_PIN, "VerifyPin", null);
  }

  /** ChangePin: old and new PIN at the card terminal. */
  public PinResult change() {
    return pin(Operation.CHANGE_PIN, "ChangePin", null);
  }

  /** UnblockPin with PUK, without a new PIN. */
  public PinResult unblock() {
    return unblock(false);
  }

  /** UnblockPin with PUK; with {@code setNewPin} the user sets a new PIN at the same time. */
  public PinResult unblock(boolean setNewPin) {
    return pin(Operation.UNBLOCK_PIN, "UnblockPin", setNewPin);
  }

  /** EnablePin. */
  public PinResult enable() {
    return pin(Operation.ENABLE_PIN, "EnablePin", null);
  }

  /** DisablePin. */
  public PinResult disable() {
    return pin(Operation.DISABLE_PIN, "DisablePin", null);
  }

  private PinResult pin(Operation operation, String name, Boolean setNewPin) {
    ServiceDirectory.Selection selection = kon.select(operation);
    Object request = request(selection, name);
    if (setNewPin != null) {
      Jaxb.set(request, "SetNewPin", setNewPin);
    }
    PinResponseType response = kon.invoke(selection, request, PinResponseType.class);
    return new PinResult(
        response.getPinResult() == null ? null : response.getPinResult().value(),
        response.getLeftTries() == null ? null : response.getLeftTries().intValue());
  }

  private Object request(ServiceDirectory.Selection selection, String name) {
    Object request = Jaxb.request(selection.binding(), name);
    Jaxb.set(request, "Context", Jaxb.context(kon.context()));
    Jaxb.set(request, "CardHandle", handle);
    Jaxb.set(request, "PinTyp", pinType);
    return request;
  }
}
