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

import de.gematik.liana.konnektor.ws.conn.signatureservice.v7_5.ActivateComfortSignature;
import de.gematik.liana.konnektor.ws.conn.signatureservice.v7_5.ActivateComfortSignatureResponse;
import de.gematik.liana.konnektor.ws.conn.signatureservice.v7_5.DeactivateComfortSignature;
import de.gematik.liana.konnektor.ws.conn.signatureservice.v7_5.DeactivateComfortSignatureResponse;
import de.gematik.liana.konnektor.ws.conn.signatureservice.v7_5.GetSignatureMode;
import de.gematik.liana.konnektor.ws.conn.signatureservice.v7_5.GetSignatureModeResponse;
import de.gematik.liana.konnektor.ws.conn.signatureservice.v7_5.SessionInfo;
import javax.xml.datatype.Duration;

/**
 * Komfortsignatur of an HBA (SignatureService 7.5, A_19107-01, A_19108, A_19109-02; LIANA-136,
 * LIANA-112.06): activate (with PIN.QES at the card terminal), deactivate, query the mode. The call
 * context needs the UserId; ActivateComfortSignature needs a UUID per RFC 4122 (A_20073-01) that
 * did not occur in the last 1,000 activations (A_20074).
 */
public final class Comfort {

  /**
   * Signature mode as returned by GetSignatureMode (TAB_KON_876).
   *
   * @param status the Konnektor's Komfortsignatur function, {@code ENABLED} or {@code DISABLED}
   * @param max configured SAK_COMFORT_SIGNATURE_MAX
   * @param timerSeconds configured SAK_COMFORT_SIGNATURE_TIMER in seconds
   * @param session the Komfortsignatur session of the card session, {@code null} in PIN mode
   */
  public record Status(String status, int max, long timerSeconds, Session session) {}

  /**
   * SessionInfo of a Komfortsignatur session.
   *
   * @param mode {@code COMFORT}
   * @param countRemaining remaining Komfortsignaturen without PIN entry
   * @param timeRemainingSeconds remaining time in seconds
   */
  public record Session(String mode, int countRemaining, long timeRemainingSeconds) {}

  private final Konnektor kon;
  private final CardScope card;

  Comfort(Konnektor kon, CardScope card) {
    this.kon = kon;
    this.card = card;
  }

  /** ActivateComfortSignature. */
  public void activate() {
    ActivateComfortSignature request = new ActivateComfortSignature();
    request.setContext(Jaxb.context(kon.context()));
    request.setCardHandle(card.handle());
    kon.invoke(
        Operation.ACTIVATE_COMFORT_SIGNATURE, request, ActivateComfortSignatureResponse.class);
  }

  /** DeactivateComfortSignature (per schema only CardHandles, without Context). */
  public void deactivate() {
    DeactivateComfortSignature request = new DeactivateComfortSignature();
    request.getCardHandle().add(card.handle());
    kon.invoke(
        Operation.DEACTIVATE_COMFORT_SIGNATURE, request, DeactivateComfortSignatureResponse.class);
  }

  /** GetSignatureMode. */
  public Status status() {
    GetSignatureMode request = new GetSignatureMode();
    request.setContext(Jaxb.context(kon.context()));
    request.setCardHandle(card.handle());
    GetSignatureModeResponse response =
        kon.invoke(Operation.GET_SIGNATURE_MODE, request, GetSignatureModeResponse.class);
    SessionInfo info = response.getSessionInfo();
    return new Status(
        response.getComfortSignatureStatus().value(),
        response.getComfortSignatureMax(),
        seconds(response.getComfortSignatureTimer()),
        info == null
            ? null
            : new Session(
                info.getSignatureMode().value(),
                info.getCountRemaining(),
                seconds(info.getTimeRemaining())));
  }

  private static long seconds(Duration duration) {
    return duration.getTimeInMillis(new java.util.Date(0)) / 1000;
  }
}
