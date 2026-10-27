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

import static de.gematik.liana.konnektor.Binding.AUTH_SIGNATURE_SERVICE_7_4;
import static de.gematik.liana.konnektor.Binding.CARD_SERVICE_8_1;
import static de.gematik.liana.konnektor.Binding.CARD_SERVICE_8_2;
import static de.gematik.liana.konnektor.Binding.CARD_TERMINAL_SERVICE_1_1;
import static de.gematik.liana.konnektor.Binding.CERTIFICATE_SERVICE_6_0;
import static de.gematik.liana.konnektor.Binding.ENCRYPTION_SERVICE_6_1;
import static de.gematik.liana.konnektor.Binding.EVENT_SERVICE_7_2;
import static de.gematik.liana.konnektor.Binding.SIGNATURE_SERVICE_7_4;
import static de.gematik.liana.konnektor.Binding.SIGNATURE_SERVICE_7_5;
import static de.gematik.liana.konnektor.Binding.VSD_SERVICE_5_2;
import static de.gematik.liana.konnektor.Timing.LONG;
import static de.gematik.liana.konnektor.Timing.SHORT;

import java.util.List;

/**
 * Operations of the bound services, each with the bindings whose WSDL contains it, and its runtime
 * class (LIANA-132). {@link Timing#LONG}: PIN entry at the card terminal, card crypto operation,
 * waiting for insertion or removal, ReadVSD (reading the eGK, with Onlineprüfung at the specialist
 * service).
 */
public enum Operation {
  // EventService
  SUBSCRIBE("Subscribe", SHORT, EVENT_SERVICE_7_2),
  UNSUBSCRIBE("Unsubscribe", SHORT, EVENT_SERVICE_7_2),
  RENEW_SUBSCRIPTIONS("RenewSubscriptions", SHORT, EVENT_SERVICE_7_2),
  GET_SUBSCRIPTION("GetSubscription", SHORT, EVENT_SERVICE_7_2),
  GET_RESOURCE_INFORMATION("GetResourceInformation", SHORT, EVENT_SERVICE_7_2),
  GET_CARD_TERMINALS("GetCardTerminals", SHORT, EVENT_SERVICE_7_2),
  GET_CARDS("GetCards", SHORT, EVENT_SERVICE_7_2),
  // CardService
  VERIFY_PIN("VerifyPin", LONG, CARD_SERVICE_8_1, CARD_SERVICE_8_2),
  CHANGE_PIN("ChangePin", LONG, CARD_SERVICE_8_1, CARD_SERVICE_8_2),
  UNBLOCK_PIN("UnblockPin", LONG, CARD_SERVICE_8_1, CARD_SERVICE_8_2),
  GET_PIN_STATUS("GetPinStatus", SHORT, CARD_SERVICE_8_1, CARD_SERVICE_8_2),
  ENABLE_PIN("EnablePin", LONG, CARD_SERVICE_8_1, CARD_SERVICE_8_2),
  DISABLE_PIN("DisablePin", LONG, CARD_SERVICE_8_1, CARD_SERVICE_8_2),
  START_CARD_SESSION("StartCardSession", SHORT, CARD_SERVICE_8_2),
  SECURE_SEND_APDU("SecureSendAPDU", LONG, CARD_SERVICE_8_2),
  STOP_CARD_SESSION("StopCardSession", SHORT, CARD_SERVICE_8_2),
  // CardTerminalService
  REQUEST_CARD("RequestCard", LONG, CARD_TERMINAL_SERVICE_1_1),
  EJECT_CARD("EjectCard", LONG, CARD_TERMINAL_SERVICE_1_1),
  // CertificateService
  CHECK_CERTIFICATE_EXPIRATION("CheckCertificateExpiration", SHORT, CERTIFICATE_SERVICE_6_0),
  READ_CARD_CERTIFICATE("ReadCardCertificate", SHORT, CERTIFICATE_SERVICE_6_0),
  VERIFY_CERTIFICATE("VerifyCertificate", SHORT, CERTIFICATE_SERVICE_6_0),
  // AuthSignatureService
  EXTERNAL_AUTHENTICATE("ExternalAuthenticate", LONG, AUTH_SIGNATURE_SERVICE_7_4),
  // SignatureService
  SIGN_DOCUMENT("SignDocument", LONG, SIGNATURE_SERVICE_7_4, SIGNATURE_SERVICE_7_5),
  VERIFY_DOCUMENT("VerifyDocument", SHORT, SIGNATURE_SERVICE_7_4, SIGNATURE_SERVICE_7_5),
  GET_JOB_NUMBER("GetJobNumber", SHORT, SIGNATURE_SERVICE_7_4, SIGNATURE_SERVICE_7_5),
  STOP_SIGNATURE("StopSignature", SHORT, SIGNATURE_SERVICE_7_4, SIGNATURE_SERVICE_7_5),
  ACTIVATE_COMFORT_SIGNATURE("ActivateComfortSignature", LONG, SIGNATURE_SERVICE_7_5),
  DEACTIVATE_COMFORT_SIGNATURE("DeactivateComfortSignature", SHORT, SIGNATURE_SERVICE_7_5),
  GET_SIGNATURE_MODE("GetSignatureMode", SHORT, SIGNATURE_SERVICE_7_5),
  // EncryptionService
  ENCRYPT_DOCUMENT("EncryptDocument", SHORT, ENCRYPTION_SERVICE_6_1),
  DECRYPT_DOCUMENT("DecryptDocument", LONG, ENCRYPTION_SERVICE_6_1),
  // VSDService (Fachmodul VSDM)
  READ_VSD("ReadVSD", LONG, VSD_SERVICE_5_2);

  private final String wsdlName;
  private final Timing timing;
  private final List<Binding> bindings;

  Operation(String wsdlName, Timing timing, Binding... bindings) {
    this.wsdlName = wsdlName;
    this.timing = timing;
    this.bindings = List.of(bindings);
  }

  /** Name of the operation in the WSDL. */
  public String wsdlName() {
    return wsdlName;
  }

  /** Runtime class, determines the timeout. */
  public Timing timing() {
    return timing;
  }

  /** Service of the operation. */
  public Service service() {
    return bindings.get(0).service();
  }

  /**
   * Whether the user may enter a PIN at the card terminal for this operation (LIANA-137): PIN
   * operations, SignDocument (QES) and ActivateComfortSignature. The PIN hook ({@link
   * PinPromptHandler}) runs beforehand.
   */
  public boolean pinInput() {
    return switch (this) {
      case VERIFY_PIN,
          CHANGE_PIN,
          UNBLOCK_PIN,
          ENABLE_PIN,
          DISABLE_PIN,
          SIGN_DOCUMENT,
          ACTIVATE_COMFORT_SIGNATURE ->
          true;
      default -> false;
    };
  }

  /** Bindings whose WSDL contains the operation, in ascending version order. */
  public List<Binding> bindings() {
    return bindings;
  }
}
