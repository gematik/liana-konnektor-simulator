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

/**
 * SOAP fault with gematik error trace ({@code GERROR:Error}, LIANA-137); one subclass per {@code
 * ErrorType} of the first trace entry (gemSpec_OM, TelematikError v2.0). Unknown or missing
 * ErrorTypes yield this class.
 */
public class KonnektorFault extends SoapFaultException {

  KonnektorFault(
      Operation operation,
      String faultCode,
      String faultString,
      String detail,
      GematikError error) {
    super(operation, faultCode, faultString, detail, error);
  }

  /** The error trace (always present). */
  public GematikError gematikError() {
    return error().orElseThrow();
  }

  /**
   * {@code ErrorType} Technical: technical error in the Konnektor or at the card and card terminal.
   */
  public static final class Technical extends KonnektorFault {
    Technical(
        Operation operation,
        String faultCode,
        String faultString,
        String detail,
        GematikError error) {
      super(operation, faultCode, faultString, detail, error);
    }
  }

  /** {@code ErrorType} Security: access denied, certificate or authorization. */
  public static final class Security extends KonnektorFault {
    Security(
        Operation operation,
        String faultCode,
        String faultString,
        String detail,
        GematikError error) {
      super(operation, faultCode, faultString, detail, error);
    }
  }

  /** {@code ErrorType} Business: business error, such as an invalid Aufrufkontext. */
  public static final class Business extends KonnektorFault {
    Business(
        Operation operation,
        String faultCode,
        String faultString,
        String detail,
        GematikError error) {
      super(operation, faultCode, faultString, detail, error);
    }
  }

  /** {@code ErrorType} Infrastructure: TI services unreachable. */
  public static final class Infrastructure extends KonnektorFault {
    Infrastructure(
        Operation operation,
        String faultCode,
        String faultString,
        String detail,
        GematikError error) {
      super(operation, faultCode, faultString, detail, error);
    }
  }
}
