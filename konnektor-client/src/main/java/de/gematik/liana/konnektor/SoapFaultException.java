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

import java.util.Optional;

/**
 * The Konnektor responded with a SOAP fault (LIANA-137). With a gematik error trace, a subclass per
 * {@code ErrorType} is raised ({@link KonnektorFault}); with a product gap according to the quirks
 * table, {@link ProductUnsupportedException}; with neither, this class.
 */
public class SoapFaultException extends KonnektorException {

  private final Operation operation;
  private final String faultCode;
  private final String faultString;
  private final String detail;
  private final GematikError error;

  public SoapFaultException(
      Operation operation, String faultCode, String faultString, String detail) {
    this(operation, faultCode, faultString, detail, null);
  }

  SoapFaultException(
      Operation operation,
      String faultCode,
      String faultString,
      String detail,
      GematikError error) {
    super(
        operation.wsdlName()
            + ": SOAP-Fault "
            + faultCode
            + " "
            + faultString
            + (error == null || error.code().isEmpty()
                ? ""
                : " ("
                    + error.code().get()
                    + error.errorType().map(t -> " " + t).orElse("")
                    + ")"));
    this.operation = operation;
    this.faultCode = faultCode;
    this.faultString = faultString;
    this.detail = detail;
    this.error = error;
  }

  /** The called operation. */
  public Operation operation() {
    return operation;
  }

  /** {@code faultcode} of the SOAP fault. */
  public String faultCode() {
    return faultCode;
  }

  /** {@code faultstring} of the SOAP fault. */
  public String faultString() {
    return faultString;
  }

  /** Content of {@code detail} as XML text, empty if the fault has none. */
  public String detail() {
    return detail;
  }

  /** The gematik error trace, if present in {@code detail}. */
  public Optional<GematikError> error() {
    return Optional.ofNullable(error);
  }

  /** Error code of the first trace entry (e.g. 4021), if present. */
  public Optional<Integer> code() {
    return error().flatMap(GematikError::code);
  }

  /** Builds the matching exception: by ErrorType, or "not supported by the product". */
  static SoapFaultException of(
      Operation operation,
      String faultCode,
      String faultString,
      String detail,
      Optional<QuirksTable.Gap> gap) {
    Optional<GematikError> error = GematikError.parse(detail);
    if (gap.isPresent() && error.flatMap(GematikError::code).isEmpty()) {
      return new ProductUnsupportedException(operation, faultCode, faultString, detail, gap.get());
    }
    if (error.isEmpty()) {
      return new SoapFaultException(operation, faultCode, faultString, detail);
    }
    GematikError e = error.get();
    return switch (e.errorType().orElse("")) {
      case "Technical" ->
          new KonnektorFault.Technical(operation, faultCode, faultString, detail, e);
      case "Security" -> new KonnektorFault.Security(operation, faultCode, faultString, detail, e);
      case "Business" -> new KonnektorFault.Business(operation, faultCode, faultString, detail, e);
      case "Infrastructure" ->
          new KonnektorFault.Infrastructure(operation, faultCode, faultString, detail, e);
      default -> new KonnektorFault(operation, faultCode, faultString, detail, e);
    };
  }
}
