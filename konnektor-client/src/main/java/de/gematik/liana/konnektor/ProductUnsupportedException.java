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
 * The Konnektor rejected a call that, according to the quirks table, the product does not implement
 * or implements only up to the access check (LIANA-137, decision-12 in LIANA): "not supported by
 * the product", not a Konnektor error.
 */
public final class ProductUnsupportedException extends SoapFaultException {

  private final QuirksTable.Gap gap;

  ProductUnsupportedException(
      Operation operation,
      String faultCode,
      String faultString,
      String detail,
      QuirksTable.Gap gap) {
    super(operation, faultCode, faultString, detail);
    this.gap = gap;
  }

  /** The gap according to the quirks table, with source. */
  public QuirksTable.Gap gap() {
    return gap;
  }
}
