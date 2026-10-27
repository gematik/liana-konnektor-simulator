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
package de.gematik.liana.kern.error;

/**
 * Abort of an operation with a connector error code; the SOAP adapters turn it into a SOAP fault.
 */
public class ConnectorException extends RuntimeException {

  private final ConnectorError error;
  private final String text;
  private final ConnectorError protocolError;
  private String clientDetail;

  ConnectorException(
      ConnectorError error, String text, ConnectorError protocolError, String detail) {
    super(
        error.code()
            + " "
            + text
            + (protocolError == error ? "" : " (" + protocolError.code() + ")")
            + ": "
            + detail);
    this.error = error;
    this.text = text;
    this.protocolError = protocolError;
  }

  /**
   * The exception this error arose from; appears in the log of the SOAP fault, never in the
   * response.
   */
  public ConnectorException causedBy(Throwable cause) {
    initCause(cause);
    return this;
  }

  /**
   * A detail the client may see ({@code GERROR:Trace/Detail}): only terms of the specification,
   * never internal states; the cause for the log is in the detail text of the exception
   * (LIANA-164).
   */
  public ConnectorException clientDetail(String detail) {
    this.clientDetail = detail;
    return this;
  }

  /** {@link #clientDetail(String)}, otherwise {@code null}. */
  public String clientDetail() {
    return clientDetail;
  }

  public ConnectorError error() {
    return error;
  }

  /** Error code in the log (TAB_KON_514-01 note 3); otherwise the same as {@link #error()}. */
  public ConnectorError protocolError() {
    return protocolError;
  }

  /** Error text for the client: that of the error code, placeholders filled in. */
  public String text() {
    return text;
  }
}
