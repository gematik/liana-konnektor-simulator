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
package de.gematik.liana.control;

/** The Admin API rejected a call ({@code {"error":…}}, 400, 404, 409, 503). */
public class LianaControlException extends RuntimeException {

  private final int status;
  private final String error;
  private final String code;

  public LianaControlException(String request, int status, String error, String code) {
    super(
        request
            + ": HTTP "
            + status
            + (error == null ? "" : " " + error)
            + (code == null ? "" : " (" + code + ")"));
    this.status = status;
    this.error = error;
    this.code = code;
  }

  /** HTTP status. */
  public int status() {
    return status;
  }

  /** LIANA's message from {@code error}, {@code null} if the response has none. */
  public String error() {
    return error;
  }

  /** Error code from {@code code} (e.g. 4040–4042 for pairing), otherwise {@code null}. */
  public String code() {
    return code;
  }
}
