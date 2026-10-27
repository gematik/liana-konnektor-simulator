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
 * Signature service without card reference (LIANA-136): GetJobNumber (TIP1-A_4658) and
 * StopSignature (TIP1-A_4659).
 */
public final class Signatures {

  private final Konnektor kon;

  Signatures(Konnektor kon) {
    this.kon = kon;
  }

  /** GetJobNumber: identifier for the next SignDocument call (format {@code XYZ-123}). */
  public String jobNumber() {
    ServiceDirectory.Selection selection = kon.select(Operation.GET_JOB_NUMBER);
    Object request = Jaxb.request(selection.binding(), "GetJobNumber");
    Jaxb.set(request, "Context", Jaxb.context(kon.context()));
    Object response =
        kon.invoke(selection, request, Jaxb.type(selection.binding(), "GetJobNumberResponse"));
    return (String) Jaxb.get(response, "JobNumber");
  }

  /** StopSignature: aborts the signature job with this JobNumber. */
  public void stop(String jobNumber) {
    ServiceDirectory.Selection selection = kon.select(Operation.STOP_SIGNATURE);
    Object request = Jaxb.request(selection.binding(), "StopSignature");
    Jaxb.set(request, "Context", Jaxb.context(kon.context()));
    Jaxb.set(request, "JobNumber", jobNumber);
    kon.invoke(selection, request, Jaxb.type(selection.binding(), "StopSignatureResponse"));
  }
}
