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
package de.gematik.liana.adapter.soap;

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.vendor.VendorProfile;

/**
 * Aufrufkontext of the document operations with the part of checkArguments that depends on the
 * vendor profile.
 */
final class DocumentContext {

  private DocumentContext() {}

  /**
   * {@code CCTX:Context} of the operation. Depending on the profile, an empty UserId is a syntax
   * error (4000) instead of a missing UserId in TUC_KON_000 ({@link
   * VendorProfile#emptyUserIdIsSyntaxError(boolean)}).
   *
   * @param mtom whether the request came as an MTOM message ({@link SoapEnvelope#isMtom})
   */
  static Context of(XmlNode operation, VendorProfile vendor, boolean mtom) {
    Context context = EventServiceResource.context(operation);
    if (context.userId() != null
        && context.userId().isEmpty()
        && vendor.emptyUserIdIsSyntaxError(mtom)) {
      throw ConnectorError.SYNTAX.exception("leere UserId");
    }
    return context;
  }
}
