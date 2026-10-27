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
import de.gematik.liana.kern.access.Infomodel;
import de.gematik.liana.kern.card.CardAccess;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import de.gematik.liana.kern.vendor.VendorProfile;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import java.util.Optional;

/**
 * Encryption service EncryptionService v6.1 under {@code /ws/EncryptionService}: EncryptDocument
 * (TIP1-A_4621-06) and DecryptDocument (TIP1-A_4622-05) up to and including TUC_KON_000, also as
 * MTOM message. If the Aufrufkontext is valid, LIANA responds with the fault from {@link
 * SoapFaults#afterAccessCheck} (decision-12); LIANA does not implement the hybrid encryption and
 * decryption (LIANA-60).
 */
@Path("/ws/EncryptionService")
public class EncryptionServiceResource {

  static final String NAMESPACE = "http://ws.gematik.de/conn/EncryptionService/v6.1";
  private static final String SERVICE = "EncryptionService";

  private final CardAccess cardAccess;
  private final Infomodel infomodel;
  private final VendorProfile vendor;
  private final SoapFaults faults;
  private final RequestCheck requestCheck;

  EncryptionServiceResource(
      CardAccess cardAccess,
      Infomodel infomodel,
      VendorProfile vendor,
      SoapFaults faults,
      RequestCheck requestCheck) {
    this.cardAccess = cardAccess;
    this.infomodel = infomodel;
    this.vendor = vendor;
    this.faults = faults;
    this.requestCheck = requestCheck;
  }

  @POST
  public Response post(
      @HeaderParam("SOAPAction") String soapAction,
      @HeaderParam("Content-Type") String contentType,
      byte[] body) {
    XmlNode operation;
    byte[] root;
    try {
      root = SoapEnvelope.rootPart(contentType, body);
      operation = SoapEnvelope.operation(root);
    } catch (SoapEnvelope.InvalidSoapException e) {
      return faults.client(e);
    }
    Optional<Response> rejected = requestCheck.check(soapAction, root, operation);
    if (rejected.isPresent()) {
      return rejected.get();
    }
    String name = EventServiceResource.operationName(NAMESPACE, soapAction, operation);
    if (name == null) {
      return faults.client(
          "SOAPAction '"
              + soapAction
              + "' passt nicht zu "
              + operation.namespace()
              + "#"
              + operation.name());
    }
    try {
      return switch (name) {
        case "EncryptDocument" -> encryptDocument(operation, SoapEnvelope.isMtom(contentType));
        case "DecryptDocument" -> decryptDocument(operation, SoapEnvelope.isMtom(contentType));
        default -> faults.unsupported(SERVICE, name);
      };
    } catch (ConnectorException e) {
      return faults.connector(e, operation);
    }
  }

  /**
   * TAB_KON_746 steps 1 and 3: checkArguments and TUC_KON_000 with cardHandle from
   * RecipientKeys/CertificateOnCard and userId (needCardSession: step 4 gets the CardSession; HBAx
   * without UserId → 4003). Without CertificateOnCard (certificates only) without cardHandle (rule
   * R3). Step 2 (checkDocumentFormat) is omitted without business logic.
   */
  private Response encryptDocument(XmlNode operation, boolean mtom) {
    Context context = DocumentContext.of(operation, vendor, mtom);
    XmlNode recipients =
        operation
            .child("RecipientKeys")
            .orElseThrow(
                () -> ConnectorError.SYNTAX.exception("EncryptDocument ohne RecipientKeys"));
    var onCard = recipients.child("CertificateOnCard");
    if (onCard.isPresent()) {
      cardAccess.card(context, onCard.get().childText("CardHandle").orElse(null), true);
    } else if (recipients.child("Certificate").isEmpty()) {
      throw ConnectorError.SYNTAX.exception("RecipientKeys ohne CertificateOnCard und Certificate");
    } else {
      infomodel.checkAccess(context, false);
    }
    return faults.afterAccessCheck(SERVICE, "EncryptDocument");
  }

  /**
   * TAB_KON_076 steps 1–2: checkArguments and TUC_KON_000 with cardHandle from PrivateKeyOnCard and
   * userId.
   */
  private Response decryptDocument(XmlNode operation, boolean mtom) {
    Context context = DocumentContext.of(operation, vendor, mtom);
    XmlNode key =
        operation
            .child("PrivateKeyOnCard")
            .orElseThrow(
                () -> ConnectorError.SYNTAX.exception("DecryptDocument ohne PrivateKeyOnCard"));
    cardAccess.card(context, key.childText("CardHandle").orElse(null), true);
    return faults.afterAccessCheck(SERVICE, "DecryptDocument");
  }
}
