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
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import de.gematik.liana.kern.signature.ComfortSignature;
import de.gematik.liana.kern.signature.DocumentSigning;
import de.gematik.liana.kern.signature.DocumentVerification;
import de.gematik.liana.kern.signature.JobNumbers;
import de.gematik.liana.kern.signature.SignRequest;
import de.gematik.liana.kern.vendor.VendorProfile;
import io.quarkus.qute.Location;
import io.quarkus.qute.Template;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.IntStream;

/**
 * Signature service SignatureService v7.5 under {@code /ws/SignatureService}: GetJobNumber
 * (TIP1-A_5667) complete, SignDocument (TIP1-A_5010-11) with CMS ({@link DocumentSigning}, nonQES
 * LIANA-112.02, QES LIANA-112.04, batch LIANA-112.05), other variants with the fault from {@link
 * SoapFaults#unsupported(String, String, String)}; StopSignature (TIP1-A_5666-03, LIANA-112.05);
 * ActivateComfortSignature (A_19107-01), DeactivateComfortSignature (A_19108) and GetSignatureMode
 * (A_19109-02) with {@link ComfortSignature} (LIANA-112.06); VerifyDocument (TIP1-A_5034-06) for
 * CMS with {@link DocumentVerification} (LIANA-112.07), PAdES and XAdES with the fault from {@link
 * SoapFaults#unsupported(String, String, String)} (decision-12).
 *
 * <p>GetJobNumber, SignDocument and VerifyDocument also exist in v7.4; {@code connector.sds}
 * announces both namespaces (TIP1-A_4529-02, LIANA-120), the response is in the namespace of the
 * request.
 */
@Path("/ws/SignatureService")
public class SignatureServiceResource {

  static final String NAMESPACE = "http://ws.gematik.de/conn/SignatureService/v7.5";
  static final String NAMESPACE_V74 = "http://ws.gematik.de/conn/SignatureService/v7.4";
  private static final String SERVICE = "SignatureService";

  private final JobNumbers jobNumbers;
  private final DocumentSigning signing;
  private final ComfortSignature comfort;
  private final DocumentVerification verification;
  private final Infomodel infomodel;
  private final VendorProfile vendor;
  private final Template jobNumberResponse;
  private final Template signResponse;
  private final Template stopResponse;
  private final Template activateResponse;
  private final Template deactivateResponse;
  private final Template modeResponse;
  private final Template verifyResponse;
  private final SoapFaults faults;
  private final RequestCheck requestCheck;

  SignatureServiceResource(
      JobNumbers jobNumbers,
      DocumentSigning signing,
      ComfortSignature comfort,
      DocumentVerification verification,
      Infomodel infomodel,
      VendorProfile vendor,
      @Location("soap/GetJobNumberResponse.xml") Template jobNumberResponse,
      @Location("soap/SignDocumentResponse.xml") Template signResponse,
      @Location("soap/StopSignatureResponse.xml") Template stopResponse,
      @Location("soap/ActivateComfortSignatureResponse.xml") Template activateResponse,
      @Location("soap/DeactivateComfortSignatureResponse.xml") Template deactivateResponse,
      @Location("soap/GetSignatureModeResponse.xml") Template modeResponse,
      @Location("soap/VerifyDocumentResponse.xml") Template verifyResponse,
      SoapFaults faults,
      RequestCheck requestCheck) {
    this.jobNumbers = jobNumbers;
    this.verification = verification;
    this.verifyResponse = verifyResponse;
    this.signing = signing;
    this.comfort = comfort;
    this.activateResponse = activateResponse;
    this.deactivateResponse = deactivateResponse;
    this.modeResponse = modeResponse;
    this.infomodel = infomodel;
    this.vendor = vendor;
    this.jobNumberResponse = jobNumberResponse;
    this.signResponse = signResponse;
    this.stopResponse = stopResponse;
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
      name = EventServiceResource.operationName(NAMESPACE_V74, soapAction, operation);
    }
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
        case "GetJobNumber" ->
            EventServiceResource.ok(
                jobNumberResponse
                    .data("namespace", operation.namespace())
                    .data("jobNumber", jobNumbers.next(EventServiceResource.context(operation)))
                    .render());
        case "SignDocument" -> signDocument(operation, contentType, body);
        case "StopSignature" -> stopSignature(operation);
        case "ActivateComfortSignature" -> activateComfortSignature(operation);
        case "DeactivateComfortSignature" -> deactivateComfortSignature(operation);
        case "GetSignatureMode" -> signatureMode(operation);
        case "VerifyDocument" -> verifyDocument(operation, contentType, body);
        default -> faults.unsupported(SERVICE, name);
      };
    } catch (DocumentSigning.Unsupported e) {
      return faults.unsupported(SERVICE, name, e.getMessage());
    } catch (ConnectorException e) {
      return faults.connector(e, operation);
    }
  }

  /**
   * TAB_KON_756: CardHandle, Context, JobNumber, SignRequests (the Konnektor does not evaluate
   * Crypt and TvMode, TAB_KON_065). Base64Data may be an XOP reference into the MTOM message.
   */
  private Response signDocument(XmlNode operation, String contentType, byte[] body) {
    Context context = DocumentContext.of(operation, vendor, SoapEnvelope.isMtom(contentType));
    List<SignRequest> requests = new ArrayList<>();
    for (XmlNode request : operation.children()) {
      if (request.name().equals("SignRequest")) {
        requests.add(signRequest(request, contentType, body));
      }
    }
    var results =
        signing.sign(
            new DocumentSigning.Call(
                context,
                operation.childText("CardHandle").orElse(null),
                operation.childText("JobNumber").orElse(null),
                requests));
    return EventServiceResource.ok(
        signResponse
            .data("namespace", operation.namespace())
            .data(
                "responses",
                IntStream.range(0, results.size())
                    .mapToObj(i -> SignResponseView.of(results.get(i), i))
                    .toList())
            .render());
  }

  /** TAB_KON_840: Context and JobNumber; the job itself answers its SignDocument (TAB_KON_192). */
  private Response stopSignature(XmlNode operation) {
    signing.stop(
        EventServiceResource.context(operation), operation.childText("JobNumber").orElse(null));
    return EventServiceResource.ok(stopResponse.data("namespace", operation.namespace()).render());
  }

  /** TAB_KON_874: CardHandle and Context, returns SignatureMode. */
  private Response activateComfortSignature(XmlNode operation) {
    String mode =
        comfort.activate(
            EventServiceResource.context(operation),
            operation.childText("CardHandle").orElse(null));
    return EventServiceResource.ok(
        activateResponse.data("namespace", operation.namespace()).data("mode", mode).render());
  }

  /**
   * TAB_KON_875: one or more CardHandles, without Context; warnings from TUC_KON_172 in the status.
   */
  private Response deactivateComfortSignature(XmlNode operation) {
    List<String> cardHandles =
        operation.children().stream()
            .filter(c -> c.name().equals("CardHandle"))
            .map(c -> c.text().strip())
            .toList();
    List<GerrorView> warnings =
        comfort.deactivate(cardHandles).stream()
            .map(w -> GerrorView.of(w.error(), w.text()))
            .toList();
    return EventServiceResource.ok(
        deactivateResponse
            .data("namespace", operation.namespace())
            .data("warnings", warnings)
            .render());
  }

  /** TAB_KON_876: configuration and, in Comfort mode, SessionInfo; times as xsd:duration. */
  private Response signatureMode(XmlNode operation) {
    ComfortSignature.Mode mode =
        comfort.mode(
            EventServiceResource.context(operation),
            operation.childText("CardHandle").orElse(null));
    return EventServiceResource.ok(
        modeResponse
            .data("namespace", operation.namespace())
            .data("status", mode.enabled() ? "ENABLED" : "DISABLED")
            .data("max", mode.max())
            .data("timer", duration(mode.timer()))
            .data(
                "countRemaining",
                mode.session().map(ComfortSignature.SessionInfo::countRemaining).orElse(null))
            .data(
                "timeRemaining", mode.session().map(i -> duration(i.timeRemaining())).orElse(null))
            .render());
  }

  /** xsd:duration „PTnHnMnS“ (TAB_KON_876), in seconds. */
  static String duration(Duration duration) {
    return duration.truncatedTo(ChronoUnit.SECONDS).toString();
  }

  /** {@code SIG:SignRequest}: RequestID, OptionalInputs, Document, IncludeRevocationInfo. */
  private static SignRequest signRequest(XmlNode request, String contentType, byte[] body) {
    XmlNode inputs = request.child("OptionalInputs").orElse(null);
    Optional<XmlNode> updated =
        inputs == null ? Optional.empty() : inputs.child("ReturnUpdatedSignature");
    return new SignRequest(
        request.attributes().get("RequestID"),
        request.child("Document").map(d -> document(d, contentType, body)).orElse(null),
        inputs == null ? null : inputs.childText("SignatureType").orElse(null),
        inputs == null
            ? null
            : inputs.childText("IncludeEContent").map(Boolean::parseBoolean).orElse(null),
        request.childText("IncludeRevocationInfo").map(Boolean::parseBoolean).orElse(false),
        inputs == null
            ? null
            : inputs
                .child("SignaturePlacement")
                .map(SignatureServiceResource::placement)
                .orElse(null),
        // SIG:IncludeObjects with dss:IncludeObject (SignatureService_V7_5_6.xsd)
        inputs != null && inputs.child("IncludeObjects").isPresent(),
        updated.map(u -> u.attributes().getOrDefault("Type", "")).orElse(null),
        inputs == null
            ? null
            : inputs
                .child("GenerateUnderSignaturePolicy")
                .flatMap(p -> p.childText("SignaturePolicyIdentifier"))
                .map(String::strip)
                .orElse(null));
  }

  /**
   * {@code dss:SignaturePlacement}: WhichDocument, CreateEnvelopedSignature (Default true),
   * XPathFirstChildOf/After.
   */
  private static SignRequest.Placement placement(XmlNode placement) {
    return new SignRequest.Placement(
        placement.attributes().get("WhichDocument"),
        placement.childText("XPathFirstChildOf").map(String::strip).orElse(null),
        placement.childText("XPathAfter").map(String::strip).orElse(null),
        // xs:boolean: false or 0
        !Set.of("false", "0")
            .contains(
                placement.attributes().getOrDefault("CreateEnvelopedSignature", "true").strip()));
  }

  /**
   * {@code SIG:Document} with {@code CONN:Base64XML} or {@code dss:Base64Data} (inline or {@code
   * xop:Include}).
   */
  private static SignRequest.Document document(XmlNode document, String contentType, byte[] body) {
    String id = document.attributes().get("ID");
    String shortText = document.attributes().get("ShortText");
    Optional<XmlNode> xml = document.child("Base64XML");
    Optional<XmlNode> data = document.child("Base64Data");
    XmlNode content = xml.or(() -> data).orElse(null);
    return new SignRequest.Document(
        id,
        document.attributes().get("RefURI"),
        shortText,
        data.map(d -> d.attributes().get("MimeType")).orElse(null),
        content == null ? null : bytes(content, contentType, body),
        xml.isPresent());
  }

  private static byte[] bytes(XmlNode content, String contentType, byte[] body) {
    Optional<XmlNode> include = content.child("Include");
    try {
      if (include.isPresent()) {
        return SoapEnvelope.attachment(contentType, body, include.get().attributes().get("href"));
      }
      return Base64.getMimeDecoder().decode(content.text().strip());
    } catch (SoapEnvelope.InvalidSoapException | IllegalArgumentException e) {
      throw ConnectorError.SYNTAX.exception(content.name() + ": " + e.getMessage()).causedBy(e);
    }
  }

  /**
   * TAB_KON_759: Context, Document (Base64Data inline or XOP, Base64XML),
   * SignatureObject/Base64Signature, IncludeRevocationInfo, OptionalInputs UseVerificationTime and
   * ReturnVerificationReport; LIANA does not evaluate TvMode, VerifyManifests, AdditionalKeyInfo,
   * Schemas and ViewerInfo.
   */
  private Response verifyDocument(XmlNode operation, String contentType, byte[] body) {
    XmlNode inputs = operation.child("OptionalInputs").orElse(null);
    DocumentVerification.Document document =
        operation.child("Document").map(d -> verifiedDocument(d, contentType, body)).orElse(null);
    DocumentVerification.Signature signature =
        operation
            .child("SignatureObject")
            .flatMap(o -> o.child("Base64Signature"))
            .map(
                s ->
                    new DocumentVerification.Signature(
                        bytes(s, contentType, body), s.attributes().get("Type")))
            .orElse(null);
    Optional<Instant> verificationTime =
        inputs == null
            ? Optional.empty()
            : inputs
                .child("UseVerificationTime")
                .flatMap(t -> t.childText("SpecificTime"))
                .map(SignatureServiceResource::dateTime);
    var result =
        verification.verify(
            new DocumentVerification.Request(
                EventServiceResource.context(operation),
                document,
                signature,
                operation
                    .childText("IncludeRevocationInfo")
                    .map(Boolean::parseBoolean)
                    .orElse(false),
                verificationTime));
    boolean report = inputs != null && inputs.child("ReturnVerificationReport").isPresent();
    return EventServiceResource.ok(
        verifyResponse
            .data("namespace", operation.namespace())
            .data("r", VerifyResponseView.of(result, report, Instant.now()))
            .render());
  }

  private static DocumentVerification.Document verifiedDocument(
      XmlNode document, String contentType, byte[] body) {
    Optional<XmlNode> xml = document.child("Base64XML");
    Optional<XmlNode> data = document.child("Base64Data");
    XmlNode content = xml.or(() -> data).orElse(null);
    return new DocumentVerification.Document(
        content == null ? new byte[0] : bytes(content, contentType, body),
        data.map(d -> d.attributes().get("MimeType")).orElse(null),
        xml.isPresent());
  }

  /** xsd:dateTime, without time zone as UTC. */
  private static Instant dateTime(String value) {
    try {
      String text = value.strip();
      return OffsetDateTime.parse(text.matches(".*(Z|[+-]\\d\\d:\\d\\d)$") ? text : text + "Z")
          .toInstant();
    } catch (DateTimeParseException e) {
      throw ConnectorError.SYNTAX.exception("UseVerificationTime: " + value).causedBy(e);
    }
  }
}
