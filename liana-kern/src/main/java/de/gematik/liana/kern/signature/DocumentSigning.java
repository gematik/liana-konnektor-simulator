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
package de.gematik.liana.kern.signature;

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.card.AuthState;
import de.gematik.liana.kern.card.CardAccess;
import de.gematik.liana.kern.card.CardCertificates;
import de.gematik.liana.kern.card.CardLocks;
import de.gematik.liana.kern.card.CardObject;
import de.gematik.liana.kern.card.CardSignature;
import de.gematik.liana.kern.card.CardToCard;
import de.gematik.liana.kern.card.CardType;
import de.gematik.liana.kern.card.PinVerification;
import de.gematik.liana.kern.card.TrustedChannels;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import de.gematik.liana.kern.management.ManagementSettings;
import de.gematik.liana.kern.terminal.SecureChannel;
import de.gematik.liana.kern.vendor.VendorProfile;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.UnaryOperator;

/**
 * SignDocument (TIP1-A_5010-11) per TAB_KON_756, CMS (CAdES) enveloping and detached, also as
 * parallel signature:
 *
 * <ul>
 *   <li>nonQES with the SM-B per TUC_KON_160 „Dokumente nonQES signieren“ (TIP1-A_4653-04), OSIG
 *       key (TAB_KON_900, A_17768-01), PIN.SMC from the card session (LIANA-112.02);
 *   <li>QES with the HBA per TUC_KON_150 „Dokumente QES signieren“ (TIP1-A_4655-04): PIN.QES at the
 *       CT in DF.QES, one document per TUC_KON_168 (TIP1-A_4652-03) as in single signature mode
 *       (LIANA-112.04), a batch per TUC_KON_154 (TIP1-A_4651-03) with one PIN.QES per Teilstapel
 *       (LIANA-112.05), in SE #2 with trusted channels ({@link TrustedChannels}, LIANA-112.13);
 *   <li>QES in Komfortsignatur mode per TUC_KON_170 (A_19103-08) and TUC_KON_158 (A_19102-05),
 *       without PIN entry ({@link ComfortSignature}, LIANA-112.06), in SE #2 via the trusted
 *       channel gSMC-K↔HBA (A_19258).
 * </ul>
 *
 * <p>StopSignature (TIP1-A_5666-03) aborts a running job via its Jobnummer; the behavior follows
 * TAB_KON_192 (TIP1-A_4671). With MGM_LU_ONLINE=Enabled, TUC_KON_159 obtains a status response and
 * embeds it with IncludeRevocationInfo (LIANA-112.03).
 *
 * <p>PAdES (LIANA-112.08) for PDF/A in all three paths: TUC_KON_080 (B) checks the PDF/A
 * identification, the signature goes into the document as an incremental update ({@link
 * PdfSignatures}, TAB_KON_779-01), the ShortText into the field Reason (TUC_KON_155); an OCSP
 * response is not embedded for PAdES (TUC_KON_159).
 *
 * <p>XAdES (LIANA-112.09) only as QES under the signature policy NFDM (TIP1-A_5538, TAB_KON_778
 * „Bedingt“): internally detached as the first child of {@code XPathFirstChildOf}, the reference
 * from {@code RefURI} ({@link XmlSignatures}); nonQES XAdES ends with 4111 (A_18756).
 *
 * <p>S/MIME (LIANA-112.10) nonQES only: TUC_KON_080 (D), preparation, CMS enveloping and
 * post-processing via {@link Smime}, the OCSP response in the SignedData; profile KOCO reports 4279
 * ({@link VendorProfile#rejectsSmime()}). LIANA does not yet implement the countersignature, the
 * XAdES parallel signature and HBA predecessor cards ({@link Unsupported}, decision-12).
 */
public final class DocumentSigning {

  /**
   * Maximum number of SignRequests per call (TAB_KON_065: at least 50, otherwise 4000);
   * Konnektor-QES signs batches of up to 80 (KUC_1602_072).
   */
  static final int MAX_REQUESTS = 250;

  private static final String PIN_SMC = "PIN.SMC";
  private static final String PIN_QES = "PIN.QES";
  private static final String MIME_PDF_A = "application/pdf-a";

  /**
   * XPath step from {@code XPathFirstChildOf} to the new signature, its first child
   * (dss:SignaturePtr/@XPath).
   */
  static final String SIGNATURE_STEP = "/*[local-name()='Signature'][1]";

  /** A variant of SignDocument that LIANA does not implement (decision-12). */
  public static final class Unsupported extends RuntimeException {
    Unsupported(String message) {
      super(message);
    }
  }

  /**
   * Call parameters of SignDocument (TAB_KON_065), as far as TUC_KON_160 evaluates them; not Crypt
   * and TvMode.
   */
  public record Call(
      Context context, String cardHandle, String jobNumber, List<SignRequest> requests) {}

  /** Signature key and certificate C.HP.QES of the HBA (TAB_KON_900). */
  private record QesKey(CardSignature.Key key, byte[] certificate) {}

  /** A SignRequest per TUC_KON_160 or TUC_KON_150 steps 1 and 2: CMS, PDF or XML. */
  private record Plan(
      SignRequest request, SignatureType type, boolean parallel, List<ConnectorError> warnings) {}

  /** A running job for StopSignature (TAB_KON_841 step 2: CardHandle for the Jobnummer). */
  private record Job(String cardHandle, AtomicBoolean stopped) {}

  /**
   * The signatures of a job: {@code signatures} in the order of the SignRequests, of which the
   * first {@code kept} apply; the remaining SignRequests end with {@code end} (TAB_KON_192).
   */
  private record Signed(List<byte[]> signatures, int kept, ConnectorError end) {}

  private final Map<String, Job> running = new ConcurrentHashMap<>();

  private final CardAccess access;
  private final CardLocks locks;
  private final AuthState authState;
  private final PinVerification pins;
  private final CardCertificates certificates;
  private final CardSignature cardSignature;
  private final JobNumbers jobNumbers;
  private final CmsSignatures cms;
  private final PdfSignatures pdf;
  private final XmlSignatures xml;
  private final RevocationSource revocation;
  private final ManagementSettings settings;
  private final VendorProfile vendor;
  private final ComfortSignature comfort;
  private final TrustedChannels channels;

  public DocumentSigning(
      CardAccess access,
      CardLocks locks,
      AuthState authState,
      PinVerification pins,
      CardCertificates certificates,
      CardSignature cardSignature,
      JobNumbers jobNumbers,
      CmsSignatures cms,
      PdfSignatures pdf,
      XmlSignatures xml,
      RevocationSource revocation,
      ManagementSettings settings,
      VendorProfile vendor,
      ComfortSignature comfort,
      TrustedChannels channels) {
    this.access = access;
    this.locks = locks;
    this.authState = authState;
    this.pins = pins;
    this.certificates = certificates;
    this.cardSignature = cardSignature;
    this.jobNumbers = jobNumbers;
    this.cms = cms;
    this.pdf = pdf;
    this.xml = xml;
    this.revocation = revocation;
    this.settings = settings;
    this.vendor = vendor;
    this.comfort = comfort;
    this.channels = channels;
  }

  /** TAB_KON_756; one SignResult per SignRequest in its order. */
  public List<SignResult> sign(Call call) {
    checkArguments(call);
    // steps 2 and 3: TUC_KON_000 with userId and cardHandle, TUC_KON_026 (4093 on a foreign card
    // lock)
    CardObject card = access.card(call.context(), call.cardHandle(), true);
    access.checkFree(card);
    CardType type = card.data().type();
    if (type.matches("HBAx") && type != CardType.HBA) {
      throw new Unsupported("QES mit HBA-Vorläuferkarten (" + type.value() + ")");
    }
    if (type != CardType.SMC_B && type != CardType.HBA) {
      // TUC_KON_160 (3), TUC_KON_150 (->2), TAB_KON_900
      throw ConnectorError.CARD_TYPE_NOT_FOR_SIGNATURE.exception(type.value());
    }
    jobNumbers.use(call.jobNumber());
    Job job = new Job(call.cardHandle(), new AtomicBoolean());
    running.put(call.jobNumber(), job);
    try {
      if (type != CardType.HBA) {
        return nonQes(call, card, job);
      }
      Optional<ComfortSignature.Active> active = comfort.active(call.context(), call.cardHandle());
      return active.isPresent() ? tucKon170(call, card, job, active.get()) : qes(call, card, job);
    } finally {
      running.remove(call.jobNumber(), job);
    }
  }

  /**
   * StopSignature per TAB_KON_841: checkArguments (4000), CardHandle for the Jobnummer of a running
   * job (otherwise 4243, TAB_KON_842), TUC_KON_000 with UserId for HBAx, then the job stops before
   * its next signature.
   */
  public void stop(Context context, String jobNumber) {
    if (blank(jobNumber)) {
      throw ConnectorError.SYNTAX.exception("JobNumber fehlt");
    }
    Job job = running.get(jobNumber);
    if (job == null) {
      throw ConnectorError.JOB_NUMBER_UNKNOWN.exception(jobNumber);
    }
    access.card(context, job.cardHandle(), true);
    job.stopped().set(true);
  }

  /**
   * TUC_KON_160 from step 1; after StopSignature it discards all signatures (TAB_KON_192 no. 5).
   */
  private List<SignResult> nonQes(Call call, CardObject card, Job job) {
    // step 5: TUC_KON_160, steps 1 and 2 for the whole batch before the first signature
    List<Plan> plans = call.requests().stream().map(this::nonQesPlan).toList();
    // TUC_KON_218 step 3: PrK.HCI.OSIG.E256 is released by PWD(01), PIN.SMC
    if (!authState.isVerified(call.context(), call.cardHandle(), PIN_SMC)) {
      throw ConnectorError.ACCESS_CONDITIONS.exception(
          PIN_SMC + " in der Kartensitzung nicht verifiziert");
    }
    // TUC_KON_165 step 2: TUC_KON_216, C.HCI.OSIG.E256 (TAB_KON_900); the temporal validity (step
    // 3)
    // is checked by the port when signing
    byte[] certificate = certificates.read(card, "C.SIG", "ECC");
    List<byte[]> signatures = new ArrayList<>();
    for (Plan plan : plans) {
      if (job.stopped().get()) {
        return results(plans, new Signed(signatures, 0, ConnectorError.PIN_CANCELLED), certificate);
      }
      // TUC_KON_155 and TUC_KON_166 steps 1–4
      signatures.add(
          sign(
              plan,
              certificate,
              hash -> cardSignature.sign(card, CardSignature.Key.OSIG_E256, hash)));
    }
    return results(plans, new Signed(signatures, plans.size(), null), certificate);
  }

  /**
   * TUC_KON_150 from step 1. One document is signed by TUC_KON_168 (step 7a) without secure
   * messaging as in single signature mode (SAK_SIMPLE_SIGNATURE_MODE = SE#1, TAB_KON_596), a batch
   * by TUC_KON_154 (7b) in SE #2: PIN.QES in the remote PIN procedure, PSO CDS in the trusted
   * channel gSMC-K↔HBA ({@link TrustedChannels}, LIANA-112.13). If anything is missing for that,
   * the batch is also signed in SE #1 with PWD(81) and the usage counter of the PIN.QES.
   */
  private List<SignResult> qes(Call call, CardObject card, Job job) {
    // steps 1 and 2, TUC_KON_152 step 1 (TUC_KON_080) for the whole batch before PIN entry
    List<Plan> plans = call.requests().stream().map(this::qesPlan).toList();
    // TUC_KON_152 step 2: TUC_KON_216, C.HP.QES per TAB_KON_900
    QesKey qes = qesKey(card, plans);
    byte[] certificate = qes.certificate();
    // TUC_KON_154 security requirements: the HBA's CVC before DF.QES
    Optional<CardToCard.Target> se2 = plans.size() > 1 ? channels.prepare(card) : Optional.empty();
    Signed signed;
    // step 4: TUC_KON_023 with doLock=true, 4093 if the card is reserved
    CardLocks.Lock lock = locks.lock(card.cardHandle());
    try {
      // steps 6 and 7 in DF.QES
      cardSignature.enter(card, qes.key());
      try {
        QesSession session = new QesSession(card, qes.key(), se2.orElse(null));
        // step 6: TUC_KON_012 with PIN.QES, Mandatorisch; after a wrong entry the card refuses the
        // signature (TUC_KON_218: 4085)
        session.verify(call);
        signed = tucKon154(call, job, plans, qes, session);
      } finally {
        // step 8 and error case a)
        cardSignature.leave(card);
        authState.notVerified(call.context(), call.cardHandle(), PIN_QES);
      }
    } finally {
      // step 9 and error case b): TUC_KON_023 with doLock=false
      locks.unlock(lock);
    }
    return results(plans, signed, certificate);
  }

  /**
   * TUC_KON_170 for a card session in Comfort mode: like TUC_KON_150, but without PIN entry and
   * without leaving DF.QES; TUC_KON_158 signs each document with the Komfortsignatur counter.
   * SAK_COMFORT_SIGNATURE_MAX, the timer and an expired usage counter of the PIN.QES (the card
   * refuses the signature) end the mode with 4271 (TUC_KON_172). If TUC_KON_171 brought the HBA
   * into SE #2, step 1 of TUC_KON_158 establishes the trusted channel gSMC-K↔HBA per job (A_19258,
   * LIANA-112.13), otherwise SE #1 without secure messaging. StopSignature discards all signatures
   * of the job (TAB_KON_192, one Teilstapel).
   */
  private List<SignResult> tucKon170(
      Call call, CardObject card, Job job, ComfortSignature.Active active) {
    // steps 3–5
    List<Plan> plans = call.requests().stream().map(this::qesPlan).toList();
    // steps 1 and 2
    comfort.start(active, card);
    QesKey qes = qesKey(card, plans);
    byte[] certificate = qes.certificate();
    QesSession session =
        new QesSession(card, qes.key(), comfort.secureEnvironment(card).orElse(null));
    List<byte[]> signatures = new ArrayList<>();
    // step 6: TUC_KON_023 with doLock=true
    CardLocks.Lock lock = locks.lock(card.cardHandle());
    try {
      // step 8 in DF.QES; selecting the same DF again leaves the PIN.QES in place
      cardSignature.enter(card, qes.key());
      for (Plan plan : plans) {
        if (job.stopped().get()) {
          return results(
              plans, new Signed(signatures, 0, ConnectorError.PIN_CANCELLED), certificate);
        }
        // TUC_KON_158 steps 3–5
        comfort.next(active, card);
        try {
          signatures.add(sign(plan, certificate, session::sign));
        } catch (ConnectorException e) {
          if (e.error() == ConnectorError.ACCESS_CONDITIONS) {
            throw comfort.abort(card, "PIN.QES nicht mehr verifiziert: " + e.getMessage());
          }
          throw e;
        }
        comfort.counted(active, card);
      }
    } finally {
      // step 9
      locks.unlock(lock);
    }
    // step 10
    return results(plans, new Signed(signatures, plans.size(), null), certificate);
  }

  /**
   * TUC_KON_154 steps 1–3 (or TUC_KON_168 for one document) after the first PIN.QES: per document
   * TUC_KON_155 and TUC_KON_218. If the card refuses a signature after it has already signed with
   * this PIN, the usage counter of the PIN.QES has expired (step 3): TUC_KON_012 again, from here a
   * new Teilstapel. If this PIN entry ends without verification (TAB_KON_192 no. 1, 2, 4) or
   * StopSignature arrives (no. 3, 5), the signatures of the previous Teilstapel remain, the other
   * SignRequests end without signature. Any other error aborts the whole batch (no. 7).
   */
  private Signed tucKon154(Call call, Job job, List<Plan> plans, QesKey qes, QesSession session) {
    List<byte[]> signatures = new ArrayList<>();
    int subBatch = 0;
    while (signatures.size() < plans.size()) {
      if (job.stopped().get()) {
        return new Signed(signatures, subBatch, ConnectorError.PIN_CANCELLED);
      }
      Plan plan = plans.get(signatures.size());
      try {
        signatures.add(sign(plan, qes.certificate(), session::sign));
      } catch (ConnectorException e) {
        if (e.error() != ConnectorError.ACCESS_CONDITIONS || signatures.size() == subBatch) {
          throw e;
        }
        subBatch = signatures.size();
        Optional<ConnectorError> pin = verifyAgain(call, session);
        if (pin.isPresent()) {
          return new Signed(signatures, subBatch, pin.get());
        }
      }
    }
    return new Signed(signatures, plans.size(), null);
  }

  /** TUC_KON_154 step 3: PIN.QES for the next Teilstapel; empty if it is verified. */
  private Optional<ConnectorError> verifyAgain(Call call, QesSession session) {
    authState.notVerified(call.context(), call.cardHandle(), PIN_QES);
    try {
      PinVerification.Result result = session.verify(call);
      return result.pinResult() == PinVerification.PinResult.OK
          ? Optional.empty()
          : Optional.of(ConnectorError.ACCESS_CONDITIONS);
    } catch (ConnectorException e) {
      return Optional.of(e.error());
    }
  }

  /**
   * Step 10 or TUC_KON_160: TUC_KON_159 for every valid signature, 4123 discards all; the remaining
   * SignRequests without signature with the error that ended the job.
   */
  private List<SignResult> results(List<Plan> plans, Signed signed, byte[] certificate) {
    List<SignResult> results = new ArrayList<>();
    for (int i = 0; i < plans.size(); i++) {
      Plan plan = plans.get(i);
      results.add(
          i < signed.kept()
              ? result(plan, afterSigning(plan, signed.signatures().get(i), certificate))
              : SignResult.failed(plan.request(), signed.end()));
    }
    return List.copyOf(results);
  }

  /**
   * The HBA in DF.QES for one job: without {@code se2} in SE #1 without secure messaging; with
   * {@code se2} (the HBA's CVC, {@link TrustedChannels#prepare}) in SE #2, the PIN.QES via the
   * channel gSMC-KT↔HBA (TIP1-A_5012), PSO CDS via the channel gSMC-K↔HBA, which is re-established
   * after every PIN entry.
   */
  private final class QesSession {
    private final CardObject card;
    private final CardSignature.Key key;
    private final CardToCard.Target se2;
    private SecureChannel signing;

    QesSession(CardObject card, CardSignature.Key key, CardToCard.Target se2) {
      this.card = card;
      this.key = key;
      this.se2 = se2;
    }

    /** TUC_KON_012 with PIN.QES, in SE #2 after MSE RESTORE (which clears a verified PIN.QES). */
    PinVerification.Result verify(Call call) {
      signing = null;
      if (se2 == null) {
        return pins.verifyQes(call.context(), card, call.jobNumber());
      }
      channels.environment(card, 2);
      return pins.verifyQes(call.context(), card, call.jobNumber(), channels.remotePin(card, se2));
    }

    /**
     * TUC_KON_218, in SE #2 in the trusted channel gSMC-K↔HBA (TUC_KON_154 standard flow,
     * TUC_KON_158 step 1).
     */
    byte[] sign(byte[] hash) {
      if (se2 == null) {
        return cardSignature.sign(card, key, hash);
      }
      if (signing == null) {
        signing = channels.signing(card, se2);
      }
      return cardSignature.sign(card, key, hash, signing);
    }
  }

  /**
   * TAB_KON_900 (A_17768-01): from G2.1 C.HP.QES.E256 with PrK.HP.QES.E256, for the HBA G2.0
   * C.HP.QES.R2048 with PrK.HP.QES.R2048 (RSASSA-PSS). As in {@link
   * de.gematik.liana.kern.card.EgkFiles}, the card decides: if it has the ECC certificate, it is
   * G2.1. LIANA signs XAdES only with ECC (decision-023, JSR 105 with ecdsa-sha256).
   */
  private QesKey qesKey(CardObject card, List<Plan> plans) {
    try {
      return new QesKey(CardSignature.Key.QES_E256, certificates.read(card, "C.QES", "ECC"));
    } catch (ConnectorException e) {
      if (e.error() != ConnectorError.CERT_NOT_ON_CARD) {
        throw e;
      }
    }
    byte[] certificate = certificates.read(card, "C.QES", "RSA");
    if (plans.stream().anyMatch(plan -> plan.type() == SignatureType.XML)) {
      throw new Unsupported("XAdES mit PrK.HP.QES.R2048 des HBA G2.0 (RSA)");
    }
    return new QesKey(CardSignature.Key.QES_R2048, certificate);
  }

  /** TUC_KON_155 and TUC_KON_166 steps 1–4: the CMS signature or the signed PDF or XML document. */
  private byte[] sign(Plan plan, byte[] certificate, UnaryOperator<byte[]> signHash) {
    SignRequest request = plan.request();
    if (plan.type() == SignatureType.XML) {
      return xml.sign(
          new XmlSignatures.Request(
              request.document().content(),
              certificate,
              request.document().shortText(),
              request.document().refUri(),
              request.placement().xPathFirstChildOf(),
              request.signaturePolicy()),
          signHash);
    }
    if (plan.type() == SignatureType.PDF) {
      return pdf.sign(
          new PdfSignatures.Request(
              request.document().content(), certificate, request.document().shortText()),
          signHash);
    }
    if (plan.type() == SignatureType.SMIME) {
      return cms.sign(
          new CmsSignatures.Request(
              Smime.entity(Smime.parse(request.document().content())),
              true,
              certificate,
              request.document().shortText(),
              null),
          signHash);
    }
    return cms.sign(
        new CmsSignatures.Request(
            request.document().content(),
            plan.parallel() || Boolean.TRUE.equals(request.includeEContent()),
            certificate,
            request.document().shortText(),
            plan.parallel() ? request.document().content() : null),
        signHash);
  }

  private static SignResult result(Plan plan, byte[] signature) {
    SignRequest request = plan.request();
    if (plan.type() == SignatureType.SMIME) {
      // S/MIME post-processing step: the SignedData (with OCSP) into the MIME message
      signature = Smime.message(Smime.parse(request.document().content()), signature);
    }
    return new SignResult(
        request.requestId(),
        request.document(),
        plan.type(),
        signature,
        List.copyOf(plan.warnings()),
        null,
        plan.type() == SignatureType.XML
            ? request.placement().xPathFirstChildOf() + SIGNATURE_STEP
            : null);
  }

  /**
   * TUC_KON_159 after the signature: with MGM_LU_ONLINE=Enabled the status response (steps 2 and 4,
   * offline no request); REVOKED or UNKNOWN → 4123; with {@code includeRevocationInfo} embedded for
   * CMS and XAdES, not for PAdES (step 5).
   */
  private byte[] afterSigning(Plan plan, byte[] signature, byte[] certificate) {
    if (!settings.online()) {
      return signature;
    }
    RevocationSource.Answer answer = revocation.status(certificate);
    if (answer.status() != RevocationSource.Status.GOOD) {
      throw ConnectorError.SIGNATURE_CREATION_FAILED.exception("OCSP-Status " + answer.status());
    }
    if (!plan.request().includeRevocationInfo()) {
      return signature;
    }
    return switch (plan.type()) {
      case CMS, SMIME -> cms.embedOcsp(signature, answer.ocspResponse());
      case XML ->
          xml.embedOcsp(
              signature, plan.request().placement().xPathFirstChildOf(), answer.ocspResponse());
      default -> signature;
    };
  }

  /** TAB_KON_756 step 1: Jobnummer, SignRequests with RequestID and document (4000). */
  private static void checkArguments(Call call) {
    if (blank(call.jobNumber())) {
      throw ConnectorError.SYNTAX.exception("JobNumber fehlt");
    }
    if (call.requests().isEmpty() || call.requests().size() > MAX_REQUESTS) {
      throw ConnectorError.SYNTAX.exception(
          call.requests().size() + " SignRequests, erlaubt 1–" + MAX_REQUESTS);
    }
    for (SignRequest request : call.requests()) {
      if (blank(request.requestId())) {
        throw ConnectorError.SYNTAX.exception("SignRequest ohne RequestID");
      }
      if (request.document() == null
          || request.document().content() == null
          || request.document().content().length == 0) {
        throw ConnectorError.SYNTAX.exception(
            "SignRequest " + request.requestId() + " ohne Dokument");
      }
    }
  }

  /**
   * TUC_KON_160 steps 1 and 2: signature type (default per TAB_KON_583) and its admissibility for
   * nonQES with the SM-B, signature variant (parallel signature), warnings; TUC_KON_165 step 1:
   * TUC_KON_080. PAdES requires a document in PDF/A format (TAB_KON_778), otherwise 4111.
   */
  private Plan nonQesPlan(SignRequest request) {
    SignatureType type = signatureType(request);
    boolean parallel = false;
    switch (type) {
      // A_18756: nonQES XAdES may end with 4111
      case XML ->
          throw ConnectorError.INVALID_SIGNATURE_TYPE
              .exception("nonQES-XAdES (A_18756)")
              .clientDetail("nonQES-XAdES wird nicht unterstützt (A_18756)");
      case PDF -> {
        if (DocumentFormat.of(request.document()) != DocumentFormat.PDF_A) {
          throw ConnectorError.INVALID_SIGNATURE_TYPE.exception(
              "PAdES für " + DocumentFormat.of(request.document()).label());
        }
        padesVariant(request);
      }
      case SMIME -> {
        if (vendor.rejectsSmime()) {
          throw ConnectorError.SMIME_UNSUPPORTED.exception(
              "SMIME-Funktionalität nicht unterstützt", "nonQES S/MIME");
        }
        smimeVariant(request);
      }
      case CMS -> parallel = cmsVariant(request);
    }
    if (type == SignatureType.SMIME) {
      // TUC_KON_080 (D): the document format is MIME, whatever the MimeType (KUC_1601_009)
      Smime.parse(request.document().content());
    } else {
      DocumentFormat.validate(request.document(), null, pdf, xml);
    }
    List<ConnectorError> warnings = warnings(request, type);
    if ((parallel || !settings.online() && request.includeRevocationInfo())
        && vendor.warnsOfflineWithoutOcsp()) {
      warnings.add(ConnectorError.OFFLINE_NO_OCSP);
    }
    return new Plan(request, type, parallel, warnings);
  }

  /**
   * TUC_KON_150 steps 1 and 2 with the document format (QES_DocFormate) and TUC_KON_152 step 1
   * (TUC_KON_080). An unknown SignatureType is always 4111, a format not matching the signature
   * type (PAdES without PDF/A, S/MIME) 4111 or 4110 ({@link
   * VendorProfile#reportsQesFormatMismatch()}), binary 4110 before or after the variants of a CMS
   * signature ({@link VendorProfile#checksQesFormatFirst()}). XAdES only for XML and per {@link
   * #xadesVariant}.
   */
  private Plan qesPlan(SignRequest request) {
    SignatureType type = signatureType(request);
    DocumentFormat format = DocumentFormat.of(request.document());
    switch (type) {
      case SMIME -> {
        if (vendor.rejectsSmime()) {
          throw ConnectorError.SMIME_UNSUPPORTED.exception(
              "SMIME-Funktionalität nicht unterstützt", "QES S/MIME");
        }
        throw formatMismatch(type, format);
      }
      case PDF -> {
        if (format != DocumentFormat.PDF_A) {
          throw formatMismatch(type, format);
        }
        padesVariant(request);
      }
      case XML -> {
        if (format != DocumentFormat.XML) {
          throw formatMismatch(type, format);
        }
        xadesVariant(request);
      }
      default -> {}
    }
    if (vendor.checksQesFormatFirst() && format == DocumentFormat.BINARY) {
      throw invalidFormat(format);
    }
    boolean parallel = type == SignatureType.CMS && cmsVariant(request);
    if (format == DocumentFormat.BINARY) {
      throw invalidFormat(format);
    }
    DocumentFormat.validate(
        request.document(), type == SignatureType.XML ? request.signaturePolicy() : null, pdf, xml);
    return new Plan(request, type, parallel, warnings(request, type));
  }

  private RuntimeException formatMismatch(SignatureType type, DocumentFormat format) {
    return vendor.reportsQesFormatMismatch()
        ? invalidFormat(format)
        : ConnectorError.INVALID_SIGNATURE_TYPE.exception(type + " für " + format.label());
  }

  /** TUC_KON_150 (->1): no QES_DocFormat or not matching the signature type, 4110. */
  private static RuntimeException invalidFormat(DocumentFormat format) {
    ConnectorError error = ConnectorError.INVALID_DOCUMENT_FORMAT;
    return error.exception(
        error.text().replace("%Format%", format.label()), "QES_DocFormate: " + format.label());
  }

  /** SignatureType as URI, the default per TAB_KON_583 if not given; an unknown URI is 4111. */
  private static SignatureType signatureType(SignRequest request) {
    return request.signatureType() == null
        ? defaultType(request.document())
        : SignatureType.of(request.signatureType())
            .orElseThrow(
                () ->
                    ConnectorError.INVALID_SIGNATURE_TYPE.exception(
                        "SignatureType " + request.signatureType()));
  }

  /**
   * Signature variant of a CMS signature (TAB_KON_065): IncludeObject only for XML (4111),
   * ReturnUpdatedSignature parallel or document-excluding countersignature, any other Type 4111.
   * Returns whether to sign in parallel.
   */
  private static boolean cmsVariant(SignRequest request) {
    if (request.includeObject()) {
      throw ConnectorError.INVALID_SIGNATURE_TYPE.exception("IncludeObject bei CMS");
    }
    if (request.updateType() == null) {
      return false;
    }
    return switch (request.updateType()) {
      case SignRequest.PARALLEL -> true;
      case SignRequest.COUNTER -> throw new Unsupported("dokumentexkludierende Gegensignatur");
      default ->
          throw ConnectorError.INVALID_SIGNATURE_TYPE.exception(
              "ReturnUpdatedSignature/@Type " + request.updateType());
    };
  }

  /**
   * S/MIME is always {@code application/pkcs7-mime} with embedded content (IncludeEContent has no
   * effect); IncludeObject, parallel and countersignature are reserved for CMS or XML (TAB_KON_065,
   * otherwise 4111).
   */
  private static void smimeVariant(SignRequest request) {
    if (request.includeObject() || request.updateType() != null) {
      throw ConnectorError.INVALID_SIGNATURE_TYPE.exception("Variante bei S/MIME");
    }
  }

  /**
   * TAB_KON_065: IncludeEContent only for CMS, IncludeObject only for XML, parallel and
   * countersignature only for XML and CMS (TAB_KON_779-01: „Parallele Signaturen werden nicht
   * angeboten“), otherwise 4111.
   */
  private static void padesVariant(SignRequest request) {
    if (Boolean.TRUE.equals(request.includeEContent())
        || request.includeObject()
        || request.updateType() != null) {
      throw ConnectorError.INVALID_SIGNATURE_TYPE.exception("Variante bei PAdES");
    }
  }

  /**
   * TIP1-A_5538, TAB_KON_778 and TAB_KON_065 for QES XAdES: only under a signature policy LIANA
   * knows (NFDM, otherwise 4111); its variant is „detached, ausgewähltes Element, innerhalb des
   * Dokuments, aber außerhalb des signierten Subbaums“: SignaturePlacement with XPathFirstChildOf
   * and CreateEnvelopedSignature=false, the reference as {@code RefURI} „#ID“, no IncludeEContent
   * and no IncludeObject (everything else 4111).
   */
  private static void xadesVariant(SignRequest request) {
    if (!XmlSignatures.NFDM_POLICY.equals(request.signaturePolicy())) {
      throw ConnectorError.INVALID_SIGNATURE_TYPE.exception(
          "QES-XAdES ohne bekannte Signaturrichtlinie: " + request.signaturePolicy());
    }
    SignRequest.Placement placement = request.placement();
    if (placement == null
        || placement.createEnvelopedSignature()
        || blank(placement.xPathFirstChildOf())) {
      throw ConnectorError.INVALID_SIGNATURE_TYPE.exception(
          "NFDM: SignaturePlacement mit XPathFirstChildOf und CreateEnvelopedSignature=false");
    }
    String refUri = request.document().refUri();
    if (refUri == null || !refUri.startsWith("#") || refUri.length() < 2) {
      throw ConnectorError.INVALID_SIGNATURE_TYPE.exception(
          "NFDM: RefURI #ID fehlt (" + refUri + ")");
    }
    if (Boolean.TRUE.equals(request.includeEContent()) || request.includeObject()) {
      throw ConnectorError.INVALID_SIGNATURE_TYPE.exception(
          "IncludeEContent bzw. IncludeObject bei NFDM");
    }
    if (request.updateType() != null) {
      if (SignRequest.PARALLEL.equals(request.updateType())
          || SignRequest.COUNTER.equals(request.updateType())) {
        throw new Unsupported("XAdES-Parallel- und Gegensignatur");
      }
      throw ConnectorError.INVALID_SIGNATURE_TYPE.exception(
          "ReturnUpdatedSignature/@Type " + request.updateType());
    }
  }

  /** TAB_KON_065 SignaturePlacement: ignored for signatures other than XML, warning 4197. */
  private static List<ConnectorError> warnings(SignRequest request, SignatureType type) {
    List<ConnectorError> warnings = new ArrayList<>();
    if (request.signaturePlacement() && type != SignatureType.XML) {
      warnings.add(ConnectorError.SIGNATURE_PLACEMENT_IGNORED);
    }
    return warnings;
  }

  /** TAB_KON_583: XML → XAdES, PDF/A → PAdES, all others → CAdES detached. */
  private static SignatureType defaultType(SignRequest.Document document) {
    if (document.xml()) {
      return SignatureType.XML;
    }
    return MIME_PDF_A.equals(document.mimeType()) ? SignatureType.PDF : SignatureType.CMS;
  }

  private static boolean blank(String value) {
    return value == null || value.isBlank();
  }
}
