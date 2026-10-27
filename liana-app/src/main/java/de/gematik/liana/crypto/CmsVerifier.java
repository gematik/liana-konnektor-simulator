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
package de.gematik.liana.crypto;

import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.signature.SignatureVerifier;
import de.gematik.liana.kern.vendor.Deviation;
import de.gematik.liana.kern.vendor.PeerDeviations;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Selector;

/**
 * {@link SignatureVerifier} with BouncyCastle (decision-022, LIANA-112.07): CoreValidation per
 * [RFC5652] 5.6 for each SignerInfo including countersignatures (RSASSA-PKCS1-v1_5, RSASSA-PSS and
 * ECDSA, brainpool too), the signing certificate from {@code SignedData.certificates} via the
 * SignerIdentifier and, if signed, signing-certificate(-v2) ([CAdES] 5.7.3). Certificate check
 * without revocation status: for the QES TUC_PKI_030 (temporal validity) and the issuer in the
 * BNetzA-VL, otherwise like TUC_PKI_018 against the TSL with the certificate types from
 * TAB_KON_786.
 *
 * <p>PAdES ({@link #pdf}): the SignedData from {@code /Contents}, detached over the {@code
 * /ByteRange} ([PAdES-3] 4.6).
 *
 * <p>If, for a detached signature, the hash of a document with LF line endings does not match,
 * LIANA checks it again with CRLF ({@link Deviation#DETACHED_CONTENT_LF}).
 */
public final class CmsVerifier implements SignatureVerifier {

  /**
   * TAB_KON_786: oid_egk_aut, oid_egk_autn, oid_smc_b_osig, oid_fd_sig, oid_fd_osig, oid_zd_sig.
   */
  static final Set<String> NON_QES_POLICIES =
      Set.of(
          "1.2.276.0.76.4.70",
          "1.2.276.0.76.4.71",
          "1.2.276.0.76.4.78",
          "1.2.276.0.76.4.203",
          "1.2.276.0.76.4.283",
          "1.2.276.0.76.4.287");

  private static final int DIGITAL_SIGNATURE = 0;
  private static final int NON_REPUDIATION = 1;

  private final TrustSpace trustSpace;
  private final PeerDeviations deviations;
  private final CadesSignatures cades;

  public CmsVerifier(TrustSpace trustSpace, PeerDeviations deviations, Clock clock) {
    this.trustSpace = trustSpace;
    this.deviations = deviations;
    this.cades = new CadesSignatures(clock);
  }

  @Override
  public List<Signer> cms(byte[] signature, byte[] detachedContent) {
    CMSSignedData signed = parse(signature);
    if (signed.getSignedContent() != null) {
      return signers(signed);
    }
    if (detachedContent == null) {
      throw ConnectorError.SYNTAX.exception("detached CMS-Signatur ohne SIG:Document");
    }
    List<Signer> signers = signers(detached(signed, detachedContent));
    byte[] crlf =
        signers.stream().allMatch(s -> s.problems().isEmpty()) ? null : crlf(detachedContent);
    if (crlf != null) {
      List<Signer> retried = signers(detached(signed, crlf));
      if (retried.stream().allMatch(s -> s.problems().isEmpty())
          && deviations.tolerate(
              Deviation.DETACHED_CONTENT_LF,
              "VerifyDocument",
              Map.of("Dokument", detachedContent.length + " Bytes mit LF"))) {
        return retried;
      }
    }
    return signers;
  }

  @Override
  public List<Signer> pdf(byte[] cms, byte[] signedContent) {
    return signers(detached(parse(cms), signedContent));
  }

  private static CMSSignedData detached(CMSSignedData signed, byte[] content) {
    try {
      return new CMSSignedData(new CMSProcessableByteArray(content), signed.toASN1Structure());
    } catch (CMSException e) {
      throw ConnectorError.SYNTAX.exception("CMS-Signatur: " + e.getMessage()).causedBy(e);
    }
  }

  /**
   * {@code content} with CRLF instead of LF, {@code null} if it contains no LF without a preceding
   * CR.
   */
  static byte[] crlf(byte[] content) {
    ByteArrayOutputStream out = new ByteArrayOutputStream(content.length + content.length / 32);
    boolean changed = false;
    for (int i = 0; i < content.length; i++) {
      if (content[i] == '\n' && (i == 0 || content[i - 1] != '\r')) {
        out.write('\r');
        changed = true;
      }
      out.write(content[i]);
    }
    return changed ? out.toByteArray() : null;
  }

  private List<Signer> signers(CMSSignedData signed) {
    Collection<SignerInformation> top = signed.getSignerInfos().getSigners();
    if (top.isEmpty()) {
      throw ConnectorError.NO_SIGNATURE.exception("SignedData ohne SignerInfo");
    }
    List<Signer> signers = new ArrayList<>();
    for (SignerInformation signer : top) {
      add(signed, signer, false, signers);
    }
    return signers;
  }

  private void add(
      CMSSignedData signed, SignerInformation signer, boolean counter, List<Signer> signers) {
    List<Problem> problems = new ArrayList<>();
    X509CertificateHolder certificate = certificate(signed, signer);
    boolean qualified = false;
    if (certificate == null) {
      problems.add(
          new Problem(
              ConnectorError.SIGNER_CERTIFICATE_MISSING, "kein Zertifikat zu " + signer.getSID()));
    } else {
      qualified = qualified(certificate);
      core(signer, certificate).ifPresent(problems::add);
    }
    signers.add(
        new Signer(
            signer.getSignature(),
            counter,
            encoded(certificate),
            qualified,
            signingTime(signer),
            List.copyOf(problems)));
    for (SignerInformation counterSigner : signer.getCounterSignatures().getSigners()) {
      add(signed, counterSigner, true, signers);
    }
  }

  /** CoreValidation: hash chain (messageDigest), signature value and signing-certificate(-v2). */
  private static Optional<Problem> core(
      SignerInformation signer, X509CertificateHolder certificate) {
    try {
      if (!signer.verify(
          new JcaSimpleSignerInfoVerifierBuilder()
              .setProvider(CryptoProviders.BC)
              .build(certificate))) {
        return Optional.of(invalid("Signaturwert falsch (" + certificate.getSubject() + ")"));
      }
    } catch (CMSException
        | GeneralSecurityException
        | OperatorCreationException
        | RuntimeException e) {
      return Optional.of(invalid("CoreValidation: " + e.getMessage()));
    }
    return signingCertificate(signer, certificate);
  }

  /**
   * [CAdES] 5.7.3: the hash in the signing-certificate(-v2) attribute must match the signing
   * certificate.
   */
  @SuppressWarnings(
      "java:S4790") // ESSCertID of signing-certificate (v1) is SHA-1 by definition (RFC 2634)
  private static Optional<Problem> signingCertificate(
      SignerInformation signer, X509CertificateHolder certificate) {
    AttributeTable attributes = signer.getSignedAttributes();
    if (attributes == null) {
      return Optional.empty();
    }
    try {
      byte[] encoded = certificate.getEncoded();
      Attribute v2 = attributes.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2);
      if (v2 != null) {
        ESSCertIDv2 id =
            SigningCertificateV2.getInstance(v2.getAttrValues().getObjectAt(0)).getCerts()[0];
        if (!Arrays.equals(id.getCertHash(), digest(id.getHashAlgorithm(), encoded))) {
          return Optional.of(invalid("signing-certificate-v2 passt nicht zum Signaturzertifikat"));
        }
      }
      Attribute v1 = attributes.get(PKCSObjectIdentifiers.id_aa_signingCertificate);
      if (v1 != null) {
        ESSCertID id =
            SigningCertificate.getInstance(v1.getAttrValues().getObjectAt(0)).getCerts()[0];
        if (!Arrays.equals(
            id.getCertHash(),
            MessageDigest.getInstance("SHA-1", CryptoProviders.BC).digest(encoded))) {
          return Optional.of(invalid("signing-certificate passt nicht zum Signaturzertifikat"));
        }
      }
    } catch (IOException
        | GeneralSecurityException
        | OperatorCreationException
        | RuntimeException e) {
      return Optional.of(invalid("signing-certificate nicht lesbar: " + e.getMessage()));
    }
    return Optional.empty();
  }

  private static byte[] digest(AlgorithmIdentifier algorithm, byte[] data)
      throws OperatorCreationException, IOException {
    DigestCalculator calculator =
        new JcaDigestCalculatorProviderBuilder()
            .setProvider(CryptoProviders.BC)
            .build()
            .get(algorithm);
    calculator.getOutputStream().write(data);
    return calculator.getDigest();
  }

  private static Problem invalid(String detail) {
    return new Problem(ConnectorError.DOCUMENT_SIGNATURE_INVALID, detail);
  }

  @SuppressWarnings("unchecked")
  private static X509CertificateHolder certificate(CMSSignedData signed, SignerInformation signer) {
    Collection<X509CertificateHolder> matches =
        signed
            .getCertificates()
            .getMatches((Selector<X509CertificateHolder>) (Selector<?>) signer.getSID());
    return matches.isEmpty() ? null : matches.iterator().next();
  }

  /** TAB_KON_760 step 3: QCStatement id-etsi-qcs-QcCompliance (0.4.0.1862.1.1). */
  static boolean qualified(X509CertificateHolder certificate) {
    Extension extension = certificate.getExtension(Extension.qCStatements);
    if (extension == null) {
      return false;
    }
    for (ASN1Encodable statement : ASN1Sequence.getInstance(extension.getParsedValue())) {
      if (ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance.equals(
          QCStatement.getInstance(statement).getStatementId())) {
        return true;
      }
    }
    return false;
  }

  private static Optional<Instant> signingTime(SignerInformation signer) {
    AttributeTable attributes = signer.getSignedAttributes();
    Attribute attribute = attributes == null ? null : attributes.get(CMSAttributes.signingTime);
    if (attribute == null) {
      return Optional.empty();
    }
    try {
      return Optional.of(
          Time.getInstance(attribute.getAttrValues().getObjectAt(0)).getDate().toInstant());
    } catch (RuntimeException e) {
      return Optional.empty();
    }
  }

  @Override
  public Optional<Problem> checkCertificate(
      byte[] certificate, boolean qualified, Instant baseTime) {
    X509Certificate x509;
    try {
      x509 =
          (X509Certificate)
              CertificateFactory.getInstance("X.509", CryptoProviders.BC)
                  .generateCertificate(new ByteArrayInputStream(certificate));
    } catch (GeneralSecurityException e) {
      return Optional.of(
          new Problem(
              ConnectorError.SIGNER_CERTIFICATE_MISSING, "nicht lesbar: " + e.getMessage()));
    }
    String subject = x509.getSubjectX500Principal().getName();
    // TUC_PKI_002 or TUC_PKI_030: valid at the verification time
    try {
      x509.checkValidity(Date.from(baseTime));
    } catch (CertificateExpiredException | CertificateNotYetValidException e) {
      return Optional.of(
          new Problem(ConnectorError.CERTIFICATE_NOT_VALID_TIME, subject + " am " + baseTime));
    }
    Optional<TrustSpace.Ca> issuer =
        qualified ? trustSpace.qualifiedIssuerOf(x509) : trustSpace.issuerOf(x509);
    if (issuer.isEmpty()) {
      return Optional.of(
          new Problem(
              ConnectorError.CA_CERT_MISSING,
              "Aussteller "
                  + x509.getIssuerX500Principal().getName()
                  + (qualified ? " nicht in der BNetzA-VL" : " weder in der TSL noch importiert")));
    }
    // TUC_PKI_004
    try {
      x509.verify(issuer.get().certificate().getPublicKey(), CryptoProviders.BC);
    } catch (GeneralSecurityException e) {
      return Optional.of(new Problem(ConnectorError.CERTIFICATE_NOT_VALID_MATH, subject));
    }
    if (qualified) {
      return Optional.empty();
    }
    // TUC_PKI_018: KeyUsage for a signature, certificate type per TAB_KON_786
    boolean[] keyUsage = x509.getKeyUsage();
    if (keyUsage == null || !keyUsage[DIGITAL_SIGNATURE] && !keyUsage[NON_REPUDIATION]) {
      return Optional.of(new Problem(ConnectorError.WRONG_KEYUSAGE, subject));
    }
    List<String> policies = ScenarioSignerCheck.policies(x509);
    if (policies.stream().noneMatch(NON_QES_POLICIES::contains)) {
      return Optional.of(new Problem(ConnectorError.CERT_TYPE_MISMATCH, subject + ": " + policies));
    }
    return Optional.empty();
  }

  @Override
  public byte[] embedOcsp(byte[] signature, byte[] ocspResponse) {
    try {
      return cades.embedOcsp(parse(signature).getEncoded(), ocspResponse);
    } catch (IOException e) {
      throw ConnectorError.INTERNAL.exception("CMS-Signatur: " + e.getMessage()).causedBy(e);
    }
  }

  /**
   * The first ASN.1 object as ContentInfo with SignedData; embedded signatures are often padded
   * with zero bytes.
   */
  private static CMSSignedData parse(byte[] der) {
    try (ASN1InputStream in = new ASN1InputStream(der)) {
      return new CMSSignedData(ContentInfo.getInstance(in.readObject()));
    } catch (IOException | CMSException | RuntimeException e) {
      throw ConnectorError.SYNTAX.exception("keine CMS-Signatur: " + e.getMessage()).causedBy(e);
    }
  }

  private static byte[] encoded(X509CertificateHolder certificate) {
    try {
      return certificate == null ? null : certificate.getEncoded();
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }
}
