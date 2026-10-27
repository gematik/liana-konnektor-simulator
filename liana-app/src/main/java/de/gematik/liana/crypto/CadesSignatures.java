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
import de.gematik.liana.kern.signature.CmsSignatures;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.function.UnaryOperator;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.OtherRevocationInfoFormat;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.ess.ContentHints;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;

/**
 * {@link CmsSignatures} with BouncyCastle: CAdES-BES per [CAdES] and TUC_KON_155, SignedData with
 * SHA-256 and ecdsa-with-SHA256 (RSA certificate of the HBA G2.0: RSASSA-PSS with SHA-256,
 * MGF1-SHA-256, salt 32 like PSO COMPUTE DIGITAL SIGNATURE with signPSS, gemSpec_COS
 * G2_N088.600.a), signed attributes contentType, messageDigest, signingTime (system time,
 * TIP1-A_5402), signing-certificate-v2 and ContentHints with the ShortText (TUC_KON_155), OCSP
 * response in {@code crls.other} (TUC_KON_159). The card supplies the signature value; the parallel
 * signature is added as a further SignerInfo to the existing SignedData (gemSpec_Kon appendix,
 * „Parallele Signaturen werden durch je einen SignerInfo-Container pro Signatur realisiert“).
 *
 * <p>For PAdES ({@link #pades}) the same SignedData, detached over the {@code /ByteRange}, but
 * without signingTime and ContentHints ([PAdES Baseline Profile] 6.2.1: the signing time is in
 * {@code /M}, the ShortText in {@code /Reason}); signing-certificate-v2 per [PAdES-3] 4.4.3.
 */
public final class CadesSignatures implements CmsSignatures {

  private static final AlgorithmIdentifier ECDSA_SHA256 =
      new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256);
  private static final AlgorithmIdentifier SHA256 =
      new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);

  /** RSASSA-PSS (RFC 4055) with SHA-256, MGF1-SHA-256, salt 32, trailer 1. */
  private static final AlgorithmIdentifier RSASSA_PSS_SHA256 =
      new AlgorithmIdentifier(
          PKCSObjectIdentifiers.id_RSASSA_PSS,
          new RSASSAPSSparams(
              SHA256,
              new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, SHA256),
              new ASN1Integer(32),
              new ASN1Integer(1)));

  private final Clock clock;

  public CadesSignatures(Clock clock) {
    this.clock = clock;
  }

  @Override
  public byte[] sign(Request request, UnaryOperator<byte[]> signHash) {
    try {
      X509CertificateHolder certificate = new X509CertificateHolder(request.certificate());
      Date now = validNow(certificate);
      CMSSignedData existing = request.parallelTo() == null ? null : parse(request.parallelTo());
      byte[] content =
          existing == null ? request.content() : (byte[]) existing.getSignedContent().getContent();
      CMSSignedData signed =
          generate(
              certificate,
              content,
              request.encapsulate(),
              new DefaultSignedAttributeTableGenerator(
                  signedAttributes(certificate, now, request.shortText())),
              signHash);
      SignerInformation signer = signed.getSignerInfos().getSigners().iterator().next();
      return (existing == null ? signed : parallel(existing, signer, certificate))
          .getEncoded("DER");
    } catch (IOException | CMSException | OperatorCreationException e) {
      throw ConnectorError.INTERNAL.exception("CMS-Signatur: " + e.getMessage()).causedBy(e);
    }
  }

  /**
   * The CMS signature for {@code /Contents} of a PAdES signature over {@code signedContent} ({@code
   * /ByteRange}).
   */
  byte[] pades(byte[] signedContent, byte[] certificateDer, UnaryOperator<byte[]> signHash) {
    try {
      X509CertificateHolder certificate = new X509CertificateHolder(certificateDer);
      validNow(certificate);
      DefaultSignedAttributeTableGenerator defaults =
          new DefaultSignedAttributeTableGenerator(
              new AttributeTable(signingCertificateV2(certificate)));
      CMSAttributeTableGenerator withoutTime =
          parameters -> defaults.getAttributes(parameters).remove(CMSAttributes.signingTime);
      return generate(certificate, signedContent, false, withoutTime, signHash).getEncoded("DER");
    } catch (IOException | CMSException | OperatorCreationException e) {
      throw ConnectorError.INTERNAL.exception("PAdES-Signatur: " + e.getMessage()).causedBy(e);
    }
  }

  /** TUC_KON_165 step 3: valid at the signing time. */
  private Date validNow(X509CertificateHolder certificate) {
    Date now = Date.from(clock.instant());
    if (!certificate.isValidOn(now)) {
      throw ConnectorError.CERTIFICATE_NOT_VALID_TIME.exception(
          certificate.getSubject().toString());
    }
    return now;
  }

  /**
   * SignedData with one SignerInfo, signature value from the card; TUC_KON_166 step 3 checks it
   * (4120).
   */
  private static CMSSignedData generate(
      X509CertificateHolder certificate,
      byte[] content,
      boolean encapsulate,
      CMSAttributeTableGenerator attributes,
      UnaryOperator<byte[]> signHash)
      throws CMSException, OperatorCreationException {
    CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
    generator.addSignerInfoGenerator(
        new SignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider(CryptoProviders.BC).build())
            .setSignedAttributeGenerator(attributes)
            .build(new CardSigner(signHash, algorithm(certificate)), certificate));
    generator.addCertificate(certificate);
    CMSSignedData signed = generator.generate(new CMSProcessableByteArray(content), encapsulate);
    SignerInformation signer = signed.getSignerInfos().getSigners().iterator().next();
    if (!verifies(signer, certificate)) {
      throw ConnectorError.CARD_SIGNATURE_INVALID.exception(
          "Signatur der Karte passt nicht zum Zertifikat " + certificate.getSubject());
    }
    return signed;
  }

  @Override
  public byte[] embedOcsp(byte[] signedData, byte[] ocspResponse) {
    try {
      CMSSignedData signed = new CMSSignedData(signedData);
      List<Object> revocations = new ArrayList<>(signed.getCRLs().getMatches(null));
      revocations.add(
          new OtherRevocationInfoFormat(
              CMSObjectIdentifiers.id_ri_ocsp_response, OCSPResponse.getInstance(ocspResponse)));
      return CMSSignedData.replaceCertificatesAndCRLs(
              signed,
              signed.getCertificates(),
              signed.getAttributeCertificates(),
              new CollectionStore<>(revocations))
          .getEncoded("DER");
    } catch (IOException | CMSException e) {
      throw ConnectorError.INTERNAL
          .exception("OCSP-Antwort einbetten: " + e.getMessage())
          .causedBy(e);
    }
  }

  private static AttributeTable signedAttributes(
      X509CertificateHolder certificate, Date now, String shortText) throws IOException {
    ASN1EncodableVector attributes = new ASN1EncodableVector();
    attributes.add(new Attribute(CMSAttributes.signingTime, new DERSet(new Time(now))));
    attributes.add(signingCertificateV2(certificate));
    if (shortText != null && !shortText.isEmpty()) {
      attributes.add(
          new Attribute(
              PKCSObjectIdentifiers.id_aa_contentHint,
              new DERSet(
                  new ContentHints(CMSObjectIdentifiers.data, new DERUTF8String(shortText)))));
    }
    return new AttributeTable(attributes);
  }

  private static Attribute signingCertificateV2(X509CertificateHolder certificate)
      throws IOException {
    ESSCertIDv2 certId =
        new ESSCertIDv2(
            sha256(certificate.getEncoded()),
            new IssuerSerial(
                new GeneralNames(new GeneralName(certificate.getIssuer())),
                certificate.getSerialNumber()));
    return new Attribute(
        PKCSObjectIdentifiers.id_aa_signingCertificateV2,
        new DERSet(new SigningCertificateV2(certId)));
  }

  /**
   * The existing signature of a parallel signature: only the first ASN.1 object (embedded
   * signatures are often padded with zero bytes), enveloping, otherwise 4111.
   */
  private static CMSSignedData parse(byte[] der) {
    CMSSignedData existing;
    try (ASN1InputStream in = new ASN1InputStream(der)) {
      existing = new CMSSignedData(ContentInfo.getInstance(in.readObject()));
    } catch (IOException | CMSException | RuntimeException e) {
      throw ConnectorError.INVALID_SIGNATURE_TYPE
          .exception("Parallelsignatur: Dokument ist keine CMS-Signatur")
          .causedBy(e);
    }
    if (existing.getSignedContent() == null) {
      throw ConnectorError.INVALID_SIGNATURE_TYPE.exception(
          "Parallelsignatur zu einer detached-Signatur");
    }
    return existing;
  }

  private static CMSSignedData parallel(
      CMSSignedData existing, SignerInformation signer, X509CertificateHolder certificate)
      throws CMSException {
    List<SignerInformation> signers = new ArrayList<>(existing.getSignerInfos().getSigners());
    signers.add(signer);
    CMSSignedData merged =
        CMSSignedData.replaceSigners(existing, new SignerInformationStore(signers));
    List<X509CertificateHolder> certificates =
        new ArrayList<>(existing.getCertificates().getMatches(null));
    if (!certificates.contains(certificate)) {
      certificates.add(certificate);
    }
    return CMSSignedData.replaceCertificatesAndCRLs(
        merged,
        new CollectionStore<>(certificates),
        existing.getAttributeCertificates(),
        existing.getCRLs());
  }

  private static boolean verifies(SignerInformation signer, X509CertificateHolder certificate) {
    try {
      return signer.verify(
          new JcaSimpleSignerInfoVerifierBuilder()
              .setProvider(CryptoProviders.BC)
              .build(certificate));
    } catch (CMSException | OperatorCreationException | java.security.cert.CertificateException e) {
      return false;
    }
  }

  /**
   * The signature algorithm for the certificate's key: RSASSA-PSS for RSA (C.HP.QES.R2048 carries
   * the key as id-RSASSA-PSS, others as rsaEncryption), otherwise ecdsa-with-SHA256.
   */
  private static AlgorithmIdentifier algorithm(X509CertificateHolder certificate) {
    ASN1ObjectIdentifier key = certificate.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm();
    return key.equals(PKCSObjectIdentifiers.rsaEncryption)
            || key.equals(PKCSObjectIdentifiers.id_RSASSA_PSS)
        ? RSASSA_PSS_SHA256
        : ECDSA_SHA256;
  }

  private static byte[] sha256(byte[] data) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(data);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * ContentSigner that has the card sign the SHA-256 hash of the signed attributes (TUC_KON_218).
   */
  private static final class CardSigner implements ContentSigner {
    private final UnaryOperator<byte[]> signHash;
    private final AlgorithmIdentifier algorithm;
    private final ByteArrayOutputStream signedAttributes = new ByteArrayOutputStream();

    CardSigner(UnaryOperator<byte[]> signHash, AlgorithmIdentifier algorithm) {
      this.signHash = signHash;
      this.algorithm = algorithm;
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      return algorithm;
    }

    @Override
    public OutputStream getOutputStream() {
      return signedAttributes;
    }

    @Override
    public byte[] getSignature() {
      return signHash.apply(sha256(signedAttributes.toByteArray()));
    }
  }
}
