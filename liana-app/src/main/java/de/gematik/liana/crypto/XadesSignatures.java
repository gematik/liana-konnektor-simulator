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

import de.gematik.liana.adapter.soap.RequestValidation;
import de.gematik.liana.contract.Schemas;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import de.gematik.liana.kern.signature.SignatureVerifier.Problem;
import de.gematik.liana.kern.signature.SignatureVerifier.Signer;
import de.gematik.liana.kern.signature.XmlSignatures;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.UnaryOperator;
import javax.xml.XMLConstants;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.Schema;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.bouncycastle.cert.X509CertificateHolder;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * {@link XmlSignatures} with the JDK's JSR 105 provider (decision-023, LIANA-112.09). Signing
 * produces XAdES-EPES ([XAdES] 1.3.2, TIP1-A_5402) as the vendors do: c14n 1.1 for SignedInfo and
 * the references, one reference to the element from {@code RefURI} and one to {@code
 * SignedProperties} (SigningTime as system time, SigningCertificate with SHA-256,
 * SignaturePolicyIdentifier with empty SigPolicyHash per TIP1-A_5538, DataObjectFormat with the
 * ShortText), {@code ds:KeyInfo/ds:X509Data} with the certificate. The card supplies the signature
 * value via a dedicated JCA provider; ECDSA as ecdsa-sha256 (r||s in the document). Verification
 * uses BouncyCastle (SunEC no longer knows brainpool).
 */
public final class XadesSignatures implements XmlSignatures {

  static final String DS = XMLSignature.XMLNS;
  static final String XADES = "http://uri.etsi.org/01903/v1.3.2#";
  private static final String SIGNED_PROPERTIES = "http://uri.etsi.org/01903#SignedProperties";

  /**
   * Property of the JDK provider: the JCA provider for the signature value (creation and
   * verification).
   */
  private static final String SIGNATURE_PROVIDER =
      "org.jcp.xml.dsig.internal.dom.SignatureProvider";

  private static final String C14N11 = CanonicalizationMethod.INCLUSIVE_11;

  /**
   * Schema of the NFDM signature policy (TUC_KON_080 (A)): NFD_Document with NFDM_Common and
   * xmldsig.
   */
  private static final String NFD_SCHEMA = "fa/nfds/NFD_Document_v1_4.xsd";

  private static final Map<String, String> DIGESTS =
      Map.of(
          DigestMethod.SHA256,
          "SHA-256",
          DigestMethod.SHA512,
          "SHA-512",
          DigestMethod.SHA384,
          "SHA-384",
          DigestMethod.SHA1,
          "SHA-1");

  private final Clock clock;
  private volatile Schema nfdSchema;

  public XadesSignatures(Clock clock) {
    this.clock = clock;
  }

  @Override
  public void validate(byte[] document, String signaturePolicy) {
    Document parsed = XmlCodec.parse(document);
    if (NFDM_POLICY.equals(signaturePolicy)) {
      try {
        nfdSchema().newValidator().validate(new DOMSource(parsed));
      } catch (SAXException e) {
        throw ConnectorError.XML_NOT_VALID
            .exception("NFD_Document_v1_4.xsd: " + e.getMessage())
            .causedBy(e);
      } catch (IOException e) {
        throw new IllegalStateException(e);
      }
      return;
    }
    Set<String> ids = new HashSet<>();
    for (Attr id : ids(parsed.getDocumentElement(), new ArrayList<>())) {
      if (!ids.add(id.getValue())) {
        throw ConnectorError.XML_NOT_WELL_FORMED.exception(
            "ID-Attributwert doppelt: " + id.getValue());
      }
    }
  }

  private Schema nfdSchema() {
    Schema schema = nfdSchema;
    if (schema == null) {
      schema = RequestValidation.compile(Schemas.resource(NFD_SCHEMA));
      nfdSchema = schema;
    }
    return schema;
  }

  @Override
  public byte[] sign(Request request, UnaryOperator<byte[]> signHash) {
    Document document = XmlCodec.parse(request.document());
    ids(document.getDocumentElement(), new ArrayList<>())
        .forEach(a -> a.getOwnerElement().setIdAttributeNode(a, true));
    Element parent = element(document, request.xPathFirstChildOf());
    Element signed = document.getElementById(request.referenceUri().substring(1));
    if (signed == null) {
      throw ConnectorError.INVALID_SIGNATURE_TYPE.exception(
          "RefURI " + request.referenceUri() + " trifft kein " + "Element");
    }
    if (contains(signed, parent)) {
      // TAB_KON_778: outside the signed subtree
      throw ConnectorError.INVALID_SIGNATURE_TYPE.exception("Signatur läge im signierten Element");
    }
    X509Certificate certificate = certificate(request.certificate());
    // TUC_KON_165 step 3: valid at the signing time
    try {
      certificate.checkValidity(java.util.Date.from(clock.instant()));
    } catch (java.security.cert.CertificateExpiredException
        | java.security.cert.CertificateNotYetValidException e) {
      throw ConnectorError.CERTIFICATE_NOT_VALID_TIME.exception(
          certificate.getSubjectX500Principal().getName());
    }
    try {
      XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
      String suffix = UUID.randomUUID().toString();
      String signatureId = "Signature-" + suffix;
      String propertiesId = "SignedProperties-" + suffix;
      String documentReferenceId = "Reference-Document-" + suffix;
      List<Transform> c14n = List.of(factory.newTransform(C14N11, (TransformParameterSpec) null));
      DigestMethod sha256 = factory.newDigestMethod(DigestMethod.SHA256, null);
      SignedInfo signedInfo =
          factory.newSignedInfo(
              factory.newCanonicalizationMethod(C14N11, (C14NMethodParameterSpec) null),
              factory.newSignatureMethod(SignatureMethod.ECDSA_SHA256, null),
              List.of(
                  factory.newReference(
                      request.referenceUri(), sha256, c14n, null, documentReferenceId),
                  factory.newReference("#" + propertiesId, sha256, c14n, SIGNED_PROPERTIES, null)));
      KeyInfoFactory keys = factory.getKeyInfoFactory();
      Element properties =
          qualifyingProperties(
              document, signatureId, propertiesId, documentReferenceId, certificate, request);
      XMLSignature signature =
          factory.newXMLSignature(
              signedInfo,
              keys.newKeyInfo(List.of(keys.newX509Data(List.of(certificate)))),
              List.of(
                  factory.newXMLObject(List.of(new DOMStructure(properties)), null, null, null)),
              signatureId,
              null);
      CardKey key = new CardKey(((ECPublicKey) certificate.getPublicKey()).getParams());
      DOMSignContext context =
          parent.getFirstChild() == null
              ? new DOMSignContext(key, parent)
              : new DOMSignContext(key, parent, parent.getFirstChild());
      context.setDefaultNamespacePrefix("ds");
      context.setProperty(
          SIGNATURE_PROVIDER, new CardProvider(signHash, certificate.getPublicKey()));
      signature.sign(context);
    } catch (XMLSignatureException | MarshalException e) {
      throw cardError(e);
    } catch (GeneralSecurityException e) {
      throw ConnectorError.INTERNAL.exception("XAdES: " + e.getMessage()).causedBy(e);
    }
    return XmlCodec.serialize(document);
  }

  /**
   * A ConnectorException from the card provider (4120) comes back wrapped in an
   * XMLSignatureException.
   */
  private static RuntimeException cardError(Exception e) {
    for (Throwable cause = e; cause != null; cause = cause.getCause()) {
      if (cause instanceof ConnectorException connector) {
        return connector;
      }
    }
    return ConnectorError.INTERNAL.exception("XAdES: " + e.getMessage()).causedBy(e);
  }

  private Element qualifyingProperties(
      Document document,
      String signatureId,
      String propertiesId,
      String documentReferenceId,
      X509Certificate certificate,
      Request request)
      throws GeneralSecurityException {
    Element qualifying = document.createElementNS(XADES, "xades:QualifyingProperties");
    qualifying.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:xades", XADES);
    qualifying.setAttribute("Target", "#" + signatureId);
    Element properties = add(qualifying, XADES, "SignedProperties");
    properties.setAttribute("Id", propertiesId);
    properties.setIdAttribute("Id", true);
    Element signatureProperties = add(properties, XADES, "SignedSignatureProperties");
    add(signatureProperties, XADES, "SigningTime")
        .setTextContent(clock.instant().truncatedTo(ChronoUnit.SECONDS).toString());
    Element cert = add(add(signatureProperties, XADES, "SigningCertificate"), XADES, "Cert");
    Element digest = add(cert, XADES, "CertDigest");
    add(digest, DS, "DigestMethod").setAttribute("Algorithm", DigestMethod.SHA256);
    add(digest, DS, "DigestValue")
        .setTextContent(
            Base64.getEncoder()
                .encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded())));
    Element issuerSerial = add(cert, XADES, "IssuerSerial");
    add(issuerSerial, DS, "X509IssuerName")
        .setTextContent(certificate.getIssuerX500Principal().getName());
    add(issuerSerial, DS, "X509SerialNumber")
        .setTextContent(certificate.getSerialNumber().toString());
    Element policy =
        add(
            add(signatureProperties, XADES, "SignaturePolicyIdentifier"),
            XADES,
            "SignaturePolicyId");
    add(add(policy, XADES, "SigPolicyId"), XADES, "Identifier")
        .setTextContent(request.signaturePolicy());
    // TIP1-A_5538: SigPolicyHash empty, schema-conformant
    Element policyHash = add(policy, XADES, "SigPolicyHash");
    add(policyHash, DS, "DigestMethod").setAttribute("Algorithm", "");
    add(policyHash, DS, "DigestValue");
    Element format =
        add(add(properties, XADES, "SignedDataObjectProperties"), XADES, "DataObjectFormat");
    format.setAttribute("ObjectReference", "#" + documentReferenceId);
    if (request.shortText() != null && !request.shortText().isEmpty()) {
      // TUC_KON_155: ShortText in DataObjectFormat/Description ([XAdES] 7.2.5)
      add(format, XADES, "Description").setTextContent(request.shortText());
    }
    add(format, XADES, "MimeType").setTextContent("text/xml");
    return qualifying;
  }

  @Override
  public byte[] embedOcsp(byte[] document, String xPathFirstChildOf, byte[] ocspResponse) {
    Document parsed = XmlCodec.parse(document);
    Element signature = firstChild(element(parsed, xPathFirstChildOf));
    if (signature == null
        || !DS.equals(signature.getNamespaceURI())
        || !"Signature".equals(signature.getLocalName())) {
      throw ConnectorError.INTERNAL.exception("keine ds:Signature unter " + xPathFirstChildOf);
    }
    Element qualifying =
        (Element) signature.getElementsByTagNameNS(XADES, "QualifyingProperties").item(0);
    Element unsigned = child(qualifying, "UnsignedProperties");
    Element signatureProperties = child(unsigned, "UnsignedSignatureProperties");
    Element values = child(child(signatureProperties, "RevocationValues"), "OCSPValues");
    add(values, XADES, "EncapsulatedOCSPValue")
        .setTextContent(Base64.getEncoder().encodeToString(ocspResponse));
    return XmlCodec.serialize(parsed);
  }

  @Override
  public String signaturePolicy(byte[] document) {
    NodeList ids = XmlCodec.parse(document).getElementsByTagNameNS(XADES, "SigPolicyId");
    for (int i = 0; i < ids.getLength(); i++) {
      NodeList identifier = ((Element) ids.item(i)).getElementsByTagNameNS(XADES, "Identifier");
      if (identifier.getLength() > 0) {
        return identifier.item(0).getTextContent().strip();
      }
    }
    return null;
  }

  @Override
  public List<Signer> verify(byte[] document) {
    Document parsed = XmlCodec.parse(document);
    ids(parsed.getDocumentElement(), new ArrayList<>())
        .forEach(a -> a.getOwnerElement().setIdAttributeNode(a, true));
    NodeList signatures = parsed.getElementsByTagNameNS(DS, "Signature");
    List<Signer> signers = new ArrayList<>();
    for (int i = 0; i < signatures.getLength(); i++) {
      signers.add(signer((Element) signatures.item(i)));
    }
    return List.copyOf(signers);
  }

  /**
   * TUC_KON_162 for one signature: certificate from KeyInfo, core validation, SigningCertificate,
   * SigningTime.
   */
  private static Signer signer(Element signature) {
    byte[] value = Base64.getMimeDecoder().decode(text(signature, DS, "SignatureValue"));
    Optional<Instant> signingTime = signingTime(signature);
    String encoded = text(signature, DS, "X509Certificate");
    if (encoded.isEmpty()) {
      return new Signer(
          value,
          false,
          null,
          false,
          signingTime,
          List.of(
              new Problem(
                  ConnectorError.SIGNER_CERTIFICATE_MISSING, "ds:Signature ohne X509Certificate")));
    }
    byte[] der = Base64.getMimeDecoder().decode(encoded);
    X509Certificate certificate;
    boolean qualified;
    try {
      certificate = certificate(der);
      qualified = CmsVerifier.qualified(new X509CertificateHolder(der));
    } catch (IOException | RuntimeException e) {
      return new Signer(
          value,
          false,
          null,
          false,
          signingTime,
          List.of(
              new Problem(
                  ConnectorError.SIGNER_CERTIFICATE_MISSING,
                  "X509Certificate nicht lesbar: " + e.getMessage())));
    }
    List<Problem> problems = new ArrayList<>();
    core(signature, certificate.getPublicKey()).ifPresent(problems::add);
    if (problems.isEmpty()) {
      signingCertificate(signature, der).ifPresent(problems::add);
    }
    return new Signer(value, false, der, qualified, signingTime, List.copyOf(problems));
  }

  /** [XMLDSig] 3.2 core validation: references and signature value. */
  @SuppressWarnings("java:S6377") // simulator verifying test signatures, no impact
  private static Optional<Problem> core(Element signature, PublicKey key) {
    try {
      DOMValidateContext context =
          new DOMValidateContext(KeySelector.singletonKeySelector(key), signature);
      context.setProperty(SIGNATURE_PROVIDER, Security.getProvider(CryptoProviders.BC));
      XMLSignature xml = XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(context);
      if (xml.validate(context)) {
        return Optional.empty();
      }
      if (!xml.getSignatureValue().validate(context)) {
        return Optional.of(invalid("SignatureValue falsch"));
      }
      for (Object reference : xml.getSignedInfo().getReferences()) {
        Reference ref = (Reference) reference;
        if (!ref.validate(context)) {
          return Optional.of(invalid("DigestValue der Referenz " + ref.getURI() + " falsch"));
        }
      }
      return Optional.of(invalid("Core Validation fehlgeschlagen"));
    } catch (MarshalException | XMLSignatureException | RuntimeException e) {
      return Optional.of(invalid("Core Validation: " + e.getMessage()));
    }
  }

  /** [XAdES] 7.2.2, G.2.2.5: CertDigest of SigningCertificate matches the signing certificate. */
  private static Optional<Problem> signingCertificate(Element signature, byte[] certificate) {
    NodeList digests = signature.getElementsByTagNameNS(XADES, "CertDigest");
    if (digests.getLength() == 0) {
      return Optional.empty();
    }
    Element digest = (Element) digests.item(0);
    Element method = (Element) digest.getElementsByTagNameNS(DS, "DigestMethod").item(0);
    String algorithm = method == null ? null : DIGESTS.get(method.getAttribute("Algorithm"));
    if (algorithm == null) {
      return Optional.of(invalid("SigningCertificate: DigestMethod unbekannt"));
    }
    try {
      byte[] expected = Base64.getMimeDecoder().decode(text(digest, DS, "DigestValue"));
      if (!MessageDigest.isEqual(
          expected, MessageDigest.getInstance(algorithm).digest(certificate))) {
        return Optional.of(invalid("SigningCertificate passt nicht zum Signaturzertifikat"));
      }
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      return Optional.of(invalid("SigningCertificate nicht lesbar: " + e.getMessage()));
    }
    return Optional.empty();
  }

  private static Optional<Instant> signingTime(Element signature) {
    String text = text(signature, XADES, "SigningTime");
    if (text.isEmpty()) {
      return Optional.empty();
    }
    try {
      return Optional.of(
          OffsetDateTime.parse(text.matches(".*(Z|[+-]\\d\\d:\\d\\d)$") ? text : text + "Z")
              .toInstant());
    } catch (DateTimeParseException e) {
      return Optional.empty();
    }
  }

  private static Problem invalid(String detail) {
    return new Problem(ConnectorError.DOCUMENT_SIGNATURE_INVALID, detail);
  }

  /** The text of the first element {@code ns:name} under {@code parent}, empty if none. */
  private static String text(Element parent, String ns, String name) {
    NodeList nodes = parent.getElementsByTagNameNS(ns, name);
    return nodes.getLength() == 0
        ? ""
        : nodes.item(0).getTextContent().replace("&#13;", "").strip();
  }

  /** The element for {@code xPath}; if it matches none, 4111 (SignaturePlacement). */
  private static Element element(Document document, String xPath) {
    try {
      Object node =
          XPathFactory.newInstance().newXPath().evaluate(xPath, document, XPathConstants.NODE);
      if (node instanceof Element element) {
        return element;
      }
    } catch (XPathExpressionException e) {
      throw ConnectorError.INVALID_SIGNATURE_TYPE
          .exception("XPathFirstChildOf " + xPath + ": " + e.getMessage())
          .causedBy(e);
    }
    throw ConnectorError.INVALID_SIGNATURE_TYPE.exception(
        "XPathFirstChildOf " + xPath + " trifft kein Element");
  }

  /**
   * Attributes {@code ID} and {@code Id} without namespace that resolve fragment references ({@code
   * #ID}).
   */
  private static List<Attr> ids(Element element, List<Attr> found) {
    NamedNodeMap attributes = element.getAttributes();
    for (int i = 0; i < attributes.getLength(); i++) {
      Attr attribute = (Attr) attributes.item(i);
      String name =
          attribute.getLocalName() == null ? attribute.getName() : attribute.getLocalName();
      if (attribute.getNamespaceURI() == null && (name.equals("ID") || name.equals("Id"))) {
        found.add(attribute);
      }
    }
    for (Node child = element.getFirstChild(); child != null; child = child.getNextSibling()) {
      if (child instanceof Element e) {
        ids(e, found);
      }
    }
    return found;
  }

  private static boolean contains(Node ancestor, Node node) {
    for (Node n = node; n != null; n = n.getParentNode()) {
      if (n == ancestor) {
        return true;
      }
    }
    return false;
  }

  private static Element firstChild(Element parent) {
    for (Node child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
      if (child instanceof Element e) {
        return e;
      }
    }
    return null;
  }

  /** The child {@code xades:name} of {@code parent}, created if missing. */
  private static Element child(Element parent, String name) {
    for (Node child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
      if (child instanceof Element e
          && XADES.equals(e.getNamespaceURI())
          && name.equals(e.getLocalName())) {
        return e;
      }
    }
    return add(parent, XADES, name);
  }

  private static Element add(Element parent, String ns, String name) {
    String prefix = DS.equals(ns) ? "ds:" : "xades:";
    Element element = parent.getOwnerDocument().createElementNS(ns, prefix + name);
    parent.appendChild(element);
    return element;
  }

  /** Certificate with BC: the SUN provider cannot handle Brainpool keys. */
  private static X509Certificate certificate(byte[] der) {
    try {
      return (X509Certificate)
          CertificateFactory.getInstance("X.509", CryptoProviders.BC)
              .generateCertificate(new ByteArrayInputStream(der));
    } catch (GeneralSecurityException e) {
      throw ConnectorError.INTERNAL.exception("Signaturzertifikat: " + e.getMessage()).causedBy(e);
    }
  }

  /** Placeholder for the card key: JSR 105 needs the curve for the length of r and s. */
  private record CardKey(ECParameterSpec params) implements ECPrivateKey {
    @Override
    public BigInteger getS() {
      throw new UnsupportedOperationException("Schlüssel auf der Karte");
    }

    @Override
    public ECParameterSpec getParams() {
      return params;
    }

    @Override
    public String getAlgorithm() {
      return "EC";
    }

    @Override
    public String getFormat() {
      return null;
    }

    @Override
    public byte[] getEncoded() {
      return null;
    }
  }

  /**
   * JCA provider for the signature value: SHA256withECDSA over the canonicalized SignedInfo, the
   * hash goes to the card (PSO CDS, as ECDSA-Sig-Value), the mathematical check follows TUC_KON_166
   * step 3 (4120). The service creates the SPI itself, without reflection (native image).
   */
  private static final class CardProvider extends Provider {
    CardProvider(UnaryOperator<byte[]> signHash, PublicKey publicKey) {
      super("LianaCard", "1", "Signaturwert von der Karte");
      putService(
          new Service(this, "Signature", "SHA256withECDSA", CardSpi.class.getName(), null, null) {
            @Override
            public Object newInstance(Object parameter) {
              return new CardSpi(signHash, publicKey);
            }
          });
    }
  }

  private static final class CardSpi extends SignatureSpi {
    private final ByteArrayOutputStream data = new ByteArrayOutputStream();
    private final UnaryOperator<byte[]> signHash;
    private final PublicKey publicKey;

    CardSpi(UnaryOperator<byte[]> signHash, PublicKey publicKey) {
      this.signHash = signHash;
      this.publicKey = publicKey;
    }

    @Override
    protected void engineInitVerify(PublicKey key) throws InvalidKeyException {
      throw new InvalidKeyException("nur Signatur");
    }

    @Override
    protected void engineInitSign(PrivateKey key) {
      data.reset();
    }

    @Override
    protected void engineUpdate(byte b) {
      data.write(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) {
      data.write(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
      try {
        byte[] signedInfo = data.toByteArray();
        byte[] value = signHash.apply(MessageDigest.getInstance("SHA-256").digest(signedInfo));
        java.security.Signature check =
            java.security.Signature.getInstance("SHA256withECDSA", CryptoProviders.BC);
        check.initVerify(publicKey);
        check.update(signedInfo);
        if (!check.verify(value)) {
          throw ConnectorError.CARD_SIGNATURE_INVALID.exception(
              "XAdES-Signaturwert der Karte falsch");
        }
        // ECDSA-Sig-Value (DER) as from CardSignature; JSR 105 converts to r||s ([XMLDSig] 6.4.3)
        return value;
      } catch (GeneralSecurityException e) {
        throw new SignatureException(e);
      }
    }

    @Override
    protected boolean engineVerify(byte[] signature) {
      return false;
    }

    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value) {}

    @Override
    @Deprecated
    protected Object engineGetParameter(String param) {
      return null;
    }
  }
}
