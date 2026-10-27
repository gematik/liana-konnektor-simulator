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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

/**
 * Vertrauensraum (Vertrauensraum) for TUC_KON_037: the CA certificates of the TSL (TSPService with
 * ServiceTypeIdentifier {@value #CA_PKC}, TUC_PKI_013) and CERT_IMPORTED_CA_LIST; for the QES
 * (TUC_PKI_030) the qualified CAs of the BNetzA-VL (TSPService {@value #CA_QC} and {@value
 * #NATIONAL_ROOT_CA_QC}, LIANA-112.07).
 *
 * <p>LIANA loads the TSL as a file from the boot configuration, in the image the one fetched at
 * build time (LIANA-180). LIANA does not evaluate the TSL's XML signature, ServiceStatus and
 * NextUpdate. {@link #replaceTsl} swaps the TSL's CAs at runtime for those of a TSL retrieved
 * online; imported CAs and the BNetzA-VL remain.
 */
public final class TrustSpace {

  static final String CA_PKC = "http://uri.etsi.org/TrstSvc/Svctype/CA/PKC";
  static final String CA_QC = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
  static final String NATIONAL_ROOT_CA_QC = "http://uri.etsi.org/TrstSvc/Svctype/NationalRootCA-QC";

  /** Where a CA certificate comes from: TUC_KON_037 1a (imported) or 1b (TSL). */
  public enum Source {
    TSL,
    IMPORTED,
    BNETZA_VL
  }

  public record Ca(X509Certificate certificate, Source source) {}

  /**
   * Header data of the TSL for log and admin; {@code loading} the load time, {@code parsing} the
   * share for the certificates (LIANA-178).
   */
  public record TslInfo(
      String source,
      String sequenceNumber,
      String nextUpdate,
      int caCount,
      java.time.Duration loading,
      java.time.Duration parsing) {

    /** TSLSequenceNumber as a number, {@code -1} if absent or unreadable. */
    public long sequence() {
      try {
        return sequenceNumber == null ? -1 : Long.parseLong(sequenceNumber);
      } catch (NumberFormatException e) {
        return -1;
      }
    }
  }

  /** CAs of the TSL with imported CAs first, and the TSL's header data; swapped as a whole. */
  private record Tsl(List<Ca> cas, TslInfo info) {}

  private final List<Ca> imported;
  private volatile Tsl tsl;

  /** Qualified CAs of the BNetzA-VL. */
  private final List<Ca> qualified;

  private final TslInfo vl;

  private TrustSpace(
      List<Ca> imported, List<Ca> tslCas, TslInfo tsl, List<Ca> qualified, TslInfo vl) {
    this.imported = List.copyOf(imported);
    this.tsl = new Tsl(concat(this.imported, tslCas), tsl);
    this.qualified = List.copyOf(qualified);
    this.vl = vl;
  }

  private static List<Ca> concat(List<Ca> first, List<Ca> second) {
    List<Ca> all = new ArrayList<>(first);
    all.addAll(second);
    return List.copyOf(all);
  }

  /**
   * Loads the TSL and the imported CA certificates (PEM or DER).
   *
   * @throws IllegalStateException if a file is missing or unreadable
   */
  public static TrustSpace load(Path tslFile, List<Path> importedCas) {
    return load(tslFile, importedCas, null);
  }

  /**
   * Like {@link #load(Path, List)}, plus the BNetzA-VL; {@code null} for none, then no QES has an
   * issuer.
   *
   * @throws IllegalStateException if a file is missing or unreadable
   */
  public static TrustSpace load(Path tslFile, List<Path> importedCas, Path vlFile) {
    List<Ca> imported = new ArrayList<>();
    for (Path file : importedCas) {
      try {
        imported.add(new Ca(certificate(pemOrDer(Files.readAllBytes(file))), Source.IMPORTED));
      } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {
        throw new IllegalStateException(
            "importiertes CA-Zertifikat " + file + " nicht lesbar: " + e.getMessage(), e);
      }
    }
    List<Ca> tslCas = new ArrayList<>();
    TslInfo tsl = readTsl(tslFile, tslCas, Source.TSL, List.of(CA_PKC));
    List<Ca> qualified = new ArrayList<>();
    TslInfo vl =
        vlFile == null
            ? null
            : readTsl(vlFile, qualified, Source.BNETZA_VL, List.of(CA_QC, NATIONAL_ROOT_CA_QC));
    return new TrustSpace(imported, tslCas, tsl, qualified, vl);
  }

  public TslInfo tsl() {
    return tsl.info();
  }

  /**
   * LIANA-180: replaces the TSL's CAs with those from {@code content} (TSL XML, origin {@code
   * source}) if it is readable, contains CA certificates and its TSLSequenceNumber is not lower
   * than that of the loaded one. Otherwise the loaded TSL remains.
   *
   * @return the header data of the new TSL, empty if the loaded one is newer
   * @throws IllegalStateException if {@code content} is not a readable TSL with CA certificates
   */
  public synchronized Optional<TslInfo> replaceTsl(byte[] content, String source) {
    List<Ca> tslCas = new ArrayList<>();
    TslInfo info =
        readTsl(new ByteArrayInputStream(content), source, tslCas, Source.TSL, List.of(CA_PKC));
    if (info.sequence() < tsl.info().sequence()) {
      return Optional.empty();
    }
    tsl = new Tsl(concat(imported, tslCas), info);
    return Optional.of(info);
  }

  /** Header data of the BNetzA-VL, empty if none. */
  public Optional<TslInfo> vl() {
    return Optional.ofNullable(vl);
  }

  public int importedCount() {
    return imported.size();
  }

  /**
   * TUC_PKI_003: the CA certificate that issued {@code certificate} – same name and, if both are
   * set, AuthorityKeyIdentifier equal to SubjectKeyIdentifier. Imported CAs come first (TUC_KON_037
   * 1a).
   */
  public Optional<Ca> issuerOf(X509Certificate certificate) {
    return issuerOf(certificate, tsl.cas());
  }

  /**
   * TUC_PKI_030: the qualified CA of the BNetzA-VL that issued {@code certificate} (like
   * TUC_PKI_003).
   */
  public Optional<Ca> qualifiedIssuerOf(X509Certificate certificate) {
    return issuerOf(certificate, qualified);
  }

  private static Optional<Ca> issuerOf(X509Certificate certificate, List<Ca> cas) {
    byte[] authorityKeyId = authorityKeyId(certificate);
    return cas.stream()
        .filter(
            ca ->
                ca.certificate()
                    .getSubjectX500Principal()
                    .equals(certificate.getIssuerX500Principal()))
        .filter(
            ca ->
                authorityKeyId == null
                    || subjectKeyId(ca.certificate()) == null
                    || Arrays.equals(authorityKeyId, subjectKeyId(ca.certificate())))
        .findFirst();
  }

  /**
   * Reads the CA certificates of the TSPServices with one of the {@code serviceTypes}; an entry
   * that BouncyCastle cannot read is dropped (the BNetzA-VL also lists foreign formats).
   */
  private static TslInfo readTsl(
      Path file, List<Ca> cas, Source source, List<String> serviceTypes) {
    try (InputStream in = Files.newInputStream(file)) {
      return readTsl(in, file.toString(), cas, source, serviceTypes);
    } catch (IOException e) {
      throw new IllegalStateException("TSL " + file + " nicht lesbar: " + e.getMessage(), e);
    }
  }

  private static TslInfo readTsl(
      InputStream in, String file, List<Ca> cas, Source source, List<String> serviceTypes) {
    String sequenceNumber = null;
    String nextUpdate = null;
    int count = 0;
    long start = System.nanoTime();
    long parsing = 0;
    try {
      XMLInputFactory factory = XMLInputFactory.newFactory();
      factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
      factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
      XMLStreamReader xml = factory.createXMLStreamReader(in);
      String serviceType = null;
      List<String> serviceCertificates = new ArrayList<>();
      boolean inNextUpdate = false;
      while (xml.hasNext()) {
        int event = xml.next();
        if (event == XMLStreamConstants.START_ELEMENT) {
          switch (xml.getLocalName()) {
            case "TSLSequenceNumber" -> sequenceNumber = xml.getElementText().strip();
            case "NextUpdate" -> inNextUpdate = true;
            case "dateTime" -> {
              if (inNextUpdate) {
                nextUpdate = xml.getElementText().strip();
              }
            }
            case "TSPService" -> {
              serviceType = null;
              serviceCertificates.clear();
            }
            case "ServiceTypeIdentifier" -> serviceType = xml.getElementText().strip();
            case "X509Certificate" -> serviceCertificates.add(xml.getElementText());
            default -> {}
          }
        } else if (event == XMLStreamConstants.END_ELEMENT) {
          switch (xml.getLocalName()) {
            case "NextUpdate" -> inNextUpdate = false;
            case "TSPService" -> {
              if (serviceTypes.contains(serviceType)) {
                for (String base64 : serviceCertificates) {
                  long before = System.nanoTime();
                  try {
                    cas.add(new Ca(certificate(Base64.getMimeDecoder().decode(base64)), source));
                    count++;
                  } catch (GeneralSecurityException | IllegalArgumentException e) {
                    if (source == Source.TSL) {
                      throw e;
                    }
                  } finally {
                    parsing += System.nanoTime() - before;
                  }
                }
              }
            }
            default -> {}
          }
        }
      }
    } catch (XMLStreamException | GeneralSecurityException | IllegalArgumentException e) {
      throw new IllegalStateException("TSL " + file + " nicht lesbar: " + e.getMessage(), e);
    }
    if (count == 0) {
      throw new IllegalStateException(
          "TSL " + file + " enthält keine CA-Zertifikate " + serviceTypes);
    }
    return new TslInfo(
        file,
        sequenceNumber,
        nextUpdate,
        count,
        java.time.Duration.ofNanos(System.nanoTime() - start),
        java.time.Duration.ofNanos(parsing));
  }

  private static X509Certificate certificate(byte[] der) throws GeneralSecurityException {
    return (X509Certificate)
        CertificateFactory.getInstance("X.509", CryptoProviders.BC)
            .generateCertificate(new ByteArrayInputStream(der));
  }

  private static byte[] pemOrDer(byte[] content) {
    String text = new String(content, StandardCharsets.US_ASCII);
    if (!text.contains("-----BEGIN CERTIFICATE-----")) {
      return content;
    }
    return Base64.getMimeDecoder().decode(text.replaceAll("-----[A-Z ]+-----", ""));
  }

  static byte[] authorityKeyId(X509Certificate certificate) {
    byte[] extension = certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
    return extension == null
        ? null
        : AuthorityKeyIdentifier.getInstance(ScenarioSignerCheck.parse(extension))
            .getKeyIdentifier();
  }

  static byte[] subjectKeyId(X509Certificate certificate) {
    byte[] extension = certificate.getExtensionValue(Extension.subjectKeyIdentifier.getId());
    return extension == null
        ? null
        : SubjectKeyIdentifier.getInstance(ScenarioSignerCheck.parse(extension)).getKeyIdentifier();
  }
}
