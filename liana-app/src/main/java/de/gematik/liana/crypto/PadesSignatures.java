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
import de.gematik.liana.kern.signature.PdfSignatures;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.TimeZone;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.common.PDMetadata;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;

/**
 * {@link PdfSignatures} with Apache PDFBox 3 (decision-020, LIANA-112.08). LIANA reads the PDF/A
 * identification only from {@code pdfaid:part} of the XMP metadata (gemSpec_Kon TUC_KON_080 (B)),
 * in element as well as attribute form. Signing is done as an incremental update per [PDF/A-2]
 * 7.5.6 (TAB_KON_779-01): an invisible signature field with filter Adobe.PPKLite, SubFilter
 * ETSI.CAdES.detached, {@code /M} (system time) and {@code /Reason}, the CMS signature from {@link
 * CadesSignatures#pades} in {@code /Contents}.
 */
public final class PadesSignatures implements PdfSignatures {

  private static final COSName ETSI_CADES_DETACHED = COSName.getPDFName("ETSI.CAdES.detached");

  /** Space for {@code /Contents} in bytes: SignedData with one certificate, RSA 2048 or ECC. */
  private static final int SIGNATURE_SIZE = 16_384;

  private static final Pattern PDFAID_PART =
      Pattern.compile("pdfaid:part(?:\\s*>|\\s*=\\s*[\"'])\\s*(\\d+)");

  private final CadesSignatures cades;
  private final Clock clock;

  public PadesSignatures(Clock clock) {
    this.cades = new CadesSignatures(clock);
    this.clock = clock;
  }

  @Override
  public OptionalInt pdfaPart(byte[] document) {
    try (PDDocument pdf = Loader.loadPDF(document)) {
      PDMetadata metadata = pdf.getDocumentCatalog().getMetadata();
      if (metadata == null) {
        return OptionalInt.empty();
      }
      Matcher part =
          PDFAID_PART.matcher(new String(metadata.toByteArray(), StandardCharsets.UTF_8));
      return part.find() ? OptionalInt.of(Integer.parseInt(part.group(1))) : OptionalInt.empty();
    } catch (IOException | RuntimeException e) {
      return OptionalInt.empty();
    }
  }

  @Override
  public byte[] sign(Request request, UnaryOperator<byte[]> signHash) {
    byte[] document = request.document();
    try (PDDocument pdf = Loader.loadPDF(document);
        SignatureOptions options = new SignatureOptions()) {
      PDSignature signature = new PDSignature();
      signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
      signature.setSubFilter(ETSI_CADES_DETACHED);
      signature.setSignDate(calendar(clock.instant()));
      if (request.reason() != null && !request.reason().isEmpty()) {
        signature.setReason(request.reason());
      }
      options.setPreferredSignatureSize(SIGNATURE_SIZE);
      pdf.addSignature(signature, options);
      ByteArrayOutputStream out =
          new ByteArrayOutputStream(document.length + 2 * SIGNATURE_SIZE + 4096);
      ExternalSigningSupport external = pdf.saveIncrementalForExternalSigning(out);
      byte[] signedContent = external.getContent().readAllBytes();
      external.setSignature(cades.pades(signedContent, request.certificate(), signHash));
      return out.toByteArray();
    } catch (IOException e) {
      throw ConnectorError.INTERNAL.exception("PAdES-Signatur: " + e.getMessage()).causedBy(e);
    }
  }

  @Override
  public List<Embedded> signatures(byte[] document) {
    try (PDDocument pdf = Loader.loadPDF(document)) {
      List<Embedded> signatures = new ArrayList<>();
      for (PDSignature signature : pdf.getSignatureDictionaries()) {
        Calendar signed = signature.getSignDate();
        signatures.add(
            new Embedded(
                signature.getContents(document),
                signature.getSignedContent(document),
                Optional.ofNullable(signed).map(Calendar::toInstant)));
      }
      return List.copyOf(signatures);
    } catch (IOException e) {
      ConnectorError error = ConnectorError.FORMAT_VALIDATION_FAILED;
      throw error
          .exception(
              error.text().replace("%Format%", "PDF/A"), "PDF nicht lesbar: " + e.getMessage())
          .causedBy(e);
    }
  }

  private static Calendar calendar(Instant instant) {
    Calendar calendar = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
    calendar.setTimeInMillis(instant.toEpochMilli());
    return calendar;
  }
}
