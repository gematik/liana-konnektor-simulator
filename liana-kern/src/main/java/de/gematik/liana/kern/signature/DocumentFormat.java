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

import de.gematik.liana.kern.error.ConnectorError;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.IllegalCharsetNameException;
import java.nio.charset.StandardCharsets;
import java.nio.charset.UnsupportedCharsetException;
import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;
import java.util.OptionalInt;

/**
 * Document formats per gemSpec_Kon 3.1.1: XML ({@code CONN:Base64XML}), otherwise by MIME type
 * PDF/A ({@code application/pdf-a}), text ({@code text/plain}), TIFF ({@code image/tiff}) and
 * binary for all others. QES_DocFormate are all except binary (TUC_KON_150: 4110).
 */
public enum DocumentFormat {
  XML("XML"),
  PDF_A("PDF/A"),
  TEXT("Text"),
  TIFF("TIFF"),
  BINARY("Binär");

  /** TIFF6: byte order „II“ or „MM“, then 42 in that byte order. */
  private static final byte[] TIFF_LE = {'I', 'I', 42, 0};

  private static final byte[] TIFF_BE = {'M', 'M', 0, 42};

  private final String label;

  DocumentFormat(String label) {
    this.label = label;
  }

  /** The name from 3.1.1, for %Format% in the error texts. */
  public String label() {
    return label;
  }

  public static DocumentFormat of(SignRequest.Document document) {
    if (document.xml()) {
      return XML;
    }
    return switch (mediaType(document.mimeType())) {
      case "application/pdf-a" -> PDF_A;
      case "text/plain" -> TEXT;
      case "image/tiff" -> TIFF;
      default -> BINARY;
    };
  }

  /**
   * TUC_KON_080 „Dokument validieren“ (TIP1-A_4527-04) for XML ((A) via {@link
   * XmlSignatures#validate}: 4022, with signature policy 4023), PDF/A ({@link #validatePdfA}), text
   * (E: character encoding from the MIME type, UTF-8 if not given, a BOM is allowed) and TIFF (C:
   * the first 8 bytes); otherwise 4024. Binary is not validated.
   *
   * @param signaturePolicy the signature policy for XML, {@code null} for none
   */
  public static void validate(
      SignRequest.Document document, String signaturePolicy, PdfSignatures pdf, XmlSignatures xml) {
    DocumentFormat format = of(document);
    byte[] content = document.content();
    if (format == XML) {
      xml.validate(content, signaturePolicy);
      return;
    }
    boolean valid =
        switch (format) {
          case PDF_A -> pdfA(content, pdf);
          case TEXT -> decodes(content, charset(document.mimeType()));
          case TIFF ->
              content.length >= 8
                  && (Arrays.equals(content, 0, 4, TIFF_LE, 0, 4)
                      || Arrays.equals(content, 0, 4, TIFF_BE, 0, 4));
          default -> true;
        };
    if (!valid) {
      throw failed(format);
    }
  }

  /**
   * TUC_KON_080 (B) „PDF/A-Dokumentvalidierung“: the document identifies itself in its XMP metadata
   * as PDF/A-1 or PDF/A-2; PDF/A-3 (A_18780), another part or no identification → 4024 with
   * document format PDF/A.
   */
  public static void validatePdfA(byte[] content, PdfSignatures pdf) {
    if (!pdfA(content, pdf)) {
      throw failed(PDF_A);
    }
  }

  private static boolean pdfA(byte[] content, PdfSignatures pdf) {
    OptionalInt part = pdf.pdfaPart(content);
    return part.isPresent() && (part.getAsInt() == 1 || part.getAsInt() == 2);
  }

  private static RuntimeException failed(DocumentFormat format) {
    ConnectorError error = ConnectorError.FORMAT_VALIDATION_FAILED;
    return error.exception(
        error.text().replace("%Format%", format.label), "TUC_KON_080 " + format.label);
  }

  private static String mediaType(String mimeType) {
    if (mimeType == null) {
      return "";
    }
    int semicolon = mimeType.indexOf(';');
    return (semicolon < 0 ? mimeType : mimeType.substring(0, semicolon))
        .strip()
        .toLowerCase(Locale.ROOT);
  }

  /** Parameter {@code charset} of the MIME type; empty if the connector does not know it. */
  private static Optional<Charset> charset(String mimeType) {
    String name = null;
    for (String parameter : (mimeType == null ? "" : mimeType).split(";")) {
      String[] pair = parameter.split("=", 2);
      if (pair.length == 2 && pair[0].strip().equalsIgnoreCase("charset")) {
        name = pair[1].strip().replace("\"", "");
      }
    }
    if (name == null) {
      return Optional.of(StandardCharsets.UTF_8);
    }
    try {
      return Optional.of(Charset.forName(name));
    } catch (IllegalCharsetNameException | UnsupportedCharsetException e) {
      return Optional.empty();
    }
  }

  private static boolean decodes(byte[] content, Optional<Charset> charset) {
    if (charset.isEmpty()) {
      return false;
    }
    try {
      charset
          .get()
          .newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(content));
      return true;
    } catch (CharacterCodingException e) {
      return false;
    }
  }
}
