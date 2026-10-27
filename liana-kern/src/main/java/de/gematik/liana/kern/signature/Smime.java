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
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * S/MIME signature ([RFC5751], signatureType {@code urn:ietf:rfc:5751}, nonQES_DocFormate
 * „Optional“, LIANA-112.10) around the CMS signature, TUC_KON_160 „Varianten“:
 *
 * <ul>
 *   <li>TUC_KON_080 (D) „MIME-Dokumentvalidierung“: the structure per [MIME], here a header block
 *       of fields {@code Name: Wert} (with continuation lines), empty line, body, and {@code
 *       MIME-Version}; otherwise 4024 (MIME).
 *   <li>Preparation [S/MIME] 3.1: the MIME entity to sign consists of the {@code Content-*} fields
 *       of the message and its body, canonicalized for text (3.1.1: line endings CRLF); no further
 *       transfer encoding (3.1.2).
 *   <li>Post-processing: the CMS object as {@code application/pkcs7-mime; smime-type=signed-data;
 *       name=smime.p7m}, Base64, as attachment {@code smime.p7m}; all other header fields of the
 *       message are taken over, {@code MIME-Version: 1.0} is set.
 * </ul>
 *
 * <p>For VerifyDocument, {@link #signedData} unpacks such a message again. LIANA neither creates
 * nor checks {@code multipart/signed} (detached, [S/MIME] 3.4.3).
 */
public final class Smime {

  /** The MIME type of the S/MIME message (TUC_KON_160, TAB_KON_757). */
  public static final String MIME_TYPE = "application/pkcs7-mime";

  static final String FILE_NAME = "smime.p7m";
  private static final String CRLF = "\r\n";
  private static final int LINE = 76;

  /**
   * A MIME message per TUC_KON_080 (D).
   *
   * @param headers the header fields, each field with its continuation lines and without line
   *     ending
   * @param body the body after the empty line, unchanged
   */
  record Message(List<String> headers, byte[] body) {

    Optional<String> header(String name) {
      String prefix = name.toLowerCase(Locale.ROOT) + ":";
      return headers.stream()
          .filter(h -> h.toLowerCase(Locale.ROOT).startsWith(prefix))
          .map(h -> h.substring(prefix.length()).replaceAll("\\r?\\n[ \\t]", " ").strip())
          .findFirst();
    }
  }

  private Smime() {}

  /** TUC_KON_080 (D) for a document to be signed as S/MIME; 4024 (MIME) if it is not one. */
  static Message parse(byte[] document) {
    String text = new String(document, StandardCharsets.ISO_8859_1);
    List<String> headers = new ArrayList<>();
    int position = 0;
    while (position < text.length()) {
      int end = text.indexOf('\n', position);
      String line =
          (end < 0 ? text.substring(position) : text.substring(position, end))
              .replaceFirst("\r$", "");
      position = end < 0 ? text.length() : end + 1;
      if (line.isEmpty()) {
        break;
      }
      if (line.charAt(0) == ' ' || line.charAt(0) == '\t') {
        if (headers.isEmpty()) {
          throw invalid("Folgezeile ohne Header-Feld");
        }
        headers.set(headers.size() - 1, headers.getLast() + CRLF + line);
      } else if (fieldName(line)) {
        headers.add(line);
      } else {
        throw invalid("kein Header-Feld: " + abbreviate(line));
      }
    }
    Message message =
        new Message(List.copyOf(headers), Arrays.copyOfRange(document, position, document.length));
    if (message.header("MIME-Version").isEmpty()) {
      throw invalid("MIME-Version fehlt");
    }
    return message;
  }

  /**
   * The MIME entity to sign ([S/MIME] 3.1): the {@code Content-*} fields and the body, line endings
   * CRLF (3.1.1).
   */
  static byte[] entity(Message message) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (String header : message.headers()) {
      if (content(header)) {
        out.writeBytes(canonical(header.getBytes(StandardCharsets.ISO_8859_1)));
        out.writeBytes(CRLF.getBytes(StandardCharsets.US_ASCII));
      }
    }
    out.writeBytes(CRLF.getBytes(StandardCharsets.US_ASCII));
    out.writeBytes(canonical(message.body()));
    return out.toByteArray();
  }

  /**
   * The S/MIME message for the SignedData {@code signedData} (TUC_KON_160, S/MIME post-processing
   * step).
   */
  static byte[] message(Message original, byte[] signedData) {
    StringBuilder out = new StringBuilder();
    for (String header : original.headers()) {
      if (!content(header) && !header.toLowerCase(Locale.ROOT).startsWith("mime-version:")) {
        out.append(header).append(CRLF);
      }
    }
    out.append("MIME-Version: 1.0")
        .append(CRLF)
        .append("Content-Type: ")
        .append(MIME_TYPE)
        .append("; smime-type=signed-data; name=\"")
        .append(FILE_NAME)
        .append('"')
        .append(CRLF)
        .append("Content-Transfer-Encoding: base64")
        .append(CRLF)
        .append("Content-Disposition: attachment; filename=\"")
        .append(FILE_NAME)
        .append('"')
        .append(CRLF)
        .append(CRLF);
    String base64 = Base64.getEncoder().encodeToString(signedData);
    for (int i = 0; i < base64.length(); i += LINE) {
      out.append(base64, i, Math.min(base64.length(), i + LINE)).append(CRLF);
    }
    return out.toString().getBytes(StandardCharsets.ISO_8859_1);
  }

  /**
   * The SignedData of an S/MIME message for VerifyDocument: TUC_KON_080 (D), then {@code
   * Content-Type} {@code application/pkcs7-mime} (or {@code application/x-pkcs7-mime}) with Base64
   * in the body; otherwise 4024 (MIME), e.g. without Content-Type (KUC_1603_010).
   */
  public static byte[] signedData(byte[] smime) {
    Message message = parse(smime);
    String type = message.header("Content-Type").orElseThrow(() -> invalid("Content-Type fehlt"));
    String media = type.split(";", 2)[0].strip().toLowerCase(Locale.ROOT);
    if (!media.equals(MIME_TYPE) && !media.equals("application/x-pkcs7-mime")) {
      throw invalid("Content-Type " + media);
    }
    String encoding =
        message.header("Content-Transfer-Encoding").orElse("7bit").toLowerCase(Locale.ROOT);
    if (!encoding.equals("base64")) {
      throw invalid("Content-Transfer-Encoding " + encoding);
    }
    try {
      return Base64.getMimeDecoder().decode(message.body());
    } catch (IllegalArgumentException e) {
      throw invalid("Body nicht Base64");
    }
  }

  /** Line endings CRLF ([S/MIME] 3.1.1): a single LF or CR becomes CRLF. */
  static byte[] canonical(byte[] text) {
    ByteArrayOutputStream out = new ByteArrayOutputStream(text.length + text.length / 40);
    for (int i = 0; i < text.length; i++) {
      byte b = text[i];
      if (b == '\r') {
        out.write('\r');
        out.write('\n');
        if (i + 1 < text.length && text[i + 1] == '\n') {
          i++;
        }
      } else if (b == '\n') {
        out.write('\r');
        out.write('\n');
      } else {
        out.write(b);
      }
    }
    return out.toByteArray();
  }

  private static boolean content(String header) {
    return header.toLowerCase(Locale.ROOT).startsWith("content-");
  }

  /** RFC 5322 3.6.8: field-name of printable ASCII without colon, then {@code :}. */
  private static boolean fieldName(String line) {
    int colon = line.indexOf(':');
    if (colon <= 0) {
      return false;
    }
    for (int i = 0; i < colon; i++) {
      char c = line.charAt(i);
      if (c < 33 || c > 126) {
        return false;
      }
    }
    return true;
  }

  private static String abbreviate(String line) {
    return line.length() > 40 ? line.substring(0, 40) + "…" : line;
  }

  private static RuntimeException invalid(String detail) {
    ConnectorError error = ConnectorError.FORMAT_VALIDATION_FAILED;
    return error.exception(error.text().replace("%Format%", "MIME"), "TUC_KON_080 (D): " + detail);
  }
}
