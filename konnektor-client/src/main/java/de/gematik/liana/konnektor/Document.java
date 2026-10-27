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
package de.gematik.liana.konnektor;

import java.util.Objects;

/**
 * A document for signing, verification and encryption (LIANA-136): content and MIME type,
 * optionally a short text for the Trusted Viewer.
 *
 * @param content content
 * @param mimeType MIME type, such as {@code application/pdf-a} for PAdES (gemSpec_Kon: otherwise
 *     4111)
 * @param xml whether the content is XML ({@code Base64XML} instead of {@code Base64Data})
 * @param shortText {@code ShortText} or {@code null}
 */
public record Document(byte[] content, String mimeType, boolean xml, String shortText) {

  public Document {
    content = Objects.requireNonNull(content, "content").clone();
  }

  @Override
  public byte[] content() {
    return content.clone();
  }

  /** Binary document with MIME type. */
  public static Document of(byte[] content, String mimeType) {
    return new Document(content, mimeType, false, null);
  }

  /** PDF/A for PAdES. */
  public static Document pdfA(byte[] content) {
    return new Document(content, "application/pdf-a", false, null);
  }

  /** XML document for XAdES. */
  public static Document xml(byte[] content) {
    return new Document(content, "text/xml", true, null);
  }

  /** The same document with a short text. */
  public Document withShortText(String text) {
    return new Document(content, mimeType, xml, text);
  }
}
