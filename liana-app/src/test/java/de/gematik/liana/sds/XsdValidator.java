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
package de.gematik.liana.sds;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Pattern;
import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import org.w3c.dom.ls.LSInput;
import org.xml.sax.SAXException;

/**
 * Validates rendered templates against the pinned schemas from {@code support/schemas/}
 * (decision-2). External schema access is restricted to local files, so validation runs without
 * network. The W3C schemas {@code xmldsig-core-schema.xsd} and {@code xenc-schema.xsd} refer via
 * DOCTYPE to a non-pinned {@code XMLSchema.dtd}; the DOCTYPE is removed on loading.
 */
public final class XsdValidator {

  private static final Path SCHEMAS = Path.of("support/schemas");
  private static final Pattern DOCTYPE =
      Pattern.compile("<!DOCTYPE[^\\[>]*(\\[.*?\\])?\\s*>", Pattern.DOTALL);

  private XsdValidator() {}

  /** Throws {@link SAXException} with line and reason if {@code xml} does not match the schema. */
  public static void validate(String schema, String xml) throws Exception {
    SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
    factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "file");
    factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    factory.setResourceResolver(
        (type, namespace, publicId, systemId, baseUri) -> {
          if (systemId == null || baseUri == null) {
            return null;
          }
          return new Input(URI.create(baseUri).resolve(systemId).toString());
        });
    Schema compiled = factory.newSchema(SCHEMAS.resolve(schema).toFile());
    compiled.newValidator().validate(new StreamSource(new StringReader(xml)));
  }

  /** An imported schema file without DOCTYPE. */
  private record Input(String systemId) implements LSInput {

    @Override
    public Reader getCharacterStream() {
      try {
        return new StringReader(
            DOCTYPE.matcher(Files.readString(Path.of(URI.create(systemId)))).replaceFirst(""));
      } catch (IOException e) {
        throw new UncheckedIOException(e);
      }
    }

    @Override
    public String getSystemId() {
      return systemId;
    }

    @Override
    public void setCharacterStream(Reader characterStream) {}

    @Override
    public InputStream getByteStream() {
      return null;
    }

    @Override
    public void setByteStream(InputStream byteStream) {}

    @Override
    public String getStringData() {
      return null;
    }

    @Override
    public void setStringData(String stringData) {}

    @Override
    public void setSystemId(String systemId) {}

    @Override
    public String getPublicId() {
      return null;
    }

    @Override
    public void setPublicId(String publicId) {}

    @Override
    public String getBaseURI() {
      return systemId;
    }

    @Override
    public void setBaseURI(String baseURI) {}

    @Override
    public String getEncoding() {
      return null;
    }

    @Override
    public void setEncoding(String encoding) {}

    @Override
    public boolean getCertifiedText() {
      return false;
    }

    @Override
    public void setCertifiedText(boolean certifiedText) {}
  }
}
