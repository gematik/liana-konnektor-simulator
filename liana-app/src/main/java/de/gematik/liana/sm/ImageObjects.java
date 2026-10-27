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
package de.gematik.liana.sm;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

/**
 * Objects of a card image in gematik XML format that LIANA reads for the trusted channel
 * (LIANA-28): private ELC keys of the virtual twin, CV certificates of the gSMC-KT and the card's
 * trust anchors. The image is test material; private keys are stored in it in plain text ({@code
 * privateKey}).
 */
public final class ImageObjects {

  private static final HexFormat HEX = HexFormat.of().withUpperCase();
  private static final String BRAINPOOL_P256 = "brainpoolP256r1";

  /** A {@code child} of the image with its attributes. */
  record Node(String id, String objectType, Map<String, String> attributes) {}

  private final Path image;
  private final List<Node> nodes;

  private ImageObjects(Path image, List<Node> nodes) {
    this.image = image;
    this.nodes = List.copyOf(nodes);
  }

  public static ImageObjects load(Path image) {
    XMLInputFactory factory = XMLInputFactory.newDefaultFactory();
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    List<Node> nodes = new ArrayList<>();
    try (InputStream in = Files.newInputStream(image)) {
      XMLStreamReader xml = factory.createXMLStreamReader(in);
      try {
        Deque<Node> open = new ArrayDeque<>();
        while (xml.hasNext()) {
          int event = xml.next();
          if (event == XMLStreamReader.START_ELEMENT && "child".equals(xml.getLocalName())) {
            Node node =
                new Node(
                    xml.getAttributeValue(null, "id"),
                    xml.getAttributeValue(null, "objectType"),
                    new HashMap<>());
            nodes.add(node);
            open.push(node);
          } else if (event == XMLStreamReader.END_ELEMENT && "child".equals(xml.getLocalName())) {
            open.pop();
          } else if (event == XMLStreamReader.START_ELEMENT
              && "attribute".equals(xml.getLocalName())
              && !open.isEmpty()) {
            String id = xml.getAttributeValue(null, "id");
            open.peek().attributes().put(id, xml.getElementText().strip());
          }
        }
      } finally {
        xml.close();
      }
    } catch (XMLStreamException e) {
      throw new IllegalArgumentException(
          "Kartenimage " + image + " ist kein gültiges XML: " + e.getMessage(), e);
    } catch (IOException e) {
      throw new UncheckedIOException("Kartenimage " + image + " nicht lesbar", e);
    }
    return new ImageObjects(image, nodes);
  }

  public Path image() {
    return image;
  }

  /**
   * The private key with {@code keyIdentifier} (P2 or tag 84 of MSE SET AT) that supports {@code
   * algorithm} (e.g. {@code elcSessionkey4SM}), on brainpoolP256r1; empty if the image contains no
   * such key.
   */
  public Optional<ElcSessionkey4Sm.KeyPair> privateKey(int keyIdentifier, String algorithm) {
    String reference = String.format("%02x", keyIdentifier);
    return nodes.stream()
        .filter(node -> "PrivateElcKey".equals(node.objectType()))
        .filter(node -> reference.equalsIgnoreCase(node.attributes().get("keyIdentifier")))
        .filter(node -> BRAINPOOL_P256.equals(node.attributes().get("domainParameterOid")))
        .filter(
            node ->
                node.attributes().getOrDefault("listAlgorithmIdentifier", "").contains(algorithm))
        .map(node -> node.attributes().get("privateKey"))
        .filter(java.util.Objects::nonNull)
        .findFirst()
        .map(HEX::parseHex)
        .map(ElcSessionkey4Sm.KeyPair::of);
  }

  /** The private key of the object {@code id} ({@code PrK.…}). */
  public ElcSessionkey4Sm.KeyPair privateKey(String id) {
    Node node = node(id);
    String scalar = node.attributes().get("privateKey");
    if (scalar == null || !BRAINPOOL_P256.equals(node.attributes().get("domainParameterOid"))) {
      throw new IllegalArgumentException(
          image + ": " + id + " ohne privaten Schlüssel auf " + BRAINPOOL_P256);
    }
    return ElcSessionkey4Sm.KeyPair.of(HEX.parseHex(scalar));
  }

  /** The CV certificate in the file {@code id} ({@code EF.C.…}). */
  public Cvc cvc(String id) {
    String body = node(id).attributes().get("body");
    if (body == null) {
      throw new IllegalArgumentException(image + ": " + id + " ohne Inhalt");
    }
    return Cvc.parse(HEX.parseHex(body));
  }

  /** Content of the file {@code id} ({@code EF.…}); empty if it is missing or empty. */
  public Optional<byte[]> body(String id) {
    return nodes.stream()
        .filter(node -> id.equals(node.id()))
        .findFirst()
        .map(node -> node.attributes().get("body"))
        .filter(body -> !body.isBlank())
        .map(body -> HEX.parseHex(body.strip()));
  }

  /**
   * Key references of the public keys for certificate verification ({@code
   * PublicElcVerificationKey}), e.g. {@code PuK.RCA.CS.E256}: the CVC roots the card trusts.
   */
  public List<byte[]> verificationKeys() {
    return nodes.stream()
        .filter(node -> "PublicElcVerificationKey".equals(node.objectType()))
        .map(node -> node.attributes().get("keyIdentifier"))
        .filter(java.util.Objects::nonNull)
        .map(HEX::parseHex)
        .toList();
  }

  private Node node(String id) {
    return nodes.stream()
        .filter(node -> id.equals(node.id()))
        .findFirst()
        .orElseThrow(() -> new IllegalArgumentException(image + ": " + id + " fehlt"));
  }
}
