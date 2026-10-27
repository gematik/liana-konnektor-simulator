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
package de.gematik.liana.adapter.soap;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * An element from the SOAP body: namespace, local name, attributes (local name → value), text,
 * children.
 */
public record XmlNode(
    String namespace,
    String name,
    Map<String, String> attributes,
    String text,
    List<XmlNode> children) {

  /** The first child with the local name {@code name}. */
  public Optional<XmlNode> child(String name) {
    return children.stream().filter(c -> c.name.equals(name)).findFirst();
  }

  /** Text of the first child {@code name}, trimmed; empty if it is missing. */
  public Optional<String> childText(String name) {
    return child(name).map(c -> c.text.strip());
  }
}
