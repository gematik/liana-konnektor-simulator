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

import de.gematik.liana.contract.Schemas;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The quirks table from {@code liana-contract} (LIANA-134): per product the known deviations and
 * the operations it does not implement or implements only up to the access check, each entry with
 * its source. A product matches via {@code ProductVendorID} and, if given, {@code ProductCode} from
 * {@code connector.sds}; an entry with {@code ProductCode} takes precedence. {@code includes} takes
 * over the entries of other products (LIANA with a vendor profile has that vendor's deviations and
 * its own gaps).
 */
public final class QuirksTable {

  /** A deviation. {@code expected}/{@code actual} e.g. as error codes, otherwise {@code null}. */
  public record Quirk(
      String id, String kind, String description, String expected, String actual, String source) {}

  /**
   * An operation the product does not implement or implements only up to the access check
   * (TUC_KON_000).
   */
  public record Gap(String operation, boolean accessCheckOnly, String source) {}

  /** A product of the table, with the entries from {@code includes} resolved. */
  public record KnownProduct(
      String id,
      String name,
      String vendorId,
      String productCode,
      List<Quirk> quirks,
      List<Gap> gaps) {

    public KnownProduct {
      quirks = List.copyOf(quirks);
      gaps = List.copyOf(gaps);
    }

    /** The gap for an operation, if the product does not (fully) implement it. */
    public Optional<Gap> gap(Operation operation) {
      return gaps.stream().filter(g -> g.operation().equals(operation.wsdlName())).findFirst();
    }

    /** The deviation with this ID, if the product has it. */
    public Optional<Quirk> quirk(String id) {
      return quirks.stream().filter(q -> q.id().equals(id)).findFirst();
    }
  }

  private static final QuirksTable DEFAULT = load(Schemas.quirks());

  private final List<KnownProduct> products;

  private QuirksTable(List<KnownProduct> products) {
    this.products = List.copyOf(products);
  }

  /** The table from {@code liana-contract}. */
  public static QuirksTable standard() {
    return DEFAULT;
  }

  /** All products, without the abstract building blocks. */
  public List<KnownProduct> products() {
    return products;
  }

  /** The product with this ID ({@code KOCO}, {@code LIANA-RISE}, …). */
  public Optional<KnownProduct> byId(String id) {
    return products.stream().filter(p -> p.id().equals(id)).findFirst();
  }

  /**
   * The product for {@code ProductVendorID} and {@code ProductCode}; with ProductCode before
   * without.
   */
  public Optional<KnownProduct> match(Product product) {
    if (product == null || product.vendorId() == null) {
      return Optional.empty();
    }
    Optional<KnownProduct> exact =
        products.stream()
            .filter(
                p ->
                    product.vendorId().equals(p.vendorId())
                        && p.productCode() != null
                        && p.productCode().equals(product.code()))
            .findFirst();
    return exact.or(
        () ->
            products.stream()
                .filter(p -> product.vendorId().equals(p.vendorId()) && p.productCode() == null)
                .findFirst());
  }

  static QuirksTable load(URL url) {
    try (InputStream in = url.openStream()) {
      return parse(new String(in.readAllBytes(), StandardCharsets.UTF_8));
    } catch (IOException e) {
      throw new UncheckedIOException("Quirks-Tabelle nicht lesbar: " + url, e);
    }
  }

  @SuppressWarnings("unchecked")
  static QuirksTable parse(String json) {
    Map<String, Object> root = (Map<String, Object>) Json.parse(json);
    Map<String, Map<String, Object>> raw = new LinkedHashMap<>();
    for (Object entry : (List<Object>) root.get("products")) {
      Map<String, Object> product = (Map<String, Object>) entry;
      raw.put((String) product.get("id"), product);
    }
    List<KnownProduct> products = new ArrayList<>();
    for (Map<String, Object> product : raw.values()) {
      if (Boolean.TRUE.equals(product.get("abstract"))) {
        continue;
      }
      List<Quirk> quirks = new ArrayList<>();
      List<Gap> gaps = new ArrayList<>();
      collect(product, raw, quirks, gaps, new ArrayList<>());
      products.add(
          new KnownProduct(
              (String) product.get("id"),
              (String) product.get("name"),
              (String) product.get("vendorId"),
              (String) product.get("productCode"),
              quirks,
              gaps));
    }
    return new QuirksTable(products);
  }

  @SuppressWarnings("unchecked")
  private static void collect(
      Map<String, Object> product,
      Map<String, Map<String, Object>> all,
      List<Quirk> quirks,
      List<Gap> gaps,
      List<String> seen) {
    String id = (String) product.get("id");
    if (seen.contains(id)) {
      throw new IllegalArgumentException("Quirks-Tabelle: includes im Kreis bei " + id);
    }
    seen.add(id);
    for (Object include : (List<Object>) product.getOrDefault("includes", List.of())) {
      Map<String, Object> included = all.get(include);
      if (included == null) {
        throw new IllegalArgumentException(
            "Quirks-Tabelle: " + id + " bindet unbekanntes " + include + " ein");
      }
      collect(included, all, quirks, gaps, seen);
    }
    for (Object entry : (List<Object>) product.getOrDefault("quirks", List.of())) {
      Map<String, Object> q = (Map<String, Object>) entry;
      quirks.add(
          new Quirk(
              (String) q.get("id"),
              (String) q.get("kind"),
              (String) q.get("description"),
              (String) q.get("expected"),
              (String) q.get("actual"),
              required(q, "source", id)));
    }
    for (String key : List.of("unsupported", "accessCheckOnly")) {
      for (Object entry : (List<Object>) product.getOrDefault(key, List.of())) {
        Map<String, Object> g = (Map<String, Object>) entry;
        gaps.add(
            new Gap(
                (String) g.get("operation"),
                key.equals("accessCheckOnly"),
                required(g, "source", id)));
      }
    }
  }

  private static String required(Map<String, Object> entry, String key, String product) {
    Object value = entry.get(key);
    if (!(value instanceof String s) || s.isBlank()) {
      throw new IllegalArgumentException("Quirks-Tabelle: Eintrag ohne " + key + " bei " + product);
    }
    return s;
  }
}
