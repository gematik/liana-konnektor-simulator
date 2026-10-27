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
package de.gematik.liana.config;

import io.smallrye.config.ConfigSourceInterceptor;
import io.smallrye.config.ConfigSourceInterceptorContext;
import io.smallrye.config.ConfigValue;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Keys superseded by {@code liana.infrastructure} and {@code liana.card-images} (LIANA-98,
 * decision-14). There are no aliases: the interceptor only hides the old names from the name list
 * so that the mapping does not abort with „does not map to any root“, and {@link ConfigCheck}
 * reports each one with its successor.
 */
public final class RetiredKeys implements ConfigSourceInterceptor {

  /** Old key (prefix, dot notation) and what replaces it. */
  record Retired(String prefix, String successor) {

    boolean matches(String name) {
      String dotted =
          name.startsWith("LIANA_")
              ? name.toLowerCase(Locale.ROOT).replace('_', '.')
              : name.replace('-', '.');
      String key = prefix.replace('-', '.');
      return dotted.equals(key) || dotted.startsWith(key + ".") || dotted.startsWith(key + "[");
    }
  }

  static final List<Retired> RETIRED =
      List.of(
          new Retired("liana.terminals.image-path", "liana.card-images"),
          new Retired(
              "liana.terminals",
              "liana.infrastructure.terminals.<CT.CTID> (type: fake|sicct, slot-count, "
                  + "slots, pin, host, shared-secret)"),
          new Retired(
              "liana.ctm.identity-password", "liana.infrastructure.konnektor.gsmc-k.password"),
          new Retired("liana.ctm.identity", "liana.infrastructure.konnektor.gsmc-k.sak-aut"),
          new Retired(
              "liana.tls.identity-password", "liana.infrastructure.konnektor.gsmc-k.password"),
          new Retired("liana.tls.identity-rsa", "liana.infrastructure.konnektor.gsmc-k.ak-aut-rsa"),
          new Retired("liana.tls.identity", "liana.infrastructure.konnektor.gsmc-k.ak-aut"));

  /** Per old key under {@code names} a message with the successor, in the order of the names. */
  static List<String> errors(Iterable<String> names) {
    Set<String> errors = new LinkedHashSet<>();
    for (String name : names) {
      RETIRED.stream()
          .filter(retired -> retired.matches(name))
          .findFirst()
          .ifPresent(
              retired ->
                  errors.add(
                      name
                          + " gibt es nicht mehr, stattdessen "
                          + retired.successor()
                          + " (LIANA-98)"));
    }
    return new ArrayList<>(errors);
  }

  static boolean isRetired(String name) {
    return RETIRED.stream().anyMatch(retired -> retired.matches(name));
  }

  @Override
  public ConfigValue getValue(ConfigSourceInterceptorContext context, String name) {
    return context.proceed(name);
  }

  @Override
  public Iterator<String> iterateNames(ConfigSourceInterceptorContext context) {
    List<String> names = new ArrayList<>();
    context
        .iterateNames()
        .forEachRemaining(
            name -> {
              if (!isRetired(name)) {
                names.add(name);
              }
            });
    return names.iterator();
  }
}
