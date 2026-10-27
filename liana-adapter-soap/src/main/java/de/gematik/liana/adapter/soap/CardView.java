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

import de.gematik.liana.kern.card.CardObject;
import de.gematik.liana.kern.card.CardVersion;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

/**
 * A card for {@code CARD:Card} (CardInfoType, CardService v8.1); optional values are {@code null},
 * {@code versions} empty if {@code CardVersion} is omitted.
 */
public record CardView(
    String cardHandle,
    String cardType,
    List<Version> versions,
    String iccsn,
    String ctId,
    int slotId,
    String insertTime,
    String cardHolderName,
    String kvnr,
    String certificateExpirationDate) {

  /** A child element of {@code CardVersion}, e.g. {@code COSVersion}. */
  public record Version(String element, int major, int minor, int revision) {}

  static CardView of(CardObject card) {
    var data = card.data();
    return new CardView(
        card.cardHandle(),
        data.type().value(),
        versions(data.version()),
        data.iccsn(),
        card.ctId(),
        card.slotNo(),
        DateTimeFormatter.ISO_INSTANT.format(card.insertTime().truncatedTo(ChronoUnit.MILLIS)),
        data.cardHolderName(),
        data.kvnr(),
        data.certExpirationDate() == null ? null : data.certExpirationDate() + "Z");
  }

  /**
   * In schema order; COS and object system version are mandatory, otherwise CardVersion is omitted.
   */
  private static List<Version> versions(CardVersion version) {
    var versions = new ArrayList<Version>();
    if (version == null || version.cos() == null || version.objectSystem() == null) {
      return versions;
    }
    add(versions, "COSVersion", version.cos());
    add(versions, "ObjectSystemVersion", version.objectSystem());
    add(versions, "LoggingVersion", version.logging());
    add(versions, "ATRVersion", version.atr());
    add(versions, "GDOVersion", version.gdo());
    add(versions, "KeyInfoVersion", version.keyInfo());
    return versions;
  }

  private static void add(List<Version> versions, String element, CardVersion.Version v) {
    if (v != null) {
      versions.add(new Version(element, v.major(), v.minor(), v.revision()));
    }
  }
}
