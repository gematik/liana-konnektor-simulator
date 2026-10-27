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
package de.gematik.liana.kern.event;

import de.gematik.liana.kern.card.CardData;
import de.gematik.liana.kern.card.CardEvent;
import de.gematik.liana.kern.card.CardObject;
import de.gematik.liana.kern.card.CardVersion;
import de.gematik.liana.kern.card.PinEvent;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * An event for Clientsysteme (TUC_KON_256 „Systemereignis absetzen“, element {@code Event} from
 * EventService.xsd): topic, type, severity and parameters as key-value pairs in a fixed order
 * (TAB_KON_030).
 */
public record Event(String topic, Type type, Severity severity, Map<String, String> parameters) {

  /** {@code EVT:EventType}; LIANA only emits Operation. */
  public enum Type {
    OPERATION("Operation"),
    SECURITY("Security"),
    INFRASTRUCTURE("Infrastructure");

    private final String value;

    Type(String value) {
      this.value = value;
    }

    public String value() {
      return value;
    }
  }

  /** {@code EVT:EventSeverityType}. */
  public enum Severity {
    INFO("Info"),
    WARNING("Warning"),
    ERROR("Error"),
    FATAL("Fatal");

    private final String value;

    Severity(String value) {
      this.value = value;
    }

    public String value() {
      return value;
    }
  }

  public Event {
    parameters = Collections.unmodifiableMap(new LinkedHashMap<>(parameters));
  }

  /**
   * CARD/INSERTED (TUC_KON_001 step 3) and CARD/REMOVED (TIP1-A_4562), Op and Info, parameters from
   * the CardObject. Missing values (KVNR except for the eGK, data of an UNKNOWN card) are omitted.
   * The keys are as in the spec: on removal the card type is called {@code Type} and
   * CertExpirationDate is missing.
   */
  public static Event of(CardEvent event) {
    CardObject card = event.card();
    CardData data = card.data();
    boolean inserted = event.topic() == CardEvent.Topic.INSERTED;
    Map<String, String> parameters = new LinkedHashMap<>();
    parameters.put("CardHandle", card.cardHandle());
    parameters.put(inserted ? "CardType" : "Type", data.type().value());
    put(parameters, "CardVersion", cardVersion(data.version()));
    put(parameters, "ICCSN", data.iccsn());
    parameters.put("CtID", card.ctId());
    parameters.put("SlotID", String.valueOf(card.slotNo()));
    parameters.put(
        "InsertTime",
        DateTimeFormatter.ISO_INSTANT.format(card.insertTime().truncatedTo(ChronoUnit.MILLIS)));
    put(parameters, "CardHolderName", data.cardHolderName());
    put(parameters, "KVNR", data.kvnr());
    if (inserted && data.certExpirationDate() != null) {
      parameters.put("CertExpirationDate", data.certExpirationDate().toString());
    }
    return new Event(event.topic().topic(), Type.OPERATION, Severity.INFO, parameters);
  }

  /**
   * CARD/PIN/VERIFY_*, CHANGE_* (TUC_KON_012, 019, 021 steps 7a and 7d), ENABLE_* and DISABLE_*
   * (TUC_KON_027 step 5), Op and Info, parameters in the order of the spec; {@code Result} only for
   * VERIFY_FINISHED and CHANGE_FINISHED.
   */
  public static Event of(PinEvent event) {
    CardObject card = event.card();
    Map<String, String> parameters = new LinkedHashMap<>();
    parameters.put("CardHandle", card.cardHandle());
    parameters.put("CardType", card.data().type().value());
    put(parameters, "ICCSN", card.data().iccsn());
    parameters.put("CtID", card.ctId());
    parameters.put("SlotID", String.valueOf(card.slotNo()));
    parameters.put("PinRef", event.pinRef());
    parameters.put("PinInputCtID", event.pinInputCtId());
    if (event.result() != null) {
      parameters.put("Result", event.result().name());
    }
    return new Event(event.topic().topic(), Type.OPERATION, Severity.INFO, parameters);
  }

  /**
   * Value of the parameter {@code key}, case-insensitive (TUC_KON_256 step 5b: „ctId“ for CtID).
   */
  public Optional<String> parameter(String key) {
    return parameters.entrySet().stream()
        .filter(e -> e.getKey().equalsIgnoreCase(key))
        .map(Map.Entry::getValue)
        .findFirst();
  }

  /**
   * TUC_KON_001 step 3: COSVERSION and OBJECTSYSTEMVERSION, plus the other versions read; names
   * like the elements in {@code CARD:CardVersion}, e.g. {@code COSVersion=4.4.0,
   * ObjectSystemVersion=4.7.0}.
   */
  static String cardVersion(CardVersion version) {
    if (version == null || version.cos() == null || version.objectSystem() == null) {
      return null;
    }
    StringBuilder value = new StringBuilder();
    append(value, "COSVersion", version.cos());
    append(value, "ObjectSystemVersion", version.objectSystem());
    append(value, "LoggingVersion", version.logging());
    append(value, "ATRVersion", version.atr());
    append(value, "GDOVersion", version.gdo());
    append(value, "KeyInfoVersion", version.keyInfo());
    return value.toString();
  }

  private static void append(StringBuilder value, String name, CardVersion.Version version) {
    if (version != null) {
      value.append(value.isEmpty() ? "" : ", ").append(name).append('=').append(version);
    }
  }

  private static void put(Map<String, String> parameters, String key, String value) {
    if (value != null) {
      parameters.put(key, value);
    }
  }
}
