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
package de.gematik.liana.kern.card;

import java.util.Arrays;
import java.util.Optional;
import java.util.Set;

/** Card types per TAB_KON_500. */
public enum CardType {
  EGK("EGK"),
  HBA_Q_SIG("HBA-qSig"),
  HBA("HBA"),
  SMC_B("SMC-B"),
  SMC_KT("SMC-KT"),
  KVK("KVK"),
  ZOD_2_0("ZOD_2.0"),
  UNKNOWN("UNKNOWN");

  private final String value;

  CardType(String value) {
    this.value = value;
  }

  /** Value in the schema (CardServiceCommon {@code CardTypeType}), e.g. {@code SMC-B}. */
  public String value() {
    return value;
  }

  /** The card type for the schema value; empty if it is not in TAB_KON_500. */
  public static Optional<CardType> of(String value) {
    return Arrays.stream(values()).filter(t -> t.value.equals(value)).findFirst();
  }

  /**
   * Whether the card matches the CardType filter of GetCards (TIP1-A_4605-03). Besides the
   * individual types, the summarizing identifiers HBAx (HBA and predecessor cards) and SM-B (SMC-B)
   * from TAB_KON_500 apply.
   */
  public boolean matches(String filter) {
    return switch (filter) {
      case "HBAx" -> Set.of(HBA, HBA_Q_SIG, ZOD_2_0).contains(this);
      case "SM-B" -> this == SMC_B;
      default -> value.equals(filter);
    };
  }
}
