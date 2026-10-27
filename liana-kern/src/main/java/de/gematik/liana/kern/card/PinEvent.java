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

/**
 * Internal PIN event from TUC_KON_012 step 7a (CARD/PIN/VERIFY_STARTED) and 7d
 * (CARD/PIN/VERIFY_FINISHED), TUC_KON_019/021 step 7a/7d (CHANGE_STARTED/_FINISHED, also when
 * unblocking) and TUC_KON_027 step 5a/5d (ENABLE_*, DISABLE_*); delivery to Clientsysteme is
 * TUC_KON_256 with {@code doLog=false}, i.e. without Systemprotokoll. {@code result} only for
 * VERIFY_FINISHED and CHANGE_FINISHED (TUC_KON_027 names no result).
 */
public record PinEvent(
    Topic topic,
    CardObject card,
    String pinRef,
    String pinInputCtId,
    PinVerification.PinResult result) {

  public enum Topic {
    /** TUC_KON_012 step 7a */
    VERIFY_STARTED("CARD/PIN/VERIFY_STARTED"),
    /** TUC_KON_012 step 7d */
    VERIFY_FINISHED("CARD/PIN/VERIFY_FINISHED"),
    /** TUC_KON_019 and TUC_KON_021 step 7a */
    CHANGE_STARTED("CARD/PIN/CHANGE_STARTED"),
    /** TUC_KON_019 and TUC_KON_021 step 7d */
    CHANGE_FINISHED("CARD/PIN/CHANGE_FINISHED"),
    /** TUC_KON_027 step 5A a */
    ENABLE_STARTED("CARD/PIN/ENABLE_STARTED"),
    /** TUC_KON_027 step 5A d */
    ENABLE_FINISHED("CARD/PIN/ENABLE_FINISHED"),
    /** TUC_KON_027 step 5B a */
    DISABLE_STARTED("CARD/PIN/DISABLE_STARTED"),
    /** TUC_KON_027 step 5B d */
    DISABLE_FINISHED("CARD/PIN/DISABLE_FINISHED");

    private final String topic;

    Topic(String topic) {
      this.topic = topic;
    }

    /** Topic per TUC, e.g. {@code CARD/PIN/VERIFY_STARTED}. */
    public String topic() {
      return topic;
    }
  }
}
