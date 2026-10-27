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
package de.gematik.liana.trace;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * popp-client ↔ TU Konnektor (popp-kon-tu) against LIANA with egk-valid in KT-01: what differs from
 * the recording for LIANA.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@TraceReplay("support/vendor/traces/popp-kon-tu/popp-client.tgr")
@LianaConfig(
    value = {
      "liana.infomodel.client-systems[0]=C1",
      "liana.infomodel.workplaces[0].id=W1",
      "liana.infomodel.workplaces[0].client-systems[0]=C1"
    },
    why = "Aufrufkontext der TU: Mandant M1, Clientsystem C1, Arbeitsplatz W1")
@LianaConfig(
    value = "liana.kon-export.url=http://liana:8080",
    why = "popp-client kennt LIANA als http://liana:8080")
@LianaConfig(
    value = "liana.pki.imported-cas=support/pki/replay/replay-ca.pem",
    why =
        "das Replay signiert die Szenarien neu (SessionId von LIANA); LIANA soll dem Replay-Signer vertrauen wie "
            + "der TU-Konnektor dem PoPP-Service")
@Replace(
    trace = "56e0aec6-cb06-43ce-8b55-4db3bc39559d",
    liana = "KT-01",
    why = "CtId des TU-Terminals")
@Carry(value = PoppKonTuGegenLiana.CARD_HANDLE, why = "CardHandle vergibt LIANA beim Stecken")
@Carry(value = PoppKonTuGegenLiana.SESSION_ID, why = "SessionId vergibt LIANA bei StartCardSession")
@interface PoppKonTuGegenLiana {

  String CARD_HANDLE = "$.body.Envelope.Body.GetCardsResponse.Cards.Card.CardHandle.text";
  String SESSION_ID = "$.body.Envelope.Body.StartCardSessionResponse.SessionId.text";
}
