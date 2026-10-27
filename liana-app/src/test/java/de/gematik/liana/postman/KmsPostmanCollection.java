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
package de.gematik.liana.postman;

import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.ShiftableClock;
import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.kern.management.ManagementSettings;
import de.gematik.liana.kern.vendor.Vendor;
import de.gematik.liana.kern.vendor.VendorProfile;
import jakarta.inject.Inject;
import java.time.Duration;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

/**
 * Base of the collections that need the KMS (LIANA-55): LIANA runs with the vendor profile of the
 * environment ({@code kmsVendorName=EHEX}), {@link KmsBridge} emulates the bridge endpoints {@code
 * /bridge/kms/*}. If a pre-request script waits via {@code setTimeout}, the test advances the clock
 * ({@link ShiftableClock}) instead of waiting. Afterwards the class restores profile and KMS
 * parameters.
 */
abstract class KmsPostmanCollection extends PostmanCollection {

  /** {@code timeoutTolerance} of the environment in ms (added to every wait time). */
  static final Duration TIMEOUT_TOLERANCE = Duration.ofMillis(1000);

  @Inject VendorProfile vendor;

  @Inject ManagementSettings settings;

  @Inject AdminServer admin;

  @Inject ShiftableClock clock;

  KmsBridge kms;

  /**
   * {@code startTime}: set in the pre-request script of „GetConnector.sds“ ({@code Date.now()}).
   */
  long startTime;

  @BeforeAll
  void kmsVendor() {
    vendor.switchTo(Vendor.of("EHEX"));
    kms = new KmsBridge(admin.port(), clock);
  }

  @AfterAll
  void resetKms() {
    vendor.reset();
    settings.reset();
  }

  /** GetConnector.sds with pre-request: {@code startTime = Date.now()}. */
  @Override
  void getConnectorSds() {
    startTime = clock.millis();
    super.getConnectorSds();
  }

  /** Waiting via {@code setTimeout} in the pre-request script. */
  void waitFor(Duration duration) {
    clock.advance(duration);
  }

  /**
   * FindInLog with {@code searched} for EHEX: „CARD/SESSION/TIMEOUT ist in Log vorhanden“ ({@code
   * isFound}).
   *
   * @param timer {@code PoPP} (TimeSpan of the scenario) or {@code Konnektor}
   *     (CARD_SESSION_TIMEOUT)
   */
  void findInLog(String timer) {
    String searched =
        "type=op@@severity=info@@topic=CARD/SESSION/TIMEOUT@@CardType=EGK@@SessionID="
            + sessionId
            + "@@Timer="
            + timer;
    assertTrue(
        kms.findInLog(searched, startTime),
        "CARD/SESSION/TIMEOUT ist in Log vorhanden: " + searched);
  }
}
