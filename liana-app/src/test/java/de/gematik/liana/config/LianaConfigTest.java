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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Mapping and startup check against the bundled {@code application.yaml}, without starting Quarkus.
 */
class LianaConfigTest {

  /**
   * The folders of liana.card-images from the shipped application.yaml, as ConfigCheck names them.
   */
  private static final String FOLDERS =
      "[./support/images, ./support/images/gsmc-kt, ./support/images/g20, "
          + "./support/images/gsmc-k, ./support/images/kvk, /opt/liana/images, /opt/liana/images/gsmc-kt, "
          + "/opt/liana/images/g20, /opt/liana/images/gsmc-k, /opt/liana/images/kvk]";

  @Test
  @DisplayName(
      "application.yaml bildet env, vendor, admin, kms, infomodel, card, card-images, infrastructure und "
          + "kon-export ab und ist gültig")
  void shippedYaml() throws IOException {
    LianaConfig config = TestConfig.load(Map.of());
    assertEquals(LianaConfig.Env.RU, config.env());
    assertEquals(9090, config.admin().port());
    assertEquals("neutral", config.vendor());
    assertTrue(
        config.kms().port().isEmpty(), "LIANA-146: KMS-Listener auf eigenem Port standardmäßig zu");
    assertEquals(List.of("KT-01", "KT-02"), config.infomodel().workplaces().getFirst().terminals());
    assertEquals(Path.of("/opt/liana/bin/kartos"), config.card().kartosBin());
    assertEquals(Duration.ofSeconds(120), config.card().sessionTimeout());
    assertEquals(Duration.ofSeconds(10), config.card().cardTimeout());
    var terminals = config.infrastructure().terminals();
    assertEquals(LianaConfig.Mode.FAKE, LianaConfig.Mode.of(terminals));
    assertEquals(
        List.of(
            Path.of("./support/images"),
            Path.of("./support/images/gsmc-kt"),
            Path.of("./support/images/g20"),
            Path.of("./support/images/gsmc-k"),
            Path.of("./support/images/kvk"),
            Path.of("/opt/liana/images"),
            Path.of("/opt/liana/images/gsmc-kt"),
            Path.of("/opt/liana/images/g20"),
            Path.of("/opt/liana/images/gsmc-k"),
            Path.of("/opt/liana/images/kvk")),
        config.cardImages());
    assertEquals(java.util.Optional.of("gsmckt-root6"), terminals.get("KT-01").gsmcKt());
    assertFalse(config.card().terminateSecureMessaging());
    assertEquals(java.util.Set.of("KT-01", "KT-02"), terminals.keySet());
    assertEquals(Map.of(1, "egk-valid", 2, "smcb-valid"), terminals.get("KT-01").slots());
    assertEquals(java.util.Optional.of(3), terminals.get("KT-01").slotCount());
    assertEquals("123456", terminals.get("KT-01").pin());
    assertEquals(Map.of(), terminals.get("KT-02").slots());
    assertEquals("basic", config.konExport().credentials().type());
    assertEquals(4742, config.ctm().serviceDiscoveryPort());
    assertEquals(4742, config.ctm().serviceAnnouncementPort());
    assertEquals(Duration.ofSeconds(3), config.ctm().serviceDiscoveryTimeout());
    assertEquals(
        Duration.ofMinutes(10),
        config.ctm().serviceDiscoveryCycle(),
        "CTM_SERVICE_DISCOVERY_CYCLE Default");
    assertEquals(Duration.ofSeconds(10), config.ctm().tlsHandshakeTimeout());
    assertEquals(List.of("1.0.0"), config.ctm().supportedKtVersions());
    var gsmcK = config.infrastructure().konnektor().gsmcK();
    assertEquals(Path.of("./support/pki/server/ak-aut-p256.p12"), gsmcK.akAut());
    assertEquals(
        java.util.Optional.of(Path.of("./support/pki/server/ak-aut-rsa.p12")), gsmcK.akAutRsa());
    assertEquals(Path.of("./support/pki/server/sak-aut-bp256.p12"), gsmcK.sakAut());
    assertEquals(
        java.util.Optional.of("gsmc-k"), gsmcK.image(), "LIANA-112.13: QES-Stapel im SE #2");
    assertEquals(List.of(), ConfigCheck.errors(config));
  }

  @Test
  @DisplayName(
      "LIANA-112.13 Startprüfung: gsmc-k.image muss PrK.SAK.AUTD_CVC.E256 mit CVC und CA-CVC enthalten")
  void gsmcKImage() throws IOException {
    List<String> errors =
        ConfigCheck.errors(
            TestConfig.load(Map.of("liana.infrastructure.konnektor.gsmc-k.image", "egk-valid")));
    assertEquals(1, errors.size(), errors::toString);
    assertTrue(
        errors.getFirst().startsWith("infrastructure.konnektor.gsmc-k.image: ")
            && errors.getFirst().endsWith("egk-valid.xml: EF.C.CA_SAK.CS.E256 fehlt"),
        errors::toString);
  }

  @Test
  @DisplayName(
      "LIANA-98 Startprüfung je KT-Typ: fake braucht slot-count, sicct host und ein 16-Byte-Shared-Secret; "
          + "Arbeitsplätze nennen nur konfigurierte KTs; Fake-Felder an einem überlagerten sicct-KT sind kein Fehler")
  void typen() throws IOException {
    assertEquals(
        List.of(),
        ConfigCheck.errors(
            TestConfig.load(
                Map.of(
                    "liana.infrastructure.terminals.KT-S1.type", "sicct",
                    "liana.infrastructure.terminals.KT-S1.host", "kartos-terminal",
                    "liana.infomodel.workplaces[0].terminals", "KT-01,KT-S1"))));
    assertEquals(
        List.of(),
        ConfigCheck.errors(
            TestConfig.load(
                Map.of(
                    "liana.infrastructure.terminals.KT-01.type", "sicct",
                    "liana.infrastructure.terminals.KT-01.host", "kartos-terminal"))),
        "slots von KT-01 bleiben unbeachtet");
    assertEquals(
        LianaConfig.Mode.MIXED,
        LianaConfig.Mode.of(
            TestConfig.load(
                    Map.of(
                        "liana.infrastructure.terminals.KT-01.type", "sicct",
                        "liana.infrastructure.terminals.KT-01.host", "kartos-terminal"))
                .infrastructure()
                .terminals()));
    assertEquals(
        List.of(
            "infrastructure.terminals.KT-S1: host fehlt (sicct)",
            "infrastructure.terminals.KT-S2: shared-secret ist nicht 16 Byte hex (DO_KT_0003)"),
        ConfigCheck.errors(
            TestConfig.load(
                Map.of(
                    "liana.infrastructure.terminals.KT-S1.type", "sicct",
                    "liana.infrastructure.terminals.KT-S2.type", "sicct",
                    "liana.infrastructure.terminals.KT-S2.host", "kartos-terminal",
                    "liana.infrastructure.terminals.KT-S2.shared-secret", "0011"))));
    assertEquals(
        List.of(
            "infrastructure.terminals.KT-03: slot-count fehlt oder ist kleiner als 1 (fake)",
            "infrastructure.terminals.KT-04: host und shared-secret gibt es nur bei type: sicct"),
        ConfigCheck.errors(
            TestConfig.load(
                Map.of(
                    "liana.infrastructure.terminals.KT-03.type", "fake",
                    "liana.infrastructure.terminals.KT-04.type", "fake",
                    "liana.infrastructure.terminals.KT-04.slot-count", "1",
                    "liana.infrastructure.terminals.KT-04.host", "irgendwo"))));
  }

  @Test
  @DisplayName(
      "LIANA-98: abgelöste Schlüssel (liana.terminals.*, ctm.identity, tls.identity) brechen den Start nicht "
          + "im Mapping ab, sondern mit dem Nachfolger, auch als Umgebungsvariable")
  void retiredKeys() throws IOException {
    Map<String, String> old = new java.util.LinkedHashMap<>();
    old.put("liana.terminals.mode", "sicct");
    old.put("liana.terminals.image-path[0]", "a");
    old.put("liana.ctm.identity", "x.p12");
    old.put("liana.tls.identity-rsa", "rsa.p12");
    old.put("LIANA_TLS_IDENTITY_PASSWORD", "geheim");
    LianaConfig config = TestConfig.load(Map.of("LIANA_TLS_IDENTITY_PASSWORD", "geheim"), old);
    assertEquals(
        List.of(
            "liana.terminals.mode gibt es nicht mehr, stattdessen liana.infrastructure.terminals.<CT.CTID> (type: "
                + "fake|sicct, slot-count, slots, pin, host, shared-secret) (LIANA-98)",
            "liana.terminals.image-path[0] gibt es nicht mehr, stattdessen liana.card-images (LIANA-98)",
            "liana.ctm.identity gibt es nicht mehr, stattdessen liana.infrastructure.konnektor.gsmc-k.sak-aut "
                + "(LIANA-98)",
            "liana.tls.identity-rsa gibt es nicht mehr, stattdessen liana.infrastructure.konnektor.gsmc-k.ak-aut-rsa "
                + "(LIANA-98)",
            "LIANA_TLS_IDENTITY_PASSWORD gibt es nicht mehr, stattdessen liana.infrastructure.konnektor.gsmc-k."
                + "password (LIANA-98)"),
        ConfigCheck.errors(config, old.keySet()));
  }

  @Test
  @DisplayName(
      "LIANA-67 / LIANA-147 Startprüfung cats: Standard ist KT-01 unter /cats/KT-01 ohne eigenen Port; jedes "
          + "CATS-Terminal zeigt einmal auf ein laufendes KT mit URL-tauglicher ID, ein eigener Port nur einmal")
  void cats() throws IOException {
    var shipped = TestConfig.load(Map.of()).cats().terminals().orElseThrow();
    assertEquals(1, shipped.size());
    assertTrue(shipped.getFirst().port().isEmpty(), "9998 nur noch als Kompatibilität (LIANA-147)");
    assertEquals("KT-01", shipped.getFirst().terminal());
    assertEquals(
        List.of(
            "cats: unbekanntes KT 'KT-99' (infrastructure.terminals: [KT-01, KT-02])",
            "cats: Port 9998 mehrfach vergeben (je CATS-Terminal ein Port)"),
        ConfigCheck.errors(
            TestConfig.load(
                Map.of(
                    "liana.cats.terminals[0].port", "9998",
                    "liana.cats.terminals[1].port", "9998",
                    "liana.cats.terminals[1].terminal", "KT-99"))));
    assertEquals(
        List.of("cats: KT 'KT-01' mehrfach (je KT ein CATS-Terminal)"),
        ConfigCheck.errors(TestConfig.load(Map.of("liana.cats.terminals[1].terminal", "KT-01"))));
    assertEquals(
        List.of(
            "cats: unbekanntes KT 'KT 01' (infrastructure.terminals: [KT-01, KT-02])",
            "cats: KT 'KT 01' nicht als Pfad /cats/<KT> nutzbar (erlaubt: A-Z a-z 0-9 . _ ~ -)"),
        ConfigCheck.errors(TestConfig.load(Map.of("liana.cats.terminals[0].terminal", "KT 01"))));
    assertEquals(
        List.of(),
        ConfigCheck.errors(
            TestConfig.load(
                Map.of(
                    "liana.cats.terminals[0].port", "9998",
                    "liana.cats.terminals[1].port", "9997",
                    "liana.cats.terminals[1].terminal", "KT-02"))));
    assertEquals(
        List.of(),
        ConfigCheck.errors(TestConfig.load(Map.of("liana.cats.terminals[1].terminal", "KT-02"))));
  }

  @Test
  @DisplayName(
      "LIANA-106 Startprüfung robot: ohne Port aus; mit Port zeigt jedes Robot-Terminal auf ein Fake-KT mit "
          + "Slot 1 und 2 und jedes Fach SCn auf ein Image")
  void robot() throws IOException {
    var shipped = TestConfig.load(Map.of()).robot();
    assertTrue(shipped.port().isEmpty());
    assertEquals(List.of("KT-01"), shipped.terminals());
    assertEquals("hba-valid", shipped.berechtigt().get("SC2"));
    assertEquals(
        List.of(), ConfigCheck.errors(TestConfig.load(Map.of("liana.robot.port", "9997"))));
    assertEquals(
        List.of(),
        ConfigCheck.errors(TestConfig.load(Map.of("liana.robot.terminals[0]", "KT-99"))),
        "ohne Port keine Prüfung");
    assertEquals(
        List.of(
            "robot.terminals: 'KT-99' ist kein KT (infrastructure.terminals: [KT-01, KT-02])",
            "robot.berechtigt.SC2: Image 'gibt-es-nicht' nicht gefunden in " + FOLDERS,
            "robot.egk: Fach 'ABC' ist nicht SC1…SC9"),
        ConfigCheck.errors(
            TestConfig.load(
                Map.of(
                    "liana.robot.port", "9997",
                    "liana.robot.terminals[0]", "KT-99",
                    "liana.robot.egk.ABC", "egk-valid",
                    "liana.robot.berechtigt.SC2", "gibt-es-nicht"))));
    assertFalse(shipped.awaitPin(), "PIN-Pads warten nur für Robot-Suiten (ehkt.sh)");
    assertEquals(
        List.of(
            "robot.terminals: KT-01 ist ein eHealth-KT ohne infrastructure.terminals.KT-01.control "
                + "(Steuerschnittstelle von kartos terminal)"),
        ConfigCheck.errors(
            TestConfig.load(
                Map.of(
                    "liana.robot.port",
                    "9997",
                    "liana.infrastructure.terminals.KT-01.type",
                    "sicct",
                    "liana.infrastructure.terminals.KT-01.host",
                    "kartos-terminal"))),
        "LIANA-112.15: der Robot steuert ein eHealth-KT nur über kartos");
    assertEquals(
        List.of(),
        ConfigCheck.errors(
            TestConfig.load(
                Map.of(
                    "liana.robot.port",
                    "9997",
                    "liana.infrastructure.terminals.KT-01.type",
                    "sicct",
                    "liana.infrastructure.terminals.KT-01.host",
                    "kartos-terminal",
                    "liana.infrastructure.terminals.KT-01.control",
                    "http://kartos-terminal:4743"))));
  }

  @Test
  @DisplayName("TAB_KON_527: CTM_TLS_HS_TIMEOUT 1–60 s, CTM_SERVICE_DISCOVERY_TIMEOUT positiv")
  void ctmParameter() throws IOException {
    assertEquals(
        List.of(
            "ctm.tls-handshake-timeout 61 s außerhalb 1..60 s (CTM_TLS_HS_TIMEOUT, TAB_KON_527)"),
        ConfigCheck.errors(TestConfig.load(Map.of("liana.ctm.tls-handshake-timeout", "61s"))));
    assertEquals(
        List.of(
            "ctm.keep-alive-interval 500 ms außerhalb 1..10 s (CTM_KEEP_ALIVE_INTERVAL, TAB_KON_527)"),
        ConfigCheck.errors(TestConfig.load(Map.of("liana.ctm.keep-alive-interval", "500ms"))));
    assertEquals(
        List.of(
            "ctm.keep-alive-try-count 2 außerhalb 3..10 (CTM_KEEP_ALIVE_TRY_COUNT, TAB_KON_527)"),
        ConfigCheck.errors(TestConfig.load(Map.of("liana.ctm.keep-alive-try-count", "2"))));
    assertEquals(
        List.of(
            "ctm.service-discovery-cycle darf nicht negativ sein (CTM_SERVICE_DISCOVERY_CYCLE, 0 = aus)"),
        ConfigCheck.errors(TestConfig.load(Map.of("liana.ctm.service-discovery-cycle", "-1s"))));
    assertEquals(
        List.of("ctm.service-discovery-timeout muss positiv sein (CTM_SERVICE_DISCOVERY_TIMEOUT)"),
        ConfigCheck.errors(TestConfig.load(Map.of("liana.ctm.service-discovery-timeout", "0s"))));
  }

  @Test
  @DisplayName("LIANA_CARD_IMAGES=a,b ersetzt die Ordner der Kartenimages")
  void cardImagesFromEnv() throws IOException {
    LianaConfig config = TestConfig.load(Map.of("LIANA_CARD_IMAGES", "a,b"), Map.of());
    assertEquals(List.of(Path.of("a"), Path.of("b")), config.cardImages());
  }

  @Test
  @DisplayName(
      "LIANA-98: Umgebungsvariablen überschreiben Felder eines KT aus der YAML (KT-01 → KT_01) und die "
          + "Identitäten der gSMC-K, wie im Container und in tools/testhub/popp.sh")
  void infrastructureFromEnv() throws IOException {
    LianaConfig config =
        TestConfig.load(
            Map.of(
                "LIANA_INFRASTRUCTURE_TERMINALS_KT_01_TYPE", "sicct",
                "LIANA_INFRASTRUCTURE_TERMINALS_KT_01_HOST", "tiger-sicct",
                "LIANA_INFRASTRUCTURE_KONNEKTOR_GSMC_K_SAK_AUT",
                    "/opt/liana/pki/server/sak-aut-bp256.p12"),
            Map.of());
    assertEquals(LianaConfig.Type.SICCT, config.infrastructure().terminals().get("KT-01").type());
    assertEquals(
        java.util.Optional.of("tiger-sicct"),
        config.infrastructure().terminals().get("KT-01").host());
    assertEquals(
        Path.of("/opt/liana/pki/server/sak-aut-bp256.p12"),
        config.infrastructure().konnektor().gsmcK().sakAut());
  }

  @Test
  @DisplayName("Ungültiges env bricht den Start ab")
  void invalidEnv() {
    RuntimeException e =
        assertThrows(RuntimeException.class, () -> TestConfig.load(Map.of("liana.env", "xu")));
    assertTrue(e.getMessage().contains("liana.env"), e.getMessage());
  }

  @Test
  @DisplayName(
      "decision-10: Herstellerprofil unabhängig von Groß-/Kleinschreibung, unbekannter Wert bricht den Start mit den erlaubten Werten ab")
  void vendor() throws IOException {
    assertEquals(List.of(), ConfigCheck.errors(TestConfig.load(Map.of("liana.vendor", "ehex"))));
    assertEquals(
        List.of(
            "vendor: unbekannter Hersteller 'ACME', erlaubt: neutral, KOCO, RISE, SECUNET, EHEX, CGM"
                + " (decision-10)"),
        ConfigCheck.errors(TestConfig.load(Map.of("liana.vendor", "ACME"))));
  }

  @Test
  @DisplayName("Arbeitsplatz mit unbekanntem KT bricht den Start ab")
  void unknownTerminal() throws IOException {
    LianaConfig config =
        TestConfig.load(Map.of("liana.infomodel.workplaces[0].terminals", "KT-01,KT-99"));
    assertEquals(
        List.of(
            "Arbeitsplatz WP1: unbekanntes KT 'KT-99' (infrastructure.terminals: [KT-01, KT-02])"),
        ConfigCheck.errors(config));
  }

  @Test
  @DisplayName(
      "LIANA-60 SM-B_Verwaltet: Standard ohne Einträge; unbekannter Mandant oder doppelte ICCSN bricht den "
          + "Start ab")
  void smbVerwaltet() throws IOException {
    assertEquals(java.util.Optional.empty(), TestConfig.load(Map.of()).infomodel().smbVerwaltet());
    LianaConfig config =
        TestConfig.load(
            Map.of(
                "liana.infomodel.smb-verwaltet[0].iccsn", "80276883110000168650",
                "liana.infomodel.smb-verwaltet[0].mandants", "M1,M9",
                "liana.infomodel.smb-verwaltet[1].iccsn", "80276883110000168650",
                "liana.infomodel.smb-verwaltet[1].mandants", "M1"));
    assertEquals(
        List.of(
            "infomodel.smb-verwaltet 80276883110000168650: unbekannter Mandant 'M9'",
            "infomodel.smb-verwaltet: ICCSN 80276883110000168650 mehrfach"),
        ConfigCheck.errors(config));
  }

  @Test
  @DisplayName(
      "LIANA-98: fehlendes Image bricht den Start ab und nennt KT, Slot und Ordner; ein Slot per ICCSN ist "
          + "gültig")
  void missingImage() throws IOException {
    LianaConfig config =
        TestConfig.load(Map.of("liana.infrastructure.terminals.KT-02.slots.2", "egk-revoked"));
    assertEquals(
        List.of(
            "KT-02/2: Image 'egk-revoked' nicht gefunden in " + FOLDERS + ", ähnlich: [egk-valid]"),
        ConfigCheck.errors(config));
    assertEquals(
        List.of(),
        ConfigCheck.errors(
            TestConfig.load(
                Map.of("liana.infrastructure.terminals.KT-02.slots.1", "80276883110000168584"))));
  }

  @Test
  @DisplayName("Image in einem Slot außerhalb von slot-count bricht den Start ab")
  void slotOutOfRange() throws IOException {
    LianaConfig config =
        TestConfig.load(Map.of("liana.infrastructure.terminals.KT-02.slots.3", "egk-valid"));
    assertEquals(List.of("KT-02/3: Slot außerhalb 1..2"), ConfigCheck.errors(config));
  }

  @Test
  @DisplayName("TAB_KON_554: CARD_SESSION_TIMEOUT außerhalb 10–180 s bricht den Start ab")
  void sessionTimeoutRange() throws IOException {
    assertEquals(
        List.of("card.session-timeout 5 s außerhalb 10..180 s (TAB_KON_554)"),
        ConfigCheck.errors(TestConfig.load(Map.of("liana.card.session-timeout", "5s"))));
    assertEquals(
        List.of(),
        ConfigCheck.errors(TestConfig.load(Map.of("liana.card.session-timeout", "180s"))));
  }

  @Test
  @DisplayName("TAB_KON_554: CARD_TIMEOUT_CARD muss positiv sein")
  void cardTimeoutPositiv() throws IOException {
    assertEquals(
        List.of("card.card-timeout PT0S muss positiv sein (CARD_TIMEOUT_CARD, TAB_KON_554)"),
        ConfigCheck.errors(TestConfig.load(Map.of("liana.card.card-timeout", "0s"))));
  }

  @Test
  @DisplayName(
      "LIANA-99/LIANA-28: gsmc-kt je KT über die Kartenimages (Dateiname oder ICCSN); unbekannt oder mehrdeutig "
          + "bricht den Start ab, mit card.terminate-secure-messaging auch ein fehlendes oder unvollständiges")
  void gsmcKt() throws IOException {
    assertEquals(
        List.of(),
        ConfigCheck.errors(
            TestConfig.load(
                Map.of(
                    "liana.card.terminate-secure-messaging",
                    "true",
                    "liana.infrastructure.terminals.KT-02.gsmc-kt",
                    "80276883110000152716"))));
    assertEquals(
        List.of(
            "infrastructure.terminals.KT-02.gsmc-kt: Image 'gsmckt-unbekannt' nicht gefunden in "
                + FOLDERS
                + ", ähnlich: [gsmckt-valid, gsmckt-root6]"),
        ConfigCheck.errors(
            TestConfig.load(
                Map.of("liana.infrastructure.terminals.KT-02.gsmc-kt", "gsmckt-unbekannt"))));
    var twice =
        TestConfig.load(
            Map.of("LIANA_CARD_IMAGES", "./support/images/gsmc-kt,support/images/gsmc-kt"),
            Map.of("liana.infrastructure.terminals.KT-02.gsmc-kt", "80276883110000152716"));
    assertTrue(
        ConfigCheck.errors(twice).stream()
            .anyMatch(
                error ->
                    error.startsWith(
                        "infrastructure.terminals.KT-02.gsmc-kt: ICCSN 80276883110000152716 ist mehrdeutig")),
        () -> ConfigCheck.errors(twice).toString());
    assertEquals(
        List.of(
            "infrastructure.terminals.KT-03.gsmc-kt fehlt (card.terminate-secure-messaging: Identität "
                + "als Terminal, LIANA-28)"),
        ConfigCheck.errors(
            TestConfig.load(
                Map.of(
                    "liana.card.terminate-secure-messaging", "true",
                    "liana.infrastructure.terminals.KT-03.type", "fake",
                    "liana.infrastructure.terminals.KT-03.slot-count", "1"))));
    assertEquals(
        List.of(
            "infrastructure.terminals.KT-02.gsmc-kt: ./support/images/egk-valid.xml: "
                + "EF.C.CA_SMC.CS.E256 fehlt"),
        ConfigCheck.errors(
            TestConfig.load(
                Map.of(
                    "liana.card.terminate-secure-messaging", "true",
                    "liana.infrastructure.terminals.KT-02.gsmc-kt", "egk-valid"))));
  }
}
