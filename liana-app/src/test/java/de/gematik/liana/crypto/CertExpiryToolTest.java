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
package de.gematik.liana.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.HexFormat;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The tool of LIANA-208, started like in Jenkins, on a generated tree with a fixed date. */
class CertExpiryToolTest {

  private static final LocalDate TODAY = LocalDate.of(2026, 11, 5);
  // keytool wants at least 6 characters, the repository uses "liana"
  private static final String P12_PASSWORD = "liana-test";

  @TempDir Path root;

  record Run(int exit, String output) {}

  @Test
  @DisplayName(
      "Das eingecheckte Testmaterial liest das Werkzeug vollständig: p12 mit Brainpool, Images, TSL")
  void repositoryIsReadable() throws Exception {
    Run run = run(Path.of("."));
    assertEquals(0, run.exit(), run.output());
    assertTrue(run.output().contains("support/pki/server/sak-aut-bp256.p12"), run.output());
    assertTrue(
        run.output().contains("support/images/egk-valid.xml  EF.C.CH.AUT.E256"), run.output());
    assertTrue(
        run.output().contains("support/pki/tsl/ECC-RSA_TSL-ref.xml  NextUpdate"), run.output());
  }

  @Test
  @DisplayName("Ablauf ab 45 Tagen Rest ist gut, darunter scheitert das Werkzeug")
  void limitIs45Days() throws Exception {
    pem("support/pki/a.pem", TODAY.plusDays(45));
    assertEquals(0, run(root).exit());

    pem("support/pki/b.pem", TODAY.plusDays(44));
    Run run = run(root);
    assertEquals(1, run.exit(), run.output());
    assertTrue(
        run.output().contains("FAIL      " + TODAY.plusDays(44) + "  support/pki/b.pem"),
        run.output());
  }

  @Test
  @DisplayName(
      "Auch abgelaufene Zertifikate in p12 und Kartenimage lassen es scheitern, CVCs zählen nicht")
  void p12AndImage() throws Exception {
    Path p12 = write("support/pki/x.p12");
    Run keytool =
        run(
            Path.of(System.getProperty("java.home"), "bin", "keytool").toString(),
            "-genkeypair",
            "-alias",
            "x",
            "-keyalg",
            "EC",
            "-dname",
            "CN=TEST-ONLY",
            "-startdate",
            "2026/11/03 12:00:00",
            "-validity",
            "1",
            "-storetype",
            "PKCS12",
            "-storepass",
            P12_PASSWORD,
            "-keystore",
            p12.toString());
    assertEquals(0, keytool.exit(), keytool.output());
    KeyPair keys = keys();
    String hex = HexFormat.of().formatHex(certificate(keys, TODAY.minusDays(2)).getEncoded());
    Files.writeString(
        write("support/images/karte.xml"),
        "<child id=\"EF.C.CH.AUT.E256\"><attribute id=\"body\">"
            + hex
            + "</attribute></child>"
            + "<child id=\"EF.C.CA.CS.E256\"><attribute id=\"body\">7F2100</attribute></child>"
            + "<child id=\"EF.CD\"><attribute id=\"body\">3000</attribute></child>");

    Run run = run(root);
    assertEquals(1, run.exit(), run.output());
    assertTrue(
        run.output().contains("FAIL      " + TODAY.minusDays(1) + "  support/pki/x.p12"),
        run.output());
    assertTrue(
        run.output()
            .contains(
                "FAIL      " + TODAY.minusDays(2) + "  support/images/karte.xml  EF.C.CH.AUT.E256"),
        run.output());
    assertTrue(run.output().contains("2 dates, 2 failures"), run.output());
  }

  @Test
  @DisplayName(
      "NextUpdate einer TSL unter 7 Tagen oder vorbei scheitert, in der Ausnahmeliste nicht")
  void tslAndException() throws Exception {
    Files.writeString(
        write("support/pki/tsl/t.xml"),
        "<NextUpdate><dateTime>2026-11-12T00:00:00Z</dateTime></NextUpdate>");
    assertEquals(0, run(root).exit());

    Files.writeString(
        write("support/pki/tsl/t.xml"),
        "<NextUpdate><dateTime>2026-11-11T00:00:00Z</dateTime></NextUpdate>");
    Run failed = run(root);
    assertEquals(1, failed.exit(), failed.output());
    assertTrue(
        failed.output().contains("FAIL      2026-11-11  support/pki/tsl/t.xml"), failed.output());

    Files.writeString(write("support/pki/expiry-exceptions.txt"), "support/pki/tsl/t.xml # weil\n");
    Run excepted = run(root);
    assertEquals(0, excepted.exit(), excepted.output());
    assertTrue(
        excepted.output().contains("EXCEPTION 2026-11-11  support/pki/tsl/t.xml"),
        excepted.output());
  }

  @Test
  @DisplayName("Ausnahme ohne Grund und unlesbares Zertifikat scheitern")
  void unreadableFails() throws Exception {
    Files.writeString(write("support/pki/expiry-exceptions.txt"), "support/pki/a.pem\n");
    assertEquals(1, run(root).exit());

    Files.writeString(write("support/pki/expiry-exceptions.txt"), "");
    Files.writeString(write("support/pki/kaputt.der"), "kein Zertifikat");
    assertEquals(1, run(root).exit());
  }

  private Run run(Path tree) throws IOException, InterruptedException {
    return run(
        Path.of(System.getProperty("java.home"), "bin", "java").toString(),
        "tools/pki/CertExpiry.java",
        "--root",
        tree.toString(),
        "--today",
        TODAY.toString(),
        "--p12-password",
        tree.equals(root) ? P12_PASSWORD : "liana");
  }

  private static Run run(String... command) throws IOException, InterruptedException {
    Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
    String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    return new Run(process.waitFor(), output);
  }

  private void pem(String path, LocalDate expiry) throws Exception {
    String base64 =
        java.util.Base64.getMimeEncoder().encodeToString(certificate(keys(), expiry).getEncoded());
    Files.writeString(
        write(path), "-----BEGIN CERTIFICATE-----\n" + base64 + "\n-----END CERTIFICATE-----\n");
  }

  private Path write(String path) throws IOException {
    Path file = root.resolve(path);
    Files.createDirectories(file.getParent());
    return file;
  }

  private static KeyPair keys() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(256);
    return generator.generateKeyPair();
  }

  private static X509Certificate certificate(KeyPair keys, LocalDate expiry) throws Exception {
    X500Name name = new X500Name("CN=TEST-ONLY");
    Date notAfter = Date.from(expiry.atTime(12, 0).toInstant(ZoneOffset.UTC));
    Date notBefore = Date.from(expiry.minusYears(1).atStartOfDay().toInstant(ZoneOffset.UTC));
    return new JcaX509CertificateConverter()
        .getCertificate(
            new JcaX509v3CertificateBuilder(
                    name, BigInteger.ONE, notBefore, notAfter, name, keys.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withECDSA").build(keys.getPrivate())));
  }
}
