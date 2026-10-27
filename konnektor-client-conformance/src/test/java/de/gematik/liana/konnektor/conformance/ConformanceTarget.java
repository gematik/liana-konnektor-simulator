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
package de.gematik.liana.konnektor.conformance;

import de.gematik.liana.konnektor.KonConfig;
import de.gematik.liana.konnektor.Konnektor;
import de.gematik.liana.konnektor.Trust;
import de.gematik.test.tiger.common.data.config.tigerproxy.TigerFileSaveInfo;
import de.gematik.test.tiger.common.data.config.tigerproxy.TigerProxyConfiguration;
import de.gematik.test.tiger.proxy.TigerProxy;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * The Konnektor under test (LIANA-139): {@code TI_TEST_KON_PATH} (system property or environment,
 * name as in ti-connector-client) names a {@code .kon}. Without it the suite does not run. {@code
 * conformance.record} names a {@code .tgr} file: traffic then goes through a Tiger proxy that
 * writes it there; {@code Authorization} is removed from the file afterwards. With {@code https}
 * the Tiger proxy terminates TLS with its own CA, and the client then trusts that CA; a client
 * certificate does not reach the Konnektor this way.
 */
final class ConformanceTarget implements ExecutionCondition {

  static final String KON = "TI_TEST_KON_PATH";
  static final String RECORD = "conformance.record";
  static final String INTERACTIVE = "conformance.interactive";

  private static TigerProxy tiger;
  private static Konnektor konnektor;

  static String setting(String name) {
    String value = System.getProperty(name);
    return value != null && !value.isBlank() ? value : System.getenv(name);
  }

  static boolean interactive() {
    return Boolean.parseBoolean(setting(INTERACTIVE));
  }

  @Override
  public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext context) {
    return setting(KON) == null
        ? ConditionEvaluationResult.disabled(KON + " nicht gesetzt")
        : ConditionEvaluationResult.enabled(KON + " = " + setting(KON));
  }

  static synchronized Konnektor konnektor() {
    if (konnektor != null) {
      return konnektor;
    }
    try {
      KonConfig kon = KonConfig.read(Path.of(setting(KON)));
      Konnektor.Builder builder = Konnektor.builder().kon(kon);
      String record = setting(RECORD);
      if (record != null) {
        Path file = Path.of(record).toAbsolutePath();
        Files.createDirectories(file.getParent());
        Files.deleteIfExists(file);
        tiger =
            new TigerProxy(
                TigerProxyConfiguration.builder()
                    .proxyPort(0)
                    .fileSaveInfo(
                        TigerFileSaveInfo.builder()
                            .writeToFile(true)
                            .clearFileOnBoot(true)
                            .sourceFile(null)
                            .filename(file.toString())
                            .build())
                    .build());
        builder.proxy("127.0.0.1", tiger.getProxyPort());
        if ("https".equals(kon.url().getScheme())) {
          builder.trust(new Trust(tigerCa(), kon.trust().expectedHost(), false));
        }
        Runtime.getRuntime().addShutdownHook(new Thread(() -> finishRecording(file)));
      }
      konnektor = builder.build();
      return konnektor;
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  private static List<X509Certificate> tigerCa() {
    try {
      KeyStore store = tiger.buildTruststore();
      List<X509Certificate> certificates = new ArrayList<>();
      for (String alias : Collections.list(store.aliases())) {
        certificates.add((X509Certificate) store.getCertificate(alias));
      }
      return certificates;
    } catch (KeyStoreException e) {
      throw new IllegalStateException(e);
    }
  }

  private static void finishRecording(Path file) {
    tiger.waitForAllCurrentMessagesToBeParsed();
    tiger.close();
    try {
      sanitize(file);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  private static final Pattern RAW = Pattern.compile("\"rawMessageContent\":\"([^\"]*)\"");
  private static final Pattern AUTHORIZATION =
      Pattern.compile("(?im)^(authorization|proxy-authorization):[^\\r\\n]*\\r\\n");

  /** Removes credentials from the {@code .tgr} (LIANA-139: traces without credentials). */
  static void sanitize(Path file) throws IOException {
    if (!Files.exists(file)) {
      return;
    }
    StringBuilder out = new StringBuilder();
    for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
      Matcher m = RAW.matcher(line);
      if (m.find()) {
        String raw =
            new String(Base64.getDecoder().decode(m.group(1)), StandardCharsets.ISO_8859_1);
        String clean = AUTHORIZATION.matcher(raw).replaceAll("");
        line =
            line.substring(0, m.start(1))
                + Base64.getEncoder().encodeToString(clean.getBytes(StandardCharsets.ISO_8859_1))
                + line.substring(m.end(1));
      }
      out.append(line).append('\n');
    }
    Files.writeString(file, out.toString(), StandardCharsets.UTF_8);
  }
}
