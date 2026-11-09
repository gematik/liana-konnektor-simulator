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
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Reports the expiry of the test material in the repository and fails if something runs out: certificates in support/pki
 * (pem, der, cer, crt, p12) and in the card images in support/images, below 45 days, NextUpdate of support/pki/tsl/*.xml
 * below 7 days: the RU issues a TSL for about 30 days, 45 days would fail even when fresh. JDK only, so that it starts on
 * every Jenkins agent without a build.
 *
 * <p>A date in support/pki/expiry-exceptions.txt is reported, but does not fail ("path # reason", the reason is mandatory).
 *
 * <p>Usage from the repository root: java tools/pki/CertExpiry.java [--root dir] [--days 45] [--tsl-days 7] [--today 2026-11-05] [--p12-password liana]
 */
public class CertExpiry {

  private static final String NEXT_UPDATE_LABEL = "NextUpdate";
  private static final Pattern NEXT_UPDATE =
      Pattern.compile("NextUpdate>\\s*<(?:\\w+:)?dateTime>([^<]+)<");
  private static final Pattern IMAGE_OBJECT =
      Pattern.compile("<child id=\"([^\"]+)\"|<attribute id=\"body\">([0-9A-Fa-f]+)<");

  private static char[] p12Password;

  record Entry(LocalDate expiry, String file, String what) {}

  public static void main(String[] args) throws IOException {
    Path root = Path.of(option(args, "--root", "."));
    int days = Integer.parseInt(option(args, "--days", "45"));
    p12Password = option(args, "--p12-password", "liana").toCharArray();
    int tslDays = Integer.parseInt(option(args, "--tsl-days", "7"));
    LocalDate today = LocalDate.parse(option(args, "--today", LocalDate.now(ZoneOffset.UTC).toString()));

    List<Entry> entries = new ArrayList<>();
    List<String> errors = new ArrayList<>();
    for (Path file : files(root.resolve("support/pki"))) {
      read(file, root, entries, errors, CertExpiry::pkiFile);
    }
    for (Path file : files(root.resolve("support/images"))) {
      read(file, root, entries, errors, CertExpiry::imageFile);
    }
    Map<String, String> exceptions = exceptions(root.resolve("support/pki/expiry-exceptions.txt"), errors);

    entries.sort(Comparator.comparing(Entry::expiry).thenComparing(Entry::file));
    int failures = errors.size();
    for (Entry entry : entries) {
      int limit = entry.what().equals(NEXT_UPDATE_LABEL) ? tslDays : days;
      boolean due = entry.expiry().isBefore(today.plusDays(limit));
      String state = !due ? "OK" : exceptions.containsKey(entry.file()) ? "EXCEPTION" : "FAIL";
      failures += state.equals("FAIL") ? 1 : 0;
      System.out.printf("%-9s %s  %s  %s%n", state, entry.expiry(), entry.file(), entry.what());
      if (state.equals("EXCEPTION")) {
        System.out.println("          " + exceptions.get(entry.file()));
      }
    }
    errors.forEach(error -> System.out.println("ERROR     " + error));
    System.out.printf("%d dates, %d failures, limits %d days, TSL %d days, from %s%n", entries.size(), failures, days, tslDays, today);
    System.exit(failures == 0 ? 0 : 1);
  }

  private interface Reader {
    List<Entry> read(Path file, String relative) throws IOException, GeneralSecurityException;
  }

  private static void read(Path file, Path root, List<Entry> entries, List<String> errors, Reader reader) {
    String relative = root.relativize(file).toString().replace('\\', '/');
    try {
      entries.addAll(reader.read(file, relative));
    } catch (GeneralSecurityException | IOException | IllegalArgumentException e) {
      errors.add(relative + ": " + e.getMessage());
    }
  }

  private static List<Entry> pkiFile(Path file, String relative) throws IOException, GeneralSecurityException {
    String name = file.getFileName().toString();
    if (relative.startsWith("support/pki/tsl/") && name.endsWith(".xml")) {
      return List.of(tsl(file, relative));
    }
    if (name.endsWith(".p12")) {
      return p12(file, relative);
    }
    if (name.endsWith(".pem") && !Files.readString(file).contains("BEGIN CERTIFICATE")) {
      return List.of();
    }
    if (name.endsWith(".pem") || name.endsWith(".der") || name.endsWith(".cer") || name.endsWith(".crt")) {
      try (InputStream in = Files.newInputStream(file)) {
        return CertificateFactory.getInstance("X.509").generateCertificates(in).stream()
            .map(cert -> entry((X509Certificate) cert, relative))
            .toList();
      }
    }
    return List.of();
  }

  private static Entry tsl(Path file, String relative) throws IOException {
    Matcher matcher = NEXT_UPDATE.matcher(Files.readString(file));
    if (!matcher.find()) {
      throw new IllegalArgumentException("no NextUpdate");
    }
    LocalDate date = OffsetDateTime.parse(matcher.group(1).trim()).toLocalDate();
    return new Entry(date, relative, NEXT_UPDATE_LABEL);
  }

  private static List<Entry> p12(Path file, String relative) throws IOException, GeneralSecurityException {
    KeyStore store = KeyStore.getInstance("PKCS12");
    try (InputStream in = Files.newInputStream(file)) {
      store.load(in, p12Password);
    }
    List<Entry> entries = new ArrayList<>();
    for (String alias : Collections.list(store.aliases())) {
      Certificate[] chain = store.getCertificateChain(alias);
      for (Certificate cert : chain != null ? chain : new Certificate[] {store.getCertificate(alias)}) {
        entries.add(entry((X509Certificate) cert, relative));
      }
    }
    return entries;
  }

  /** Certificates are the bodies of EF.C.* that start with a DER sequence; a CVC starts with 7F21. */
  private static List<Entry> imageFile(Path file, String relative) throws IOException, GeneralSecurityException {
    if (!file.getFileName().toString().endsWith(".xml")) {
      return List.of();
    }
    List<Entry> entries = new ArrayList<>();
    String object = "";
    Matcher matcher = IMAGE_OBJECT.matcher(Files.readString(file));
    while (matcher.find()) {
      if (matcher.group(1) != null) {
        object = matcher.group(1);
      } else if (object.startsWith("EF.C.") && matcher.group(2).startsWith("30")) {
        byte[] der = HexFormat.of().parseHex(matcher.group(2));
        X509Certificate cert =
            (X509Certificate)
                CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
        entries.add(new Entry(date(cert), relative, object));
      }
    }
    return entries;
  }

  private static Entry entry(X509Certificate cert, String relative) {
    return new Entry(date(cert), relative, cert.getSubjectX500Principal().getName());
  }

  private static LocalDate date(X509Certificate cert) {
    return cert.getNotAfter().toInstant().atZone(ZoneOffset.UTC).toLocalDate();
  }

  private static Map<String, String> exceptions(Path file, List<String> errors) throws IOException {
    Map<String, String> exceptions = new HashMap<>();
    if (!Files.exists(file)) {
      return exceptions;
    }
    for (String line : Files.readAllLines(file)) {
      if (line.isBlank() || line.startsWith("#")) {
        continue;
      }
      int hash = line.indexOf('#');
      if (hash < 0 || line.substring(hash + 1).isBlank()) {
        errors.add(file.getFileName() + ": no reason in \"" + line + "\"");
      } else {
        exceptions.put(line.substring(0, hash).trim(), line.substring(hash + 1).trim());
      }
    }
    return exceptions;
  }

  private static List<Path> files(Path dir) throws IOException {
    if (!Files.isDirectory(dir)) {
      return List.of();
    }
    try (Stream<Path> walk = Files.walk(dir)) {
      return walk.filter(Files::isRegularFile).sorted().toList();
    }
  }

  private static String option(String[] args, String name, String fallback) {
    for (int i = 0; i < args.length - 1; i++) {
      if (args[i].equals(name)) {
        return args[i + 1];
      }
    }
    return fallback;
  }
}
