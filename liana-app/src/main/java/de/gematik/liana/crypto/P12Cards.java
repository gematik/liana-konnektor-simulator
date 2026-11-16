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

import de.gematik.liana.adapter.fake.CardImages;
import de.gematik.liana.config.LianaConfig;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileTime;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax;
import org.bouncycastle.asn1.isismtt.x509.Admissions;
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.jboss.logging.Logger;

/**
 * SMC-B from a PKCS#12 in {@code liana.card-images} (LIANA-220): a release user of the Testhub only
 * has the gematik test SMC-B as {@code smcb_private.p12} (AUT_E256), no card image. LIANA fills
 * certificate and key into the template {@value #TEMPLATE}, an SMC-B object system without AUT
 * identity derived from {@code smcb-valid}; kartos runs the result like every other image.
 *
 * <p>The password is guessed from {@code liana.card-p12.passwords}, then the empty one. The ICCSN
 * is not in the certificate:
 *
 * <ul>
 *   <li>rule A: Telematik-ID {@code 1-SMC-B-Testkarte--<15 digits>}, as the generator of the test
 *       cards issues it, gives {@code 80276} and these digits,
 *   <li>rule B otherwise: {@code 80276 99999} and 10 digits from the SHA-256 of the certificate,
 *       stable per PKCS#12 and recognizable as synthetic.
 * </ul>
 *
 * The images are written to {@code java.io.tmpdir/liana-p12}, named after their content, so that
 * every {@link CardImages} of the process finds the same file. The result per PKCS#12 (path, size,
 * modification time) is kept for the process: the gematik test PKCS#12 use 102400 MAC iterations,
 * and every wrong password costs that again.
 */
public final class P12Cards implements CardImages.Generator {

  private static final Logger LOG = Logger.getLogger(P12Cards.class);

  static final String TEMPLATE = "cards/smcb-p12-template.xml";

  /** Certificate type of the C.HCI.AUT (GS-A_4445); without it TUC_KON_001 sees no SMC-B. */
  static final String OID_SMC_B_AUT = "1.2.276.0.76.4.77";

  private static final Pattern RULE_A = Pattern.compile("1-SMC-B-Testkarte--([0-9]{15})");
  private static final BigInteger RULE_B_DIGITS = BigInteger.TEN.pow(10);

  private static final Map<Key, Result> RESULTS = new ConcurrentHashMap<>();

  private final List<String> passwords;
  private final Path directory;

  private record Key(
      Path p12, long size, FileTime modified, List<String> passwords, Path directory) {}

  /** Image or the reason why there is none. */
  private record Result(Path image, String problem) {}

  public P12Cards(List<String> passwords, Path directory) {
    List<String> all = new ArrayList<>(passwords);
    all.add("");
    this.passwords = List.copyOf(all);
    this.directory = directory;
  }

  /** The card images from {@code liana.card-images}, including the PKCS#12 there. */
  public static CardImages images(LianaConfig config) {
    return new CardImages(
        config.cardImages(),
        new P12Cards(
            config.cardP12().passwords(),
            Path.of(System.getProperty("java.io.tmpdir"), "liana-p12")));
  }

  /** What LIANA takes from a PKCS#12. */
  record Smcb(X509Certificate certificate, byte[] scalar, byte[] point, String telematikId) {}

  @Override
  public Path generate(Path p12) {
    Key key;
    try {
      key =
          new Key(
              p12.toAbsolutePath(),
              Files.size(p12),
              Files.getLastModifiedTime(p12),
              passwords,
              directory);
    } catch (IOException e) {
      throw new IllegalArgumentException("nicht lesbar: " + e.getMessage(), e);
    }
    Result result =
        RESULTS.computeIfAbsent(
            key,
            k -> {
              try {
                return new Result(build(p12), null);
              } catch (IllegalArgumentException e) {
                return new Result(null, e.getMessage());
              }
            });
    if (result.problem() != null) {
      throw new IllegalArgumentException(result.problem());
    }
    if (!Files.isRegularFile(result.image())) {
      RESULTS.remove(key);
      return generate(p12);
    }
    return result.image();
  }

  private Path build(Path p12) {
    Smcb smcb = read(p12);
    String iccsn = iccsn(smcb);
    String der = HexFormat.of().withUpperCase().formatHex(encoded(smcb.certificate()));
    String image =
        template()
            .replace("@C.HCI.AUT.E256.LENGTH@", String.format("%04X", der.length() / 2))
            .replace("@C.HCI.AUT.E256@", der)
            .replace("@PrK.HCI.AUT.E256@", HexFormat.of().withUpperCase().formatHex(smcb.scalar()))
            .replace("@PuK.HCI.AUT.E256@", HexFormat.of().withUpperCase().formatHex(smcb.point()))
            .replace("@ICCSN8@", iccsn.substring(4))
            .replace("@ICCSN@", iccsn);
    byte[] bytes = image.getBytes(StandardCharsets.UTF_8);
    Path file =
        directory.resolve(iccsn + "-" + HexFormat.of().formatHex(sha256(bytes), 0, 8) + ".xml");
    if (Files.isRegularFile(file)) {
      return file;
    }
    try {
      Files.createDirectories(directory);
      Path written = Files.createTempFile(directory, iccsn, ".tmp");
      Files.write(written, bytes);
      Files.move(
          written, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    } catch (IOException e) {
      throw new UncheckedIOException("SMC-B zu " + p12 + " nicht schreibbar in " + directory, e);
    }
    LOG.infof(
        "%s: SMC-B ICCSN %s, Telematik-ID %s, %s (LIANA-220)",
        p12, iccsn, smcb.telematikId(), subject(smcb.certificate()));
    return file;
  }

  /**
   * Key and certificate of the first key entry; {@link IllegalArgumentException} with the reason.
   */
  Smcb read(Path p12) {
    byte[] content;
    try {
      content = Files.readAllBytes(p12);
    } catch (IOException e) {
      throw new IllegalArgumentException("nicht lesbar: " + e.getMessage(), e);
    }
    for (String password : passwords) {
      Optional<KeyStore> store = open(content, password);
      if (store.isPresent()) {
        return smcb(store.get(), password);
      }
    }
    throw new IllegalArgumentException(
        "keine lesbare PKCS#12, keins der "
            + passwords.size()
            + " Passwörter passt (card-p12.passwords und leeres Passwort)");
  }

  private static Optional<KeyStore> open(byte[] content, String password) {
    try {
      KeyStore store = KeyStore.getInstance("PKCS12", CryptoProviders.BC);
      store.load(new ByteArrayInputStream(content), password.toCharArray());
      return Optional.of(store);
    } catch (IOException | GeneralSecurityException e) {
      return Optional.empty();
    }
  }

  private static Smcb smcb(KeyStore store, String password) {
    try {
      for (String alias : Collections.list(store.aliases())) {
        if (store.isKeyEntry(alias)
            && store.getKey(alias, password.toCharArray()) instanceof PrivateKey key
            && store.getCertificate(alias) instanceof X509Certificate certificate) {
          return smcb(key, certificate);
        }
      }
    } catch (GeneralSecurityException e) {
      throw new IllegalArgumentException("Schlüssel nicht lesbar: " + e.getMessage(), e);
    }
    throw new IllegalArgumentException("kein Paar aus Schlüssel und Zertifikat");
  }

  private static Smcb smcb(PrivateKey key, X509Certificate certificate) {
    PrivateKeyInfo info = PrivateKeyInfo.getInstance(key.getEncoded());
    if (!(key instanceof ECPrivateKey ec)
        || !TeleTrusTObjectIdentifiers.brainpoolP256r1.equals(
            info.getPrivateKeyAlgorithm().getParameters())) {
      throw new IllegalArgumentException(
          "Schlüssel nicht brainpoolP256r1 (AUT_E256), sondern "
              + info.getPrivateKeyAlgorithm().getAlgorithm()
              + " "
              + info.getPrivateKeyAlgorithm().getParameters());
    }
    X9ECParameters curve =
        TeleTrusTNamedCurves.getByOID(TeleTrusTObjectIdentifiers.brainpoolP256r1);
    ECPoint point =
        curve
            .getCurve()
            .decodePoint(
                SubjectPublicKeyInfo.getInstance(certificate.getPublicKey().getEncoded())
                    .getPublicKeyData()
                    .getBytes())
            .normalize();
    if (!curve.getG().multiply(ec.getS()).normalize().equals(point)) {
      throw new IllegalArgumentException(
          "Schlüssel passt nicht zum Zertifikat " + subject(certificate));
    }
    if (!ScenarioSignerCheck.policies(certificate).contains(OID_SMC_B_AUT)) {
      throw new IllegalArgumentException(
          "Zertifikat "
              + subject(certificate)
              + " ohne Zertifikatstyp oid_smc_b_aut "
              + OID_SMC_B_AUT
              + " (keine SMC-B AUT)");
    }
    String telematikId =
        telematikId(certificate)
            .orElseThrow(
                () ->
                    new IllegalArgumentException(
                        "keine Telematik-ID (Admission, registrationNumber) im Zertifikat "
                            + subject(certificate)));
    return new Smcb(
        certificate,
        BigIntegers.asUnsignedByteArray(32, ec.getS()),
        point.getEncoded(false),
        telematikId);
  }

  /** registrationNumber of the first ProfessionInfo in the Admission extension. */
  static Optional<String> telematikId(X509Certificate certificate) {
    byte[] extension =
        certificate.getExtensionValue(ISISMTTObjectIdentifiers.id_isismtt_at_admission.getId());
    if (extension == null) {
      return Optional.empty();
    }
    AdmissionSyntax admission = AdmissionSyntax.getInstance(ScenarioSignerCheck.parse(extension));
    for (Admissions admissions : admission.getContentsOfAdmissions()) {
      for (ProfessionInfo info : admissions.getProfessionInfos()) {
        if (info.getRegistrationNumber() != null && !info.getRegistrationNumber().isBlank()) {
          return Optional.of(info.getRegistrationNumber());
        }
      }
    }
    return Optional.empty();
  }

  /** ICCSN by rule A, otherwise rule B. */
  static String iccsn(Smcb smcb) {
    Matcher a = RULE_A.matcher(smcb.telematikId());
    if (a.matches()) {
      return "80276" + a.group(1);
    }
    BigInteger digits = new BigInteger(1, sha256(encoded(smcb.certificate()))).mod(RULE_B_DIGITS);
    return "8027699999" + String.format(Locale.ROOT, "%010d", digits);
  }

  /** Subject in BC notation, readable also for GIVENNAME, SURNAME and the like. */
  private static String subject(X509Certificate certificate) {
    return X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded()).toString();
  }

  private static byte[] encoded(X509Certificate certificate) {
    try {
      return certificate.getEncoded();
    } catch (GeneralSecurityException e) {
      throw new IllegalArgumentException("Zertifikat nicht kodierbar: " + e.getMessage(), e);
    }
  }

  private static byte[] sha256(byte[] data) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(data);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static String template() {
    try (InputStream in = P12Cards.class.getClassLoader().getResourceAsStream(TEMPLATE)) {
      if (in == null) {
        throw new IllegalStateException(TEMPLATE + " fehlt auf dem Klassenpfad");
      }
      return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }
}
