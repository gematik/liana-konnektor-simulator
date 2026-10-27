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

import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Optional;
import java.util.function.Function;
import javax.net.ssl.X509TrustManager;

/**
 * Check of the KT certificate in the TLS handshake to the eHealth KT: TUC_KON_050 step 3 calls
 * TUC_KON_037 with {@code certificate = C.SMKT.AUT}, {@code policyList = oid_smkt_aut}, {@code
 * intendedKeyUsage = intendedKeyUsage(C.SMKT.AUT)}, {@code intendedExtendedKeyUsage =
 * id-kp-serverAuth}, {@code validationMode = NONE} (no revocation check), {@code
 * offlineAllowNoCheck = true}.
 *
 * <p>Checked in the order of TUC_PKI_018: validity period, KeyUsage digitalSignature,
 * ExtendedKeyUsage serverAuth, issuer in the Vertrauensraum (TSL or imported) including signature,
 * certificate type oid_smkt_aut. Any error aborts the handshake; TUC_KON_050 reports it as 4028.
 */
public final class SmktCertificateCheck implements X509TrustManager {

  /** gemSpec_OID: certificate type C.SMKT.AUT. */
  static final String OID_SMKT_AUT = "1.2.276.0.76.4.163";

  private final Function<X509Certificate, Optional<X509Certificate>> issuers;
  private final Clock clock;

  /**
   * @param issuers supplies the issuer certificate from the Vertrauensraum
   */
  public SmktCertificateCheck(
      Function<X509Certificate, Optional<X509Certificate>> issuers, Clock clock) {
    this.issuers = issuers;
    this.clock = clock;
  }

  /** Check against the Vertrauensraum made of the TSL and imported CAs. */
  public static SmktCertificateCheck of(TrustSpace trustSpace, Clock clock) {
    return new SmktCertificateCheck(
        certificate -> trustSpace.issuerOf(certificate).map(TrustSpace.Ca::certificate), clock);
  }

  /** TUC_KON_037 for {@code certificate} as C.SMKT.AUT. */
  public void check(X509Certificate certificate) throws CertificateException {
    ServerCertificateCheck.check(
        certificate, "C.SMKT.AUT", "oid_smkt_aut", OID_SMKT_AUT, issuers, clock);
  }

  /**
   * Verify the KT's signature over {@code message} with the key of C.SMKT.AUT: ECDSA with SHA-256,
   * {@code r ‖ s} plain per TR-03111 §5.2.1 (gemSpec_KT SEQ_KT_0001-01 step 7/8, gemSpec_Krypt
   * A_17090).
   */
  public static boolean verifyPlainEcdsa(
      X509Certificate smktAut, byte[] message, byte[] signature) {
    try {
      java.security.Signature verifier =
          java.security.Signature.getInstance("SHA256withPLAIN-ECDSA", CryptoProviders.BC);
      verifier.initVerify(smktAut.getPublicKey());
      verifier.update(message);
      return verifier.verify(signature);
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType)
      throws CertificateException {
    if (chain == null || chain.length == 0) {
      throw new CertificateException("KT ohne Zertifikat");
    }
    check(chain[0]);
  }

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType)
      throws CertificateException {
    throw new CertificateException("SmktCertificateCheck prüft nur das Zertifikat des KT");
  }

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    return new X509Certificate[0];
  }
}
