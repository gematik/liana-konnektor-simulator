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
package de.gematik.liana.konnektor;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax;
import org.bouncycastle.asn1.isismtt.x509.Admissions;
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;

/**
 * Telematik-ID and profession OIDs from the Admission extension (gemSpec_PKI, OID 1.3.36.8.3.3).
 */
final class TelematikId {

  static final String ADMISSION = "1.3.36.8.3.3";

  private TelematikId() {}

  static Optional<String> of(X509Certificate certificate) {
    return professionInfos(certificate).stream()
        .map(ProfessionInfo::getRegistrationNumber)
        .filter(java.util.Objects::nonNull)
        .findFirst();
  }

  static List<String> professionOids(X509Certificate certificate) {
    return professionInfos(certificate).stream()
        .flatMap(info -> Arrays.stream(info.getProfessionOIDs()))
        .map(ASN1ObjectIdentifier::getId)
        .toList();
  }

  private static List<ProfessionInfo> professionInfos(X509Certificate certificate) {
    byte[] extension = certificate.getExtensionValue(ADMISSION);
    if (extension == null) {
      return List.of();
    }
    try {
      AdmissionSyntax admission =
          AdmissionSyntax.getInstance(
              ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(extension).getOctets()));
      List<ProfessionInfo> infos = new ArrayList<>();
      for (Admissions admissions : admission.getContentsOfAdmissions()) {
        infos.addAll(Arrays.asList(admissions.getProfessionInfos()));
      }
      return infos;
    } catch (java.io.IOException | IllegalArgumentException e) {
      return List.of();
    }
  }
}
