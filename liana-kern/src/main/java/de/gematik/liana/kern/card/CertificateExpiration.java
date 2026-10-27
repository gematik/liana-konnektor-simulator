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

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.access.Infomodel;
import de.gematik.liana.kern.error.ConnectorError;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

/**
 * TIP1-A_4699-07 operation CheckCertificateExpiration (TAB_KON_676, flow TAB_KON_677): per card
 * TUC_KON_033 „Zertifikatsablauf prüfen“ (TIP1-A_4695-03, without system event: doInformClients =
 * false) and TUC_KON_034 for the AUT certificate, without CardHandle additionally the gSMC-K with
 * C.NK.VPN. If a certificate is missing, the card yields no entry but a warning 4257 with its
 * CardHandle (secunet connector: „RSAZertifikat nicht vorhanden auf Karte: HBA-2“).
 *
 * <p>Crypt defaults to ECC, also with the CardHandle of a G2.0 card: LIANA does not distinguish
 * G2.0 and G2.1 (like {@link CardCertificates}). The operation does not check the card lock
 * (TUC_KON_026); it only reads.
 */
public final class CertificateExpiration {

  private static final List<String> CRYPT = List.of("RSA", "ECC");

  /** Call parameters; {@code cardHandle} and {@code crypt} are optional ({@code null}). */
  public record Request(Context context, String cardHandle, String crypt) {}

  /**
   * A tuple (CtID, CardHandle, ICCSN, subject.CommonName, serialNumber, validity); for the gSMC-K,
   * CtID and CardHandle are empty.
   */
  public record Entry(
      String ctId,
      String cardHandle,
      String iccsn,
      String commonName,
      String serialNumber,
      LocalDate validity) {}

  /** The tuples and, per card without a matching certificate, the text of warning 4257. */
  public record Result(List<Entry> entries, List<String> warnings) {}

  private final Infomodel infomodel;
  private final CardList cards;
  private final CardAccess access;
  private final CardCertificates certificates;
  private final Optional<GsmcK> gsmcK;

  public CertificateExpiration(
      Infomodel infomodel,
      CardList cards,
      CardAccess access,
      CardCertificates certificates,
      Optional<GsmcK> gsmcK) {
    this.infomodel = infomodel;
    this.cards = cards;
    this.access = access;
    this.certificates = certificates;
    this.gsmcK = gsmcK;
  }

  public Result execute(Request request) {
    // TAB_KON_677 step 1: checkArguments
    if (request.crypt() != null && !CRYPT.contains(request.crypt())) {
      throw ConnectorError.SYNTAX.exception("Crypt '" + request.crypt() + "'");
    }
    String crypt = request.crypt() == null ? "ECC" : request.crypt();
    List<CardObject> selected;
    if (request.cardHandle() != null) {
      // step 2: TUC_KON_000 with cardHandle; the eGK MUST NOT be supported (4058)
      CardObject card = access.card(request.context(), request.cardHandle());
      if (!supported(card)) {
        throw ConnectorError.CALL_NOT_ALLOWED.exception(
            card.data().type().value() + " " + card.cardHandle());
      }
      selected = List.of(card);
    } else {
      // steps 2 and 3: TUC_KON_000 with allWorkplaces = true, cards of the mandant without
      // workplace filter
      Set<String> reachable = infomodel.checkAccess(request.context(), true);
      selected =
          cards.cards().stream()
              .filter(c -> reachable.contains(c.ctId()))
              .filter(CertificateExpiration::supported)
              .toList();
    }
    List<Entry> entries = new ArrayList<>();
    List<String> warnings = new ArrayList<>();
    for (CardObject card : selected) {
      // steps 5 and 6: TUC_KON_033, TUC_KON_034
      byte[] der = certificates.aut(card, crypt);
      if (der == null) {
        warnings.add(warning(crypt, card.cardHandle()));
      } else {
        entries.add(entry(card.ctId(), card.cardHandle(), card.data().iccsn(), der));
      }
    }
    if (request.cardHandle() == null && gsmcK.isPresent()) {
      // TUC_KON_033 with checkSMCK = true: C.NK.VPN; if missing (4256), warning 4257
      byte[] der = gsmcK.get().nkVpn(crypt);
      if (der == null) {
        warnings.add(warning(crypt, "gSMC-K"));
      } else {
        entries.add(entry("", "", gsmcK.get().iccsn(), der));
      }
    }
    return new Result(List.copyOf(entries), List.copyOf(warnings));
  }

  /** TAB_KON_676: HBAx, SM-B and gSMC-KT; not eGK, KVK and unknown cards. */
  private static boolean supported(CardObject card) {
    CardType type = card.data().type();
    return type == CardType.SMC_B || type == CardType.SMC_KT || type.matches("HBAx");
  }

  private static String warning(String crypt, String cardHandle) {
    return ConnectorError.CERT_MISSING
        .text()
        .replace("<$Crypt>", crypt)
        .replace("<cardHandle>", cardHandle);
  }

  /**
   * TUC_KON_034: subject.CommonName, serialNumber (decimal) and the expiry date from validity
   * (UTC).
   */
  private static Entry entry(String ctId, String cardHandle, String iccsn, byte[] der) {
    try {
      X509Certificate certificate =
          (X509Certificate)
              CertificateFactory.getInstance("X.509")
                  .generateCertificate(new ByteArrayInputStream(der));
      return new Entry(
          ctId,
          cardHandle,
          iccsn,
          commonName(certificate),
          certificate.getSerialNumber().toString(),
          LocalDate.ofInstant(certificate.getNotAfter().toInstant(), ZoneOffset.UTC));
    } catch (CertificateException | NamingException e) {
      // TAB_KON_600 (2): extraction of the expiry date failed
      throw ConnectorError.EXPIRATION_UNREADABLE
          .exception(cardHandle.isEmpty() ? "gSMC-K" : cardHandle)
          .causedBy(e);
    }
  }

  /** CN of the subject; an RDN can be multi-valued (C.HP.AUT: SN + GN + serialNumber + CN). */
  private static String commonName(X509Certificate certificate) throws NamingException {
    for (Rdn rdn : new LdapName(certificate.getSubjectX500Principal().getName()).getRdns()) {
      for (Attribute attribute : Collections.list(rdn.toAttributes().getAll())) {
        if (attribute.getID().equalsIgnoreCase("CN")) {
          return String.valueOf(attribute.get());
        }
      }
    }
    return "";
  }
}
