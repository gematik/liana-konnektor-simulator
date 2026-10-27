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
package de.gematik.liana.wiring;

import de.gematik.liana.adapter.fake.CardImages;
import de.gematik.liana.config.LianaConfig;
import de.gematik.liana.crypto.CadesSignatures;
import de.gematik.liana.crypto.CmsVerifier;
import de.gematik.liana.crypto.PadesSignatures;
import de.gematik.liana.crypto.SimulatedOcsp;
import de.gematik.liana.crypto.TrustSpace;
import de.gematik.liana.crypto.XadesSignatures;
import de.gematik.liana.kern.access.Infomodel;
import de.gematik.liana.kern.card.AuthState;
import de.gematik.liana.kern.card.CardAccess;
import de.gematik.liana.kern.card.CardCertificates;
import de.gematik.liana.kern.card.CardEvent;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.card.CardLocks;
import de.gematik.liana.kern.card.CardSignature;
import de.gematik.liana.kern.card.CardToCard;
import de.gematik.liana.kern.card.PinVerification;
import de.gematik.liana.kern.card.TrustedChannels;
import de.gematik.liana.kern.management.ClientSystemBinding;
import de.gematik.liana.kern.management.ComfortSettings;
import de.gematik.liana.kern.management.ManagementSettings;
import de.gematik.liana.kern.signature.ComfortSignature;
import de.gematik.liana.kern.signature.DocumentSigning;
import de.gematik.liana.kern.signature.DocumentVerification;
import de.gematik.liana.kern.signature.JobNumbers;
import de.gematik.liana.kern.signature.RevocationSource;
import de.gematik.liana.kern.signature.XmlSignatures;
import de.gematik.liana.kern.terminal.TerminalRegistry;
import de.gematik.liana.kern.vendor.PeerDeviations;
import de.gematik.liana.kern.vendor.VendorProfile;
import de.gematik.liana.sm.Cvc;
import de.gematik.liana.sm.ImageCardToCard;
import de.gematik.liana.sm.TerminalIdentity;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;
import java.time.Clock;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.jboss.logging.Logger;

/**
 * Signature service: Jobnummern for GetJobNumber (TIP1-A_5667), unique across all Aufrufkontexte
 * (TIP1-A_4644); SignDocument nonQES with the SM-B (TUC_KON_160), CMS via BouncyCastle ({@link
 * CadesSignatures}), OCSP from the simulator ({@link SimulatedOcsp}, port {@link
 * RevocationSource}); Komfortsignatur (Komfortsignatur) with the values from TAB_KON_596 ({@link
 * ComfortSettings}, via the KMS), sessions end when the HBA is removed; VerifyDocument with
 * BouncyCastle ({@link CmsVerifier}, decision-022) against TSL and BNetzA-VL ({@link TrustSpace}).
 * QES batches and Komfortsignatur in SE #2 via trusted channels with gSMC-K and gSMC-KT from their
 * images ({@link ImageCardToCard}, LIANA-112.13).
 */
@ApplicationScoped
public class SignatureWiring {

  private static final Logger LOG = Logger.getLogger(SignatureWiring.class);

  @Produces
  @Singleton
  JobNumbers jobNumbers() {
    return new JobNumbers();
  }

  /** Status information for signature certificates: OCSP simulator (decision-021). */
  @Produces
  @Singleton
  SimulatedOcsp revocationSource(Clock clock) {
    return new SimulatedOcsp(clock);
  }

  @Produces
  @Singleton
  ComfortSettings comfortSettings(ClientSystemBinding binding, PeerDeviations deviations) {
    return new ComfortSettings(binding, deviations);
  }

  /**
   * TUC_KON_005 „gegenseitig+TC“ (LIANA-112.13): the gSMC-K from {@code
   * infrastructure.konnektor.gsmc-k.image}, the gSMC-KT per CT from {@code gsmc-kt}, cross CVCs
   * from the TSL. {@code ConfigCheck} checks the images at startup.
   */
  @Produces
  @Singleton
  CardToCard cardToCard(LianaConfig config) {
    CardImages images = new CardImages(config.cardImages());
    List<Cvc> links = TerminalIdentity.links(config.pki().tsl());
    Optional<TerminalIdentity> gsmcK =
        config
            .infrastructure()
            .konnektor()
            .gsmcK()
            .image()
            .map(
                image ->
                    TerminalIdentity.of(
                        TerminalIdentity.Kind.GSMC_K, images.resolve(image), links));
    Map<String, TerminalIdentity> gsmcKts = new HashMap<>();
    config
        .infrastructure()
        .terminals()
        .forEach(
            (id, terminal) ->
                terminal
                    .gsmcKt()
                    .ifPresent(
                        gsmcKt ->
                            gsmcKts.put(id, TerminalIdentity.of(images.resolve(gsmcKt), links))));
    gsmcK.ifPresentOrElse(
        identity -> LOG.infof("QES im SE #2: gSMC-K %s", identity),
        () -> LOG.info("QES im SE #1 ohne Secure Messaging: kein gSMC-K-Image (LIANA-112.13)"));
    return new ImageCardToCard(gsmcK, gsmcKts);
  }

  @Produces
  @Singleton
  TrustedChannels trustedChannels(TerminalRegistry registry, CardToCard c2c) {
    return new TrustedChannels(registry, c2c);
  }

  @Produces
  @Singleton
  ComfortSignature comfortSignature(
      CardAccess access,
      CardList cards,
      CardLocks locks,
      AuthState authState,
      PinVerification pins,
      TerminalRegistry registry,
      ComfortSettings settings,
      TrustedChannels channels,
      Clock clock) {
    ComfortSignature comfort =
        new ComfortSignature(
            access,
            cards,
            locks,
            authState,
            pins,
            new CardSignature(registry),
            settings,
            channels,
            clock);
    cards.addListener(
        event -> {
          if (event.topic() == CardEvent.Topic.REMOVED) {
            comfort.removed(event.card().cardHandle());
          }
        });
    return comfort;
  }

  @Produces
  @Singleton
  DocumentSigning documentSigning(
      CardAccess access,
      CardLocks locks,
      AuthState authState,
      PinVerification pins,
      CardCertificates certificates,
      TerminalRegistry registry,
      JobNumbers jobNumbers,
      RevocationSource revocation,
      ManagementSettings settings,
      VendorProfile vendor,
      ComfortSignature comfort,
      XmlSignatures xml,
      TrustedChannels channels,
      Clock clock) {
    return new DocumentSigning(
        access,
        locks,
        authState,
        pins,
        certificates,
        new CardSignature(registry),
        jobNumbers,
        new CadesSignatures(clock),
        new PadesSignatures(clock),
        xml,
        revocation,
        settings,
        vendor,
        comfort,
        channels);
  }

  /**
   * XAdES for SignDocument and VerifyDocument (LIANA-112.09), a single instance because of the
   * compiled NFD schema.
   */
  @Produces
  @Singleton
  XmlSignatures xmlSignatures(Clock clock) {
    return new XadesSignatures(clock);
  }

  @Produces
  @Singleton
  DocumentVerification documentVerification(
      Infomodel infomodel,
      TrustSpace trustSpace,
      PeerDeviations deviations,
      RevocationSource revocation,
      ManagementSettings settings,
      VendorProfile vendor,
      XmlSignatures xml,
      Clock clock) {
    return new DocumentVerification(
        infomodel,
        new CmsVerifier(trustSpace, deviations, clock),
        new PadesSignatures(clock),
        xml,
        revocation,
        settings,
        vendor,
        clock);
  }
}
