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
package de.gematik.liana.sm;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Identity with which LIANA, as source card, establishes the trusted channel to a card (TUC_KON_005
 * „gegenseitig+TC“, TAB_KON_674): the gSMC-KT of the card terminal ({@code
 * infrastructure.terminals.<CT.CTID>.gsmc-kt}, LIANA-99) with {@code PrK.SMC.AUTD_RPS_CVC.E256} for
 * hop B (LIANA-28) and the remote PIN procedure, the gSMC-K of the Konnektor ({@code
 * infrastructure.konnektor.gsmc-k.image}) with {@code PrK.SAK.AUTD_CVC.E256} for the DTBS transfer
 * for QES (LIANA-112.13); each with CV certificate and the CA certificate above it.
 *
 * <p>If the card trusts a different CVC root than the one the gSMC-KT is under, the connection is
 * made via cross CV certificates (gemSpec_PKI 6.4.5.2, Tab_PKI_937) from the TSL ({@code
 * liana.pki.tsl}, service type {@code Svctype/CA/CVC}): {@link #chainFor} searches the shortest
 * path from a root of the card to the CAR of the CA certificate.
 */
public final class TerminalIdentity {

  /**
   * The source card's objects in the image: CA CVC, role CVC (role authentication,
   * elcSessionkey4SM), key.
   */
  public enum Kind {
    /** gSMC-KT, remote PIN sender (CHAT.54, flag list …02). */
    GSMC_KT("EF.C.CA_SMC.CS.E256", "EF.C.SMC.AUTD_RPS_CVC.E256", "PrK.SMC.AUTD_RPS_CVC.E256"),
    /** gSMC-K, signature application component (CHAT.51, flag list …01, GS-A_4622-01). */
    GSMC_K("EF.C.CA_SAK.CS.E256", "EF.C.SAK.AUTD_CVC.E256", "PrK.SAK.AUTD_CVC.E256");

    private final String caCvc;
    private final String endEntityCvc;
    private final String privateKey;

    Kind(String caCvc, String endEntityCvc, String privateKey) {
      this.caCvc = caCvc;
      this.endEntityCvc = endEntityCvc;
      this.privateKey = privateKey;
    }
  }

  private static final HexFormat HEX = HexFormat.of().withUpperCase();
  private static final Pattern TSL_CVC = Pattern.compile("<(?:\\w+:)?CVCertificate[^>]*>([^<]+)</");

  private final Path image;
  private final Cvc ca;
  private final Cvc endEntity;
  private final ElcSessionkey4Sm.KeyPair key;
  private final List<Cvc> links;

  TerminalIdentity(
      Kind kind, Path image, Cvc ca, Cvc endEntity, ElcSessionkey4Sm.KeyPair key, List<Cvc> links) {
    if (!Arrays.equals(endEntity.car(), ca.chr())) {
      throw new IllegalArgumentException(
          image + ": " + kind.endEntityCvc + " stammt nicht von " + kind.caCvc);
    }
    if (!Arrays.equals(endEntity.publicKey(), key.point())) {
      throw new IllegalArgumentException(
          image + ": " + kind.privateKey + " passt nicht zu " + kind.endEntityCvc);
    }
    this.image = image;
    this.ca = ca;
    this.endEntity = endEntity;
    this.key = key;
    this.links = List.copyOf(links);
  }

  /** The gSMC-KT in the image {@code gsmcKt}, cross CV certificates from {@code links}. */
  public static TerminalIdentity of(Path gsmcKt, List<Cvc> links) {
    return of(Kind.GSMC_KT, gsmcKt, links);
  }

  /**
   * The source card {@code kind} in the image {@code image}, cross CV certificates from {@code
   * links}.
   */
  public static TerminalIdentity of(Kind kind, Path image, List<Cvc> links) {
    ImageObjects objects = ImageObjects.load(image);
    return new TerminalIdentity(
        kind,
        image,
        objects.cvc(kind.caCvc),
        objects.cvc(kind.endEntityCvc),
        objects.privateKey(kind.privateKey),
        links);
  }

  /**
   * All CV certificates of the TSL whose CAR names a different root than the CHR: the cross CV
   * certificates.
   */
  public static List<Cvc> links(Path tsl) {
    String xml;
    try {
      xml = Files.readString(tsl);
    } catch (IOException e) {
      throw new UncheckedIOException("TSL " + tsl + " nicht lesbar", e);
    }
    List<Cvc> links = new ArrayList<>();
    Matcher matcher = TSL_CVC.matcher(xml);
    while (matcher.find()) {
      Cvc cvc = Cvc.parse(Base64.getMimeDecoder().decode(matcher.group(1).replaceAll("&#xD;", "")));
      if (!Arrays.equals(cvc.car(), cvc.chr()) && !links.contains(cvc)) {
        links.add(cvc);
      }
    }
    return links;
  }

  public Path image() {
    return image;
  }

  public Cvc endEntity() {
    return endEntity;
  }

  public ElcSessionkey4Sm.KeyPair key() {
    return key;
  }

  /**
   * The certificates the card must import via PSO VERIFY CERTIFICATE, in this order: cross CVCs
   * starting from a root in {@code trusted}, then the CA and the role CVC. Empty if no path leads
   * to one of these roots.
   */
  public Optional<List<Cvc>> chainFor(Collection<byte[]> trusted) {
    String target = HEX.formatHex(ca.car());
    Set<String> roots = new HashSet<>();
    trusted.forEach(root -> roots.add(HEX.formatHex(root)));
    Map<String, Cvc> reachedVia = new HashMap<>();
    Deque<String> queue = new ArrayDeque<>(roots);
    while (!queue.isEmpty()) {
      String reached = queue.poll();
      if (reached.equals(target)) {
        List<Cvc> chain = new ArrayList<>();
        for (String step = reached; !roots.contains(step); ) {
          Cvc link = reachedVia.get(step);
          chain.addFirst(link);
          step = HEX.formatHex(link.car());
        }
        chain.add(ca);
        chain.add(endEntity);
        return Optional.of(List.copyOf(chain));
      }
      for (Cvc link : links) {
        String next = HEX.formatHex(link.chr());
        if (HEX.formatHex(link.car()).equals(reached)
            && !roots.contains(next)
            && !reachedVia.containsKey(next)) {
          reachedVia.put(next, link);
          queue.add(next);
        }
      }
    }
    return Optional.empty();
  }

  /**
   * TUC_KON_005 variant (9): the possible import sequences for a card whose roots LIANA does not
   * know, shortest first. The first is only CA and role CVC (the card knows the root of the CA
   * CVC), each further one starts with the cross CVCs from another root; MSE SET DST shows which
   * one the card knows ('6A 88' if not).
   */
  public List<List<Cvc>> chains() {
    List<List<Cvc>> chains = new ArrayList<>();
    Map<String, List<Cvc>> paths = new HashMap<>();
    Deque<String> queue = new ArrayDeque<>();
    String start = HEX.formatHex(ca.car());
    paths.put(start, List.of());
    queue.add(start);
    while (!queue.isEmpty()) {
      String root = queue.poll();
      List<Cvc> path = paths.get(root);
      List<Cvc> chain = new ArrayList<>(path);
      chain.add(ca);
      chain.add(endEntity);
      chains.add(List.copyOf(chain));
      for (Cvc link : links) {
        String from = HEX.formatHex(link.car());
        if (HEX.formatHex(link.chr()).equals(root) && !paths.containsKey(from)) {
          List<Cvc> longer = new ArrayList<>();
          longer.add(link);
          longer.addAll(path);
          paths.put(from, List.copyOf(longer));
          queue.add(from);
        }
      }
    }
    return List.copyOf(chains);
  }

  @Override
  public String toString() {
    return "TerminalIdentity["
        + image.getFileName()
        + ", CHR "
        + HEX.formatHex(endEntity.chr())
        + "]";
  }
}
