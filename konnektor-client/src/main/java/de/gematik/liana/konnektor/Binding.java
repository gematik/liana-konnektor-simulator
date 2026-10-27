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

import de.gematik.liana.konnektor.ws.conn.cardservice.v8_1.VerifyPin;
import de.gematik.liana.konnektor.ws.conn.cardterminalservice.v1_1.RequestCard;
import de.gematik.liana.konnektor.ws.conn.certificateservice.v6_0.ReadCardCertificate;
import de.gematik.liana.konnektor.ws.conn.encryptionservice.v6_1.EncryptDocument;
import de.gematik.liana.konnektor.ws.conn.eventservice.v7_2.GetCards;
import de.gematik.liana.konnektor.ws.conn.signatureservice.v7_4.SignDocument;
import de.gematik.liana.konnektor.ws.conn.vsds.vsdservice.v5_2.ReadVSD;

/**
 * The client's JAXB bindings: one package per service and major/minor version, because each minor
 * version has its own namespace (LIANA-132). Generated from the schemas in {@code liana-contract},
 * per namespace from the newest revision in the snapshot (api-telematik 6.0.3); every revision of
 * the same major/minor version is served (TIP1-A_4966).
 */
public enum Binding {
  EVENT_SERVICE_7_2(Service.EVENT_SERVICE, 7, 2, "conn/EventService.wsdl", GetCards.class),
  CARD_SERVICE_8_1(Service.CARD_SERVICE, 8, 1, "conn/CardService_v8_1_2.wsdl", VerifyPin.class),
  CARD_SERVICE_8_2(
      Service.CARD_SERVICE,
      8,
      2,
      "conn/CardService_v8_2_1.wsdl",
      de.gematik.liana.konnektor.ws.conn.cardservice.v8_2.VerifyPin.class),
  CARD_TERMINAL_SERVICE_1_1(
      Service.CARD_TERMINAL_SERVICE, 1, 1, "conn/CardTerminalService.wsdl", RequestCard.class),
  CERTIFICATE_SERVICE_6_0(
      Service.CERTIFICATE_SERVICE,
      6,
      0,
      "conn/CertificateService_v6_0_3.wsdl",
      ReadCardCertificate.class),
  AUTH_SIGNATURE_SERVICE_7_4(
      Service.AUTH_SIGNATURE_SERVICE,
      7,
      4,
      "conn/AuthSignatureService_v7_4_1.wsdl",
      SignDocument.class),
  SIGNATURE_SERVICE_7_4(
      Service.SIGNATURE_SERVICE, 7, 4, "conn/SignatureService_V7_4_3.wsdl", SignDocument.class),
  SIGNATURE_SERVICE_7_5(
      Service.SIGNATURE_SERVICE,
      7,
      5,
      "conn/SignatureService_V7_5_7.wsdl",
      de.gematik.liana.konnektor.ws.conn.signatureservice.v7_5.SignDocument.class),
  ENCRYPTION_SERVICE_6_1(
      Service.ENCRYPTION_SERVICE,
      6,
      1,
      "conn/EncryptionService_v6_1_1.wsdl",
      EncryptDocument.class),
  /** Fachmodul VSDM; namespace {@code conn/vsds/VSDService/v5.2}, SOAPAction per WSDL with v6.0. */
  VSD_SERVICE_5_2(Service.VSD_SERVICE, 5, 2, "conn/vsds/VSDService.wsdl", ReadVSD.class);

  private final Service service;
  private final int major;
  private final int minor;
  private final String wsdl;
  private final Class<?> anchor;

  Binding(Service service, int major, int minor, String wsdl, Class<?> anchor) {
    this.service = service;
    this.major = major;
    this.minor = minor;
    this.wsdl = wsdl;
    this.anchor = anchor;
  }

  /** Service of the binding. */
  public Service service() {
    return service;
  }

  /** Major and minor version, without revision. */
  public String version() {
    return major + "." + minor;
  }

  /** Serves an offered version if major and minor version match (TIP1-A_4966). */
  public boolean serves(Version offered) {
    return offered.compatibleWith(major, minor);
  }

  /** WSDL in {@code liana-contract}, relativ zu {@code support/schemas}. */
  public String wsdl() {
    return wsdl;
  }

  /** Java package of the request and response types. */
  public String javaPackage() {
    return anchor.getPackageName();
  }
}
