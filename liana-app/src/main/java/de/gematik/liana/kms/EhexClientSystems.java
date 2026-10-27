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
package de.gematik.liana.kms;

import static de.gematik.liana.kms.EhexKms.body;
import static de.gematik.liana.kms.EhexKms.json;
import static de.gematik.liana.kms.EhexKms.validation;

import de.gematik.liana.config.LianaConfig;
import de.gematik.liana.crypto.ClientCertificates;
import de.gematik.liana.crypto.ServerIdentities;
import de.gematik.liana.crypto.TlsIdentity;
import de.gematik.liana.crypto.TlsKeys;
import de.gematik.liana.kern.management.ClientSystemBinding;
import de.gematik.liana.kern.management.ClientSystemBinding.Authentication;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.IntStream;

/**
 * The subset of the EHEX Managementschnittstelle for the connection of the Clientsysteme that the
 * CATS_CS scenarios of Konnektor-E2E need via kms-client (LIANA-65). Paths, fields and status codes
 * as in {@code KmsEhex} in kms-client 1.1.0, schemas from the EHEX spec 0.9.9 ({@code Infomodell},
 * {@code Clientsystem}, {@code ClientSystemCertificate}, {@code ClientsystemAnbindung}, {@code
 * RestResultObject}); where the two differ, kms-client wins (doc-2):
 *
 * <ul>
 *   <li>{@code GET …/ak/info}: Informationsmodell from the YAML (mandants, Clientsysteme,
 *       workplaces), internal IDs {@code m-n}, {@code cs-n}, {@code ap-n}; {@code GET
 *       …/ak/info/clientsysteme}: Clientsysteme with ANCL_CCERT_LIST.
 *   <li>{@code POST …/ak/info/clientsysteme/{id}/zertifikat}: with {@code generateNew} LIANA
 *       generates key and certificate ({@code cryptType} RSA → RSA-3072, ECC with {@code eccCurve}
 *       NIST_P256 → P-256) as PKCS#12 with {@code password}, file name {@code
 *       <clientSystemId>.p12}; otherwise it imports {@code certificate} (base64 of PEM or DER). 201
 *       with {@code data.internalId} and {@code data.filename} (spec: 200). A_21811-05: RSA-2048,
 *       Brainpool and other algorithms → 400. {@code GET …/{certId}} returns the PKCS#12, {@code
 *       DELETE …/{certId}} removes it.
 *   <li>{@code GET/PUT …/ak/dienste/clientsystem-anbindung/einstellungen}: {@code tlsMandatory}
 *       (ANCL_TLS_MANDATORY), {@code authenticationMode} (ANCL_CAUT_MANDATORY/ANCL_CAUT_MODE),
 *       {@code dvdTlsNotMandatory} (ANCL_DVD_OPEN), {@code serverAuthenticationUseSoftwareKey}.
 *       Switching off ANCL_TLS_MANDATORY and switching on the software key is confirmed by the
 *       administrator (spec „Bestätigungsmechanismus“): 300 with {@code confirmationToken}, then
 *       the same PUT with {@code ?confirmation=}. LIANA does not implement PASSWORD (basic auth) →
 *       501.
 *   <li>{@code GET/PUT …/ak/dienste/tls/einstellungen}: {@code
 *       eccUseForClientSystemConnectionEnabled} (TLS_USE_ECC_FOR_CS), {@code eccCipherEnabled}
 *       read-only (always on).
 *   <li>{@code POST …/clientsystem-anbindung/server-zertifikat}: generate ({@code generateNew},
 *       {@code hostname}, {@code alternativeHostnames}) or import ({@code keystore} base64 PKCS#12
 *       with {@code password}, A_21697-01), rules as above; {@code DELETE} removes it and switches
 *       back to ID.AK.AUT.
 * </ul>
 *
 * LIANA accepts booleans as JSON boolean or as string {@code "true"}/{@code "false"}: kms-client
 * writes {@code dvdTlsNotMandatory} and {@code eccUseForClientSystemConnectionEnabled} as strings.
 */
final class EhexClientSystems {

  static final String INFO = "/rest/mgmt/ak/info";
  static final String CLIENT_SYSTEMS = "/rest/mgmt/ak/info/clientsysteme";
  static final String CERTIFICATES = CLIENT_SYSTEMS + "/:id/zertifikat";
  static final String CERTIFICATE = CERTIFICATES + "/:certId";
  static final String BINDING = "/rest/mgmt/ak/dienste/clientsystem-anbindung/einstellungen";
  static final String SERVER_CERTIFICATE =
      "/rest/mgmt/ak/dienste/clientsystem-anbindung/server-zertifikat";
  static final String TLS_SETTINGS = "/rest/mgmt/ak/dienste/tls/einstellungen";

  private final LianaConfig.Infomodel infomodel;
  private final ClientSystemBinding clientSystemBinding;
  private final ClientCertificates clientCertificates;
  private final ServerIdentities identities;
  private final Set<String> confirmations = ConcurrentHashMap.newKeySet();
  private final SecureRandom random = new SecureRandom();

  EhexClientSystems(
      LianaConfig config,
      ClientSystemBinding binding,
      ClientCertificates certificates,
      ServerIdentities identities) {
    this.infomodel = config.infomodel();
    this.clientSystemBinding = binding;
    this.clientCertificates = certificates;
    this.identities = identities;
  }

  /** Attaches the routes; what they do not serve goes via {@code ctx.next()} to the 501 handler. */
  void routes(Router router) {
    router.get(KmsServer.relative(INFO)).handler(ctx -> json(ctx, 200, info()));
    router
        .get(KmsServer.relative(CLIENT_SYSTEMS))
        .handler(
            ctx ->
                ctx.response()
                    .setStatusCode(200)
                    .putHeader("Content-Type", "application/json")
                    .end(clientSystems().encode()));
    router.post(KmsServer.relative(CERTIFICATES)).blockingHandler(this::postCertificate);
    router.get(KmsServer.relative(CERTIFICATE)).handler(this::getCertificate);
    router.delete(KmsServer.relative(CERTIFICATE)).handler(this::deleteCertificate);
    router.get(KmsServer.relative(BINDING)).handler(ctx -> json(ctx, 200, bindingJson()));
    router.put(KmsServer.relative(BINDING)).handler(this::putBinding);
    router.get(KmsServer.relative(TLS_SETTINGS)).handler(ctx -> json(ctx, 200, tlsJson()));
    router.put(KmsServer.relative(TLS_SETTINGS)).handler(this::putTls);
    router
        .post(KmsServer.relative(SERVER_CERTIFICATE))
        .blockingHandler(this::postServerCertificate);
    router.delete(KmsServer.relative(SERVER_CERTIFICATE)).handler(this::deleteServerCertificate);
  }

  void reset() {
    confirmations.clear();
  }

  // Informationsmodell (Infomodell)

  private List<String> clientSystemIds() {
    return infomodel.clientSystems();
  }

  private static String internalId(String prefix, int index) {
    return prefix + "-" + (index + 1);
  }

  private Optional<String> clientSystem(String internalId) {
    List<String> ids = clientSystemIds();
    return IntStream.range(0, ids.size())
        .filter(i -> internalId(("cs"), i).equals(internalId))
        .mapToObj(ids::get)
        .findFirst();
  }

  private JsonObject info() {
    List<String> mandants = infomodel.mandants();
    JsonArray mandanten = new JsonArray();
    IntStream.range(0, mandants.size())
        .forEach(
            i ->
                mandanten.add(
                    new JsonObject()
                        .put("mandantId", mandants.get(i))
                        .put("internalId", internalId("m", i))));
    var workplaces = infomodel.workplaces();
    JsonArray arbeitsplaetze = new JsonArray();
    IntStream.range(0, workplaces.size())
        .forEach(
            i ->
                arbeitsplaetze.add(
                    new JsonObject()
                        .put("arbeitsplatzId", workplaces.get(i).id())
                        .put("internalId", internalId("ap", i))));
    return new JsonObject()
        .put("mandanten", mandanten)
        .put("clientSystems", clientSystems())
        .put("arbeitsplaetze", arbeitsplaetze);
  }

  private JsonArray clientSystems() {
    List<String> ids = clientSystemIds();
    JsonArray list = new JsonArray();
    for (int i = 0; i < ids.size(); i++) {
      JsonArray certs = new JsonArray();
      for (ClientCertificates.Entry entry : clientCertificates.of(ids.get(i))) {
        certs.add(certificateJson(entry));
      }
      list.add(
          new JsonObject()
              .put("clientSystemId", ids.get(i))
              .put("internalId", internalId("cs", i))
              .put("certificates", certs)
              .put("userCredentials", new JsonArray()));
    }
    return list;
  }

  private static JsonObject certificateJson(ClientCertificates.Entry entry) {
    JsonObject json =
        new JsonObject().put("internalId", entry.internalId()).put("filename", entry.filename());
    try {
      json.put("certificate", Base64.getEncoder().encodeToString(entry.certificate().getEncoded()));
    } catch (CertificateEncodingException e) {
      // without encoding only ID and name
    }
    return json;
  }

  // Clientsystem certificates

  private void postCertificate(RoutingContext ctx) {
    Optional<String> clientSystem = clientSystem(ctx.pathParam("id"));
    if (clientSystem.isEmpty()) {
      notFound(ctx, "Clientsystem " + ctx.pathParam("id"));
      return;
    }
    JsonObject body = body(ctx);
    if (body == null) {
      validation(ctx, null, "Body ist kein JSON-Objekt (ClientSystemCertificate)");
      return;
    }
    ClientCertificates.Entry entry;
    try {
      if (bool(body, "generateNew", false)) {
        String password = body.getString("password");
        if (password == null || password.isEmpty()) {
          validation(ctx, "password", "Pflichtfeld bei generateNew");
          return;
        }
        entry = clientCertificates.generate(clientSystem.get(), algorithm(body), password);
      } else {
        Object certificate = body.getValue("certificate");
        if (!(certificate instanceof String base64)) {
          validation(ctx, "certificate", "Zertifikat (base64) fehlt");
          return;
        }
        entry =
            clientCertificates.importCertificate(
                clientSystem.get(),
                Base64.getMimeDecoder().decode(base64),
                body.getString("filename", "import.pem"));
      }
    } catch (TlsKeys.RejectedKeyException | IllegalArgumentException e) {
      validation(ctx, "certificate", e.getMessage());
      return;
    } catch (GeneralSecurityException e) {
      json(ctx, 500, new JsonObject().put("message", e.getMessage()));
      return;
    }
    json(ctx, 201, new JsonObject().put("data", certificateJson(entry)));
  }

  private void getCertificate(RoutingContext ctx) {
    Optional<ClientCertificates.Entry> entry =
        clientSystem(ctx.pathParam("id"))
            .flatMap(cs -> clientCertificates.find(cs, ctx.pathParam("certId")));
    if (entry.isEmpty()) {
      notFound(ctx, "Zertifikat " + ctx.pathParam("certId"));
      return;
    }
    if (!entry.get().generated()) {
      ctx.next(); // export of imported certificates: LIANA has no key for them
      return;
    }
    ctx.response()
        .setStatusCode(200)
        .putHeader("Content-Type", "application/pkcs12")
        .putHeader("Content-Disposition", "attachment; filename=\"" + entry.get().filename() + "\"")
        .end(io.vertx.core.buffer.Buffer.buffer(entry.get().pkcs12()));
  }

  private void deleteCertificate(RoutingContext ctx) {
    Optional<String> clientSystem = clientSystem(ctx.pathParam("id"));
    if (clientSystem.isEmpty()
        || !clientCertificates.remove(clientSystem.get(), ctx.pathParam("certId"))) {
      notFound(ctx, "Zertifikat " + ctx.pathParam("certId"));
      return;
    }
    json(ctx, 200, new JsonObject());
  }

  // Settings

  private JsonObject bindingJson() {
    ClientSystemBinding.State state = clientSystemBinding.state();
    return new JsonObject()
        .put("tlsMandatory", state.tlsMandatory())
        .put("authenticationMode", state.authentication().name())
        .put("dvdTlsNotMandatory", state.dvdOpen())
        .put("serverAuthenticationUseSoftwareKey", state.serverSoftwareKey());
  }

  private void putBinding(RoutingContext ctx) {
    JsonObject body = body(ctx);
    if (body == null) {
      validation(ctx, null, "Body ist kein JSON-Objekt (ClientsystemAnbindung)");
      return;
    }
    ClientSystemBinding.State old = clientSystemBinding.state();
    ClientSystemBinding.State next;
    try {
      Authentication mode =
          Authentication.valueOf(body.getString("authenticationMode", old.authentication().name()));
      if (mode == Authentication.PASSWORD) {
        ctx.next(); // LIANA does not implement basic auth against ANCL_CUP_LIST (TIP1-A_4516)
        return;
      }
      next =
          old.withTlsMandatory(bool(body, "tlsMandatory", old.tlsMandatory()))
              .withAuthentication(mode)
              .withDvdOpen(bool(body, "dvdTlsNotMandatory", old.dvdOpen()))
              .withServerSoftwareKey(
                  bool(body, "serverAuthenticationUseSoftwareKey", old.serverSoftwareKey()));
    } catch (IllegalArgumentException | ClassCastException e) {
      validation(ctx, null, "ClientsystemAnbindung: " + e.getMessage());
      return;
    }
    if (next.serverSoftwareKey() && identities.software().isEmpty()) {
      validation(
          ctx,
          "serverAuthenticationUseSoftwareKey",
          "kein Serverzertifikat erzeugt oder importiert");
      return;
    }
    boolean confirm =
        old.tlsMandatory() && !next.tlsMandatory()
            || !old.serverSoftwareKey() && next.serverSoftwareKey();
    if (confirm && !confirmations.remove(String.valueOf(ctx.request().getParam("confirmation")))) {
      byte[] bytes = new byte[16];
      random.nextBytes(bytes);
      String token = HexFormat.of().formatHex(bytes);
      confirmations.add(token);
      json(
          ctx,
          300,
          new JsonObject()
              .put("confirmationToken", token)
              .put(
                  "message",
                  "Bestätigung erforderlich: "
                      + (old.tlsMandatory() && !next.tlsMandatory()
                          ? "ohne ANCL_TLS_MANDATORY trägt der Betreiber die Verantwortung für die vertrauliche "
                              + "Übertragung (TIP1-A_4518-02)"
                          : "Serverzertifikat ersetzt ID.AK.AUT gegenüber den Clientsystemen")));
      return;
    }
    clientSystemBinding.state(next);
    json(ctx, 200, bindingJson());
  }

  private JsonObject tlsJson() {
    return new JsonObject()
        .put("eccCipherEnabled", true)
        .put(
            "eccUseForClientSystemConnectionEnabled",
            clientSystemBinding.state().eccForClientSystems());
  }

  private void putTls(RoutingContext ctx) {
    JsonObject body = body(ctx);
    if (body == null) {
      validation(ctx, null, "Body ist kein JSON-Objekt (TLS-Einstellungen)");
      return;
    }
    boolean ecc;
    try {
      if (!bool(body, "eccCipherEnabled", true)) {
        ctx.next(); // TLS_USE_ECC_CIPHER off: LIANA always offers the suites according to
        // GS-A_4384-03
        return;
      }
      ecc =
          bool(
              body,
              "eccUseForClientSystemConnectionEnabled",
              clientSystemBinding.state().eccForClientSystems());
    } catch (IllegalArgumentException | ClassCastException e) {
      validation(ctx, null, "TLS-Einstellungen: " + e.getMessage());
      return;
    }
    if (!ecc && !identities.hasRsa()) {
      validation(
          ctx,
          "eccUseForClientSystemConnectionEnabled",
          "keine RSA-Identität konfiguriert (liana.infrastructure.konnektor.gsmc-k.ak-aut-rsa)");
      return;
    }
    clientSystemBinding.state(clientSystemBinding.state().withEccForClientSystems(ecc));
    json(ctx, 200, tlsJson());
  }

  // Server certificate

  private void postServerCertificate(RoutingContext ctx) {
    JsonObject body = body(ctx);
    if (body == null) {
      validation(ctx, null, "Body ist kein JSON-Objekt (Serverzertifikat)");
      return;
    }
    TlsIdentity identity;
    try {
      if (bool(body, "generateNew", false)) {
        Set<String> hostnames = new LinkedHashSet<>();
        Optional.ofNullable(body.getString("hostname"))
            .filter(h -> !h.isBlank())
            .ifPresent(hostnames::add);
        JsonArray alternatives = body.getJsonArray("alternativeHostnames", new JsonArray());
        alternatives.forEach(h -> hostnames.add(String.valueOf(h)));
        identity = identities.generate(algorithm(body), new ArrayList<>(hostnames));
      } else {
        String keystore = body.getString("keystore");
        if (keystore == null) {
          validation(ctx, "keystore", "PKCS#12 (base64) fehlt");
          return;
        }
        identity =
            identities.importPkcs12(
                Base64.getMimeDecoder().decode(keystore), body.getString("password", ""));
      }
    } catch (TlsKeys.RejectedKeyException | IllegalArgumentException | ClassCastException e) {
      validation(ctx, "keystore", e.getMessage());
      return;
    } catch (GeneralSecurityException e) {
      json(ctx, 500, new JsonObject().put("message", e.getMessage()));
      return;
    }
    json(
        ctx,
        200,
        new JsonObject()
            .put(
                "data",
                new JsonObject()
                    .put("subject", identity.certificate().getSubjectX500Principal().getName())
                    .put("algorithm", TlsKeys.describe(identity.certificate().getPublicKey()))
                    .put("fingerprint", identity.fingerprint())));
  }

  private void deleteServerCertificate(RoutingContext ctx) {
    identities.remove();
    clientSystemBinding.state(clientSystemBinding.state().withServerSoftwareKey(false));
    json(ctx, 200, new JsonObject());
  }

  // Helpers

  /**
   * {@code cryptType}/{@code eccCurve} as kms-client sends them. RSA without a length generates
   * RSA-3072 (TAB_KON_866); Brainpool is rejected per A_21811-05.
   */
  private static TlsKeys.Algorithm algorithm(JsonObject body) throws TlsKeys.RejectedKeyException {
    String type = body.getString("cryptType");
    String curve = body.getString("eccCurve");
    if ("RSA".equals(type) && curve == null) {
      return TlsKeys.Algorithm.RSA_3072;
    }
    if ("ECC".equals(type) && "NIST_P256".equals(curve)) {
      return TlsKeys.Algorithm.ECC_NIST_P256;
    }
    if ("BRAINPOOL_P256".equals(curve)) {
      throw new TlsKeys.RejectedKeyException(
          "ECC-256 mit brainpool-Kurve darf nicht erzeugt werden " + "(A_21811-05, TAB_KON_866)");
    }
    throw new TlsKeys.RejectedKeyException(
        "cryptType "
            + type
            + " / eccCurve "
            + curve
            + " nicht erzeugbar; erlaubt: RSA (RSA-3072), ECC mit NIST_P256 (A_21811-05)");
  }

  /** JSON boolean or string true/false; otherwise {@link IllegalArgumentException}. */
  static boolean bool(JsonObject body, String field, boolean fallback) {
    Object value = body.getValue(field);
    if (value == null) {
      return fallback;
    }
    if (value instanceof Boolean b) {
      return b;
    }
    if ("true".equalsIgnoreCase(String.valueOf(value))
        || "false".equalsIgnoreCase(String.valueOf(value))) {
      return Boolean.parseBoolean(String.valueOf(value));
    }
    throw new IllegalArgumentException(field + ": true oder false erwartet, nicht '" + value + "'");
  }

  private static void notFound(RoutingContext ctx, String what) {
    json(
        ctx,
        404,
        new JsonObject()
            .put(
                "generalErrors",
                new JsonArray().add(new JsonObject().put("message", what + " nicht gefunden"))));
  }
}
