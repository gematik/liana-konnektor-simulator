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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Connection to a Konnektor (LIANA-133): configuration from {@code .kon} or builder, service
 * directory, SOAP calls via a {@link Transport}. Thread-safe; the Dienstverzeichnis is read when
 * first needed and fetched again with {@link #refresh()} (gemILF_PS 4.1.2: after errors and after a
 * Konnektor restart).
 *
 * <pre>{@code
 * try (Konnektor kon = Konnektor.fromKon(Path.of("praxis.kon"))) {
 *     GetCardsResponse cards = kon.invoke(Operation.GET_CARDS, request, GetCardsResponse.class);
 * }
 * }</pre>
 */
public final class Konnektor implements AutoCloseable {

  private static final System.Logger LOG = System.getLogger(Konnektor.class.getName());

  private final URI url;
  private final String product;
  private final QuirksTable quirks;
  private volatile boolean warnedUnknown;
  private final boolean rewriteServiceEndpoints;
  private final Context context;
  private final Deployment deployment;
  private final Duration shortTimeout;
  private final Duration longTimeout;
  private final Transport transport;
  private final PinPromptHandler pinPrompt;
  private final EventSink eventSink;
  private Events events;
  private volatile ServiceDirectory directory;

  private Konnektor(Builder builder, Transport transport) {
    this.url = builder.url;
    this.product = builder.product;
    this.quirks = builder.quirks;
    this.rewriteServiceEndpoints = builder.rewriteServiceEndpoints;
    this.context = builder.context;
    this.deployment = builder.deployment;
    this.shortTimeout =
        builder.shortTimeout != null ? builder.shortTimeout : deployment.shortTimeout();
    this.longTimeout = builder.longTimeout != null ? builder.longTimeout : deployment.longTimeout();
    this.transport = transport;
    this.pinPrompt = builder.pinPrompt;
    this.eventSink = builder.eventSink;
  }

  /** From a {@code .kon} file, deployment {@link Deployment#LOCAL}. */
  public static Konnektor fromKon(Path file) throws IOException {
    return builder().kon(KonConfig.read(file)).build();
  }

  /** Builder: programmatic counterpart of the {@code .kon}. */
  public static Builder builder() {
    return new Builder();
  }

  /** Base URL without trailing {@code /}. */
  public URI url() {
    return url;
  }

  /** Aufrufkontext of all operations. */
  public Context context() {
    return context;
  }

  /** Deployment the defaults come from. */
  public Deployment deployment() {
    return deployment;
  }

  /** Timeout of an operation according to its {@link Timing}. */
  public Duration timeout(Operation operation) {
    return operation.timing() == Timing.LONG ? longTimeout : shortTimeout;
  }

  /** The Dienstverzeichnis, read from {@code <url>/connector.sds} on first call. */
  public ServiceDirectory serviceDirectory() throws IOException {
    ServiceDirectory current = directory;
    if (current == null) {
      current = refresh();
    }
    return current;
  }

  /** Reads {@code <url>/connector.sds} again. */
  public synchronized ServiceDirectory refresh() throws IOException {
    URI sds = URI.create(url + "/connector.sds");
    Transport.Response response =
        transport.send(
            new Transport.Request(
                "GET", sds, Map.of("Accept", "application/xml"), new byte[0], shortTimeout));
    if (response.status() != 200) {
      throw new IOException("GET " + sds + ": HTTP " + response.status());
    }
    directory = ServiceDirectory.read(new ByteArrayInputStream(response.body()));
    return directory;
  }

  /**
   * Product information, product of the quirks table and offered services (LIANA-134). If the
   * product is not in the table, the client works from the Dienstverzeichnis alone and warns once.
   */
  public KonnektorInfo info() throws IOException {
    ServiceDirectory sds = serviceDirectory();
    return new KonnektorInfo(sds.product(), known(sds), sds.offered());
  }

  private Optional<QuirksTable.KnownProduct> known(ServiceDirectory sds) {
    if (!Product.AUTO.equals(product)) {
      return Optional.of(
          quirks
              .byId(product)
              .orElseThrow(
                  () ->
                      new IllegalArgumentException(
                          "Produkt " + product + " steht nicht in der Quirks-Tabelle")));
    }
    Optional<QuirksTable.KnownProduct> known = quirks.match(sds.product());
    if (known.isEmpty() && !warnedUnknown) {
      warnedUnknown = true;
      LOG.log(
          Level.WARNING,
          "Konnektor-Produkt {0}/{1} (FW {2}) nicht in der Quirks-Tabelle, nur nach "
              + "connector.sds",
          sds.product().vendorId(),
          sds.product().code(),
          sds.product().fwVersion());
    }
    return known;
  }

  /**
   * Whether the Konnektor offers the operation: a version with a binding in the Dienstverzeichnis
   * and no gap according to the quirks table. Operations that the product implements only up to the
   * access check count as offered ({@link QuirksTable.KnownProduct#gap}).
   */
  public boolean supports(Operation operation) throws IOException {
    return unsupported(operation).isEmpty();
  }

  private Optional<String> unsupported(Operation operation) throws IOException {
    ServiceDirectory sds = serviceDirectory();
    Optional<QuirksTable.KnownProduct> known = known(sds);
    Optional<QuirksTable.Gap> gap =
        known.flatMap(k -> k.gap(operation)).filter(g -> !g.accessCheckOnly());
    if (gap.isPresent()) {
      return Optional.of(
          operation.service().sdsName()
              + "."
              + operation.wsdlName()
              + ": von "
              + known.get().name()
              + " nicht umgesetzt ("
              + gap.get().source()
              + ")");
    }
    try {
      sds.select(operation);
      return Optional.empty();
    } catch (UnsupportedOperationException e) {
      return Optional.of(e.getMessage());
    }
  }

  /**
   * Endpoint of the selected service version: {@code EndpointTLS} for an {@code https} URL,
   * otherwise {@code Endpoint}; with {@code rewriteServiceEndpoints} only the path, appended to the
   * URL ({@code .kon} §5).
   */
  public URI endpoint(ServiceDirectory.Selection selection) {
    ServiceDirectory.Offer offer = selection.offer();
    URI advertised =
        "https".equals(url.getScheme())
            ? offer.endpointTls()
            : offer.endpoint().orElse(offer.endpointTls());
    if (!rewriteServiceEndpoints) {
      return advertised;
    }
    String path = advertised.getRawPath() == null ? "" : advertised.getRawPath();
    String query = advertised.getRawQuery() == null ? "" : "?" + advertised.getRawQuery();
    return URI.create(url + path + query);
  }

  /** Inserted cards (GetCards, LIANA-135). */
  public Cards cards() {
    return new Cards(this);
  }

  /** Operations on a card. */
  public CardScope card(Card card) {
    return new CardScope(this, card.handle());
  }

  /** Operations on a card via its CardHandle. */
  public CardScope card(String cardHandle) {
    return new CardScope(this, cardHandle);
  }

  /** Events via CETP (LIANA-137); the sink starts on first use, {@link #close()} stops it. */
  public synchronized Events events() {
    if (events == null) {
      events = new Events(this, eventSink);
    }
    return events;
  }

  /** Signature service without a card: GetJobNumber, StopSignature (LIANA-136). */
  public Signatures signatures() {
    return new Signatures(this);
  }

  /**
   * EncryptDocument for one document (LIANA-136): {@code encrypt(doc).to(cert)} or {@code
   * .toCard(handle)}.
   */
  public Encryption encrypt(Document document) {
    return new Encryption(this, document);
  }

  /** VerifyDocument and VerifyCertificate (LIANA-136). */
  public Verification verify() {
    return new Verification(this);
  }

  /** Card terminals (GetCardTerminals, RequestCard, EjectCard). */
  public Terminals terminals() {
    return new Terminals(this);
  }

  /**
   * The service version in which {@code operation} is called; checks the quirks table first.
   *
   * @throws UnsupportedOperationException like {@link #invoke(Operation, Object, Class)}
   */
  public ServiceDirectory.Selection select(Operation operation) {
    try {
      Optional<String> unsupported = unsupported(operation);
      if (unsupported.isPresent()) {
        throw new UnsupportedOperationException(unsupported.get());
      }
      return serviceDirectory().select(operation);
    } catch (IOException e) {
      throw new KonnektorException("connector.sds nicht lesbar: " + e.getMessage(), e);
    }
  }

  /**
   * Calls an operation in the highest matching service version (TIP1-A_4966).
   *
   * @param request JAXB request from the package of the selected binding ({@link
   *     Binding#javaPackage()})
   * @throws UnsupportedOperationException if the Konnektor offers the operation in no bound
   *     version, or the product does not implement it according to the quirks table (LIANA-134); no
   *     call is made
   * @throws SoapFaultException if the Konnektor responds with a SOAP fault
   * @throws KonnektorException on transport or format errors
   */
  public <T> T invoke(Operation operation, Object request, Class<T> responseType) {
    ServiceDirectory.Selection selection = select(operation);
    if (!request.getClass().getPackageName().equals(selection.binding().javaPackage())) {
      throw new IllegalArgumentException(
          operation.wsdlName()
              + ": Request aus "
              + request.getClass().getPackageName()
              + ", gewählt ist "
              + selection.binding()
              + " ("
              + selection.binding().javaPackage()
              + ")");
    }
    return invoke(selection, request, responseType);
  }

  /** Calls an operation in an already selected service version. */
  public <T> T invoke(ServiceDirectory.Selection selection, Object request, Class<T> responseType) {
    Operation operation = selection.operation();
    URI endpoint = endpoint(selection);
    if (operation.pinInput() && pinPrompt != null) {
      try {
        pinPrompt.onPinPrompt(
            new PinPromptHandler.PinPrompt(
                operation, property(request, "CardHandle"), property(request, "PinTyp")));
      } catch (Exception e) {
        throw new KonnektorException(
            operation.wsdlName() + ": PIN-Hook abgebrochen: " + e.getMessage(), e);
      }
    }
    Transport.Response response;
    try {
      response =
          transport.send(
              new Transport.Request(
                  "POST",
                  endpoint,
                  Map.of(
                      "Content-Type",
                      "text/xml; charset=UTF-8",
                      "SOAPAction",
                      "\"" + Soap.action(selection.binding(), operation) + "\""),
                  Soap.envelope(selection.binding(), request),
                  timeout(operation)));
    } catch (IOException e) {
      throw new KonnektorException(
          operation.wsdlName() + " an " + endpoint + ": " + e.getMessage(), e);
    }
    if (response.status() != 200 && response.status() != 500) {
      throw new KonnektorException(
          operation.wsdlName()
              + " an "
              + endpoint
              + ": HTTP "
              + response.status()
              + preview(response.body()));
    }
    Optional<QuirksTable.Gap> gap;
    try {
      gap = known(serviceDirectory()).flatMap(k -> k.gap(operation));
    } catch (IOException e) {
      gap = Optional.empty();
    }
    return Soap.response(selection.binding(), operation, response.body(), responseType, gap);
  }

  private static String property(Object request, String name) {
    try {
      Object value = Jaxb.get(request, name);
      return value instanceof String s ? s : null;
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  private static String preview(byte[] body) {
    if (body.length == 0) {
      return "";
    }
    String text = new String(body, 0, Math.min(body.length, 200), StandardCharsets.UTF_8).strip();
    return ": " + text;
  }

  @Override
  public void close() {
    Events current;
    synchronized (this) {
      current = events;
    }
    if (current != null) {
      current.close();
    }
    try {
      transport.close();
    } catch (Exception e) {
      // nothing to do
    }
  }

  /** Programmatic counterpart of the {@code .kon}. */
  public static final class Builder {

    private URI url;
    private boolean rewriteServiceEndpoints;
    private Context context;
    private Credentials credentials = Credentials.none();
    private Trust trust = Trust.system();
    private Deployment deployment = Deployment.LOCAL;
    private Duration shortTimeout;
    private Duration longTimeout;
    private Duration connectTimeout = Duration.ofSeconds(10);
    private InetSocketAddress proxy;
    private Transport transport;
    private String product = Product.AUTO;
    private PinPromptHandler pinPrompt;
    private EventSink eventSink = EventSink.plain("127.0.0.1", 0);
    private QuirksTable quirks = QuirksTable.standard();

    private Builder() {}

    /** Takes over all settings of a {@code .kon}. */
    public Builder kon(KonConfig kon) {
      url(kon.url());
      rewriteServiceEndpoints = kon.rewriteServiceEndpoints();
      context = kon.context();
      credentials = kon.credentials();
      trust = kon.trust();
      return this;
    }

    /** Base URL, also for {@code <url>/connector.sds}; a trailing {@code /} is removed. */
    @SuppressWarnings("java:S5852") // trailing slashes of a configured URL
    public Builder url(URI url) {
      this.url = URI.create(Objects.requireNonNull(url, "url").toString().replaceAll("/+$", ""));
      return this;
    }

    /** Like {@link #url(URI)}. */
    public Builder url(String url) {
      return url(URI.create(url));
    }

    /**
     * Rebuild the endpoints from the Dienstverzeichnis against the URL (reverse proxy, NAT,
     * Docker).
     */
    public Builder rewriteServiceEndpoints(boolean rewrite) {
      this.rewriteServiceEndpoints = rewrite;
      return this;
    }

    /** Aufrufkontext; {@code userId} only for HBA operations, otherwise {@code null}. */
    public Builder context(
        String mandantId, String clientSystemId, String workplaceId, String userId) {
      this.context = new Context(mandantId, clientSystemId, workplaceId, userId);
      return this;
    }

    /** Aufrufkontext. */
    public Builder context(Context context) {
      this.context = context;
      return this;
    }

    /**
     * Authentication: {@link Credentials#none()}, {@link Credentials#basic}, {@link
     * Credentials#pkcs12}.
     */
    public Builder auth(Credentials credentials) {
      this.credentials = Objects.requireNonNull(credentials, "credentials");
      return this;
    }

    /** Verification of the Konnektor certificate: pins or CAs, expected hostname. */
    public Builder trust(Trust trust) {
      this.trust = Objects.requireNonNull(trust, "trust");
      return this;
    }

    /** Overrides the deployment's timeouts. */
    public Builder timeouts(Duration shortTimeout, Duration longTimeout) {
      this.shortTimeout = shortTimeout;
      this.longTimeout = longTimeout;
      return this;
    }

    /** Timeout for establishing the connection, 10 s by default. */
    public Builder connectTimeout(Duration timeout) {
      this.connectTimeout = timeout;
      return this;
    }

    /** Defaults for timeouts and PIN hook. */
    public Builder deployment(Deployment deployment) {
      this.deployment = Objects.requireNonNull(deployment, "deployment");
      return this;
    }

    /** HTTP proxy, such as a Tiger proxy that records the traffic. */
    public Builder proxy(String host, int port) {
      this.proxy = InetSocketAddress.createUnresolved(host, port);
      return this;
    }

    /**
     * Product of the quirks table ({@link QuirksTable.KnownProduct#id()}), {@link Product#AUTO} by
     * default: from {@code ProductVendorID} and {@code ProductCode} in the Dienstverzeichnis.
     */
    public Builder product(String id) {
      this.product = Objects.requireNonNull(id, "product");
      return this;
    }

    /** Hook before every PIN entry (LIANA-137); mandatory for {@link Deployment#KSP}. */
    public Builder onPinPrompt(PinPromptHandler handler) {
      this.pinPrompt = Objects.requireNonNull(handler, "handler");
      return this;
    }

    /**
     * Ereignissenke for {@link Konnektor#events()}; by default without TLS on 127.0.0.1, any free
     * port.
     */
    public Builder eventSink(EventSink sink) {
      this.eventSink = Objects.requireNonNull(sink, "sink");
      return this;
    }

    /** Custom quirks table instead of the one from {@code liana-contract}, e.g. for tests. */
    public Builder quirks(QuirksTable table) {
      this.quirks = Objects.requireNonNull(table, "quirks");
      return this;
    }

    /**
     * Custom transport instead of {@link HttpTransport}; authentication, trust and proxy then do
     * not apply.
     */
    public Builder transport(Transport transport) {
      this.transport = transport;
      return this;
    }

    /** Builds the connection; reads {@code connector.sds} only when first needed. */
    public Konnektor build() throws IOException {
      Objects.requireNonNull(url, "url");
      Objects.requireNonNull(context, "context");
      if (deployment.pinHookRequired() && pinPrompt == null) {
        throw new IllegalStateException(
            "Deployment "
                + deployment
                + ": PIN-Eingaben brauchen einen Hook, "
                + "Builder.onPinPrompt(…) fehlt (LIANA-137)");
      }
      Transport chosen =
          transport != null
              ? transport
              : HttpTransport.create(trust, credentials, proxy, connectTimeout);
      return new Konnektor(this, chosen);
    }
  }
}
