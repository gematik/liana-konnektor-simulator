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
package de.gematik.liana.adapter.sicct;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;
import java.util.function.Predicate;

/**
 * UDP side of service discovery (SICCT 1.2.3 §6.2.3, gemSpec_Kon TIP1-A_4540): a socket on
 * CTM_SERVICE_ANNOUNCEMENT_PORT (default 4742) receives service descriptions, both unsolicited
 * (service announcement) and in response to a service enquiry; service enquiries go from the same
 * socket to the CTM_SERVICE_DISCOVERY_PORT of a card terminal or via broadcast.
 */
public final class DiscoveryChannel implements AutoCloseable {

  private static final System.Logger LOG = System.getLogger(DiscoveryChannel.class.getName());
  private static final int MAX_PACKET = 1500;

  private final DatagramSocket socket;
  private final Consumer<ServiceDiscovery.Announcement> announcements;
  private final List<Waiter> waiting = new CopyOnWriteArrayList<>();
  private final Thread receiver;

  private record Waiter(
      Predicate<ServiceDiscovery.Announcement> match,
      CompletableFuture<ServiceDiscovery.Announcement> result) {}

  /**
   * @param bind address and port for incoming service descriptions (port 0: chosen freely, for
   *     tests)
   * @param announcements receives every valid service description (TIP1-A_4540)
   */
  public DiscoveryChannel(
      InetSocketAddress bind, Consumer<ServiceDiscovery.Announcement> announcements)
      throws SocketException {
    this.socket = new DatagramSocket(null);
    socket.setReuseAddress(true);
    socket.setBroadcast(true);
    socket.bind(bind);
    this.announcements = announcements;
    this.receiver = new Thread(this::receive, "liana-sicct-discovery");
    receiver.setDaemon(true);
    receiver.start();
  }

  /** The bound UDP port (CTM_SERVICE_ANNOUNCEMENT_PORT). */
  public int port() {
    return socket.getLocalPort();
  }

  /**
   * Sends a service enquiry to {@code target}:{@code port} (unicast to a card terminal or a
   * broadcast address); the responses arrive at this channel.
   */
  public void enquire(InetAddress target, int port) throws IOException {
    byte[] packet = ServiceDiscovery.enquiry(localAddressTowards(target), port());
    socket.send(new DatagramPacket(packet, packet.length, target, port));
  }

  /**
   * Service enquiry to {@code target}:{@code port} and the first matching service description
   * within {@code timeout} (CTM_SERVICE_DISCOVERY_TIMEOUT); empty if none arrives (TUC_KON_054:
   * 4033).
   */
  public Optional<ServiceDiscovery.Announcement> discover(
      InetAddress target, int port, Duration timeout) throws IOException {
    Waiter waiter =
        new Waiter(
            a -> a.ip().equals(target) || target.isLoopbackAddress() && a.ip().isLoopbackAddress(),
            new CompletableFuture<>());
    waiting.add(waiter);
    try {
      enquire(target, port);
      return Optional.of(waiter.result().get(timeout.toMillis(), TimeUnit.MILLISECONDS));
    } catch (TimeoutException e) {
      return Optional.empty();
    } catch (ExecutionException e) {
      throw new IOException(e.getCause());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new java.io.InterruptedIOException("Dienstsuche unterbrochen");
    } finally {
      waiting.remove(waiter);
    }
  }

  /**
   * The own address through which {@code target} is reachable (client IP of the service enquiry).
   */
  private static InetAddress localAddressTowards(InetAddress target) throws SocketException {
    if (target.isLoopbackAddress()) {
      return target;
    }
    try (DatagramSocket probe = new DatagramSocket()) {
      probe.connect(target, 9);
      return probe.getLocalAddress();
    }
  }

  private void receive() {
    byte[] buffer = new byte[MAX_PACKET];
    while (!socket.isClosed()) {
      DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
      try {
        socket.receive(packet);
      } catch (IOException e) {
        if (!socket.isClosed()) {
          LOG.log(System.Logger.Level.WARNING, "Dienstsuche: Empfang gestört: " + e.getMessage());
        }
        continue;
      }
      byte[] data = Arrays.copyOf(packet.getData(), packet.getLength());
      ServiceDiscovery.Announcement announcement;
      try {
        announcement = ServiceDiscovery.announcement(data);
      } catch (IOException e) {
        // Own service enquiries (broadcast) and foreign packets: no card terminal, no reaction
        LOG.log(
            System.Logger.Level.DEBUG,
            "Dienstsuche: kein Dienstbeschreibungspaket von "
                + packet.getSocketAddress()
                + ": "
                + e.getMessage());
        continue;
      }
      // The response to an own service enquiry (TUC_KON_054 step 1) belongs to that enquiry and is
      // not an
      // unsolicited announcement (TIP1-A_4540).
      boolean answered = false;
      for (Waiter waiter : waiting) {
        if (waiter.match().test(announcement) && waiter.result().complete(announcement)) {
          answered = true;
        }
      }
      if (answered) {
        continue;
      }
      try {
        announcements.accept(announcement);
      } catch (RuntimeException e) {
        LOG.log(
            System.Logger.Level.WARNING,
            "Dienstbeschreibung " + announcement + " nicht verarbeitet",
            e);
      }
    }
  }

  @Override
  public void close() {
    socket.close();
  }
}
