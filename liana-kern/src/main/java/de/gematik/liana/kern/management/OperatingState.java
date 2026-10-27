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
package de.gematik.liana.kern.management;

import de.gematik.liana.kern.event.SystemLog;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Betriebszustand of the connector (TIP1-A_4509, chapter 3.4) for GetResourceInformation
 * (TUC_KON_254, LIANA-187): status of the VPN connections to the TI and to the SIS, reachability of
 * the transport network and the error state list TAB_KON_503.
 *
 * <p>LIANA establishes no VPN connections; the three connection states come from the YAML and the
 * Admin API. From them and from MGM_LU_ONLINE follow EC_No_VPN_TI_Connection (A_17085),
 * EC_No_Online_Connection (A_17087) and EC_No_VPN_SIS_Connection (A_17086, only with
 * ANLW_INTERNET_MODUS=SIS, which LIANA does not know: always false). The other error states without
 * parameters have no source in LIANA and are false. If a value changes, TUC_KON_256 reports {@code
 * OPERATIONAL_STATE/$EC} (TIP1-A_4512-06). Changes are volatile, {@link #reset()} restores the boot
 * state (decision-4).
 */
public final class OperatingState {

  /** Status of a connection with the time of the last change (VPNTIStatus, VPNSISStatus). */
  public record Connection(boolean online, Instant timestamp) {}

  /** A row of the error state list (TAB_KON_503) with value and time of the last change. */
  public record ErrorState(
      String condition,
      SystemLog.Severity severity,
      SystemLog.Type type,
      boolean value,
      Instant validFrom) {}

  /** The connection states from which the derived error states follow. */
  public record Connections(boolean vpnTi, boolean vpnSis, boolean transport) {}

  /** Topic of TUC_KON_256 for the change of an error state (TIP1-A_4512-06). */
  public static final String TOPIC_PREFIX = "OPERATIONAL_STATE/";

  static final String NO_VPN_TI = "EC_No_VPN_TI_Connection";
  static final String NO_VPN_SIS = "EC_No_VPN_SIS_Connection";
  static final String NO_ONLINE = "EC_No_Online_Connection";

  private record Condition(
      String name, SystemLog.Severity severity, SystemLog.Type type, String description) {}

  /**
   * TAB_KON_503 without parameters; type and severity as there (and as for the reference connector
   * in the PS lab).
   */
  private static final List<Condition> CONDITIONS =
      List.of(
          op(
              NO_VPN_TI,
              SystemLog.Severity.ERR,
              "Kein sicherer Kanal (VPN) in die Telematikinfrastruktur aufgebaut."),
          op(
              NO_VPN_SIS,
              SystemLog.Severity.ERR,
              "Kein sicherer Kanal (VPN) zu den Sicheren Internet Services aufgebaut."),
          op(
              NO_ONLINE,
              SystemLog.Severity.ERR,
              "Konnektor kann Dienste im Transportnetz nicht erreichen."),
          op("EC_Connector_Software_Out_Of_Date", SystemLog.Severity.INFO, null),
          op("EC_FW_Update_Available", SystemLog.Severity.INFO, null),
          sec("EC_FW_Not_Valid_Status_Blocked", SystemLog.Severity.FATAL),
          op("EC_Time_Sync_Not_Successful", SystemLog.Severity.INFO, null),
          op("EC_TSL_Update_Not_Successful", SystemLog.Severity.INFO, null),
          sec("EC_TSL_Expiring", SystemLog.Severity.INFO),
          op("EC_BNetzA_VL_Update_Not_Successful", SystemLog.Severity.INFO, null),
          sec("EC_BNetzA_VL_not_valid", SystemLog.Severity.WARN),
          sec("EC_TSL_Trust_Anchor_Expiring", SystemLog.Severity.INFO),
          sec("EC_TSL_Trust_Anchor_Out_Of_Date", SystemLog.Severity.FATAL),
          op("EC_LOG_OVERFLOW", SystemLog.Severity.WARN, null),
          sec("EC_CRL_Expiring", SystemLog.Severity.WARN),
          sec("EC_TSL_Out_Of_Date_Within_Grace_Period", SystemLog.Severity.WARN),
          sec("EC_TSL_Out_Of_Date_Beyond_Grace_Period", SystemLog.Severity.FATAL),
          sec("EC_IP_Adresses_Not_Available", SystemLog.Severity.ERR),
          sec("EC_CRL_Out_Of_Date", SystemLog.Severity.FATAL),
          sec("EC_Firewall_Not_Reliable", SystemLog.Severity.FATAL),
          sec("EC_Random_Generator_Not_Reliable", SystemLog.Severity.FATAL),
          sec("EC_Secure_KeyStore_Not_Available", SystemLog.Severity.FATAL),
          op("EC_Security_Log_Not_Writable", SystemLog.Severity.FATAL, null),
          sec("EC_Software_Integrity_Check_Failed", SystemLog.Severity.FATAL),
          sec("EC_Time_Difference_Intolerable", SystemLog.Severity.FATAL),
          sec("EC_Time_Sync_Pending_Warning", SystemLog.Severity.WARN),
          sec("EC_Time_Sync_Pending_Critical", SystemLog.Severity.FATAL),
          sec("EC_CRYPTOPERATION_ALARM", SystemLog.Severity.WARN),
          sec("EC_NK_Certificate_Expiring", SystemLog.Severity.WARN),
          sec("EC_NK_Certificate_Expired", SystemLog.Severity.FATAL),
          sec("EC_TLS_Client_Certificate_Security", SystemLog.Severity.INFO));

  private final Clock clock;
  private final SystemLog systemLog;
  private final ManagementSettings settings;
  private final Connections boot;
  private Connection vpnTi;
  private Connection vpnSis;
  private Connection transport;
  private final Map<String, ErrorState> states = new LinkedHashMap<>();

  /** {@code boot}: connection states from the YAML; registers for changes of MGM_LU_ONLINE. */
  public OperatingState(
      Connections boot, ManagementSettings settings, SystemLog systemLog, Clock clock) {
    this.clock = clock;
    this.systemLog = systemLog;
    this.settings = settings;
    this.boot = boot;
    settings.addOnlineListener(() -> evaluate(true));
    reset();
  }

  /** Restores the connection states of the YAML, all timestamps to now, without event. */
  public synchronized void reset() {
    Instant now = clock.instant();
    vpnTi = new Connection(boot.vpnTi(), now);
    vpnSis = new Connection(boot.vpnSis(), now);
    transport = new Connection(boot.transport(), now);
    states.clear();
    evaluate(false);
  }

  public synchronized Connection vpnTi() {
    return vpnTi;
  }

  public synchronized Connection vpnSis() {
    return vpnSis;
  }

  /**
   * Reachability of the services in the transport network (opposite of EC_No_Online_Connection with
   * MGM_LU_ONLINE).
   */
  public synchronized Connection transport() {
    return transport;
  }

  /**
   * Sets the connection states; {@code null} leaves a value unchanged. Changed error states are
   * reported by TUC_KON_256.
   */
  public synchronized void set(Boolean vpnTiOnline, Boolean vpnSisOnline, Boolean transportOnline) {
    vpnTi = change(vpnTi, vpnTiOnline);
    vpnSis = change(vpnSis, vpnSisOnline);
    transport = change(transport, transportOnline);
    evaluate(true);
  }

  /** The error state list in the order of TAB_KON_503. */
  public synchronized List<ErrorState> errorStates() {
    return new ArrayList<>(states.values());
  }

  private Connection change(Connection current, Boolean online) {
    return online == null || online == current.online()
        ? current
        : new Connection(online, clock.instant());
  }

  private synchronized void evaluate(boolean report) {
    boolean lu = settings.online();
    Instant now = clock.instant();
    for (Condition condition : CONDITIONS) {
      boolean value =
          switch (condition.name()) {
            case NO_VPN_TI -> lu && !vpnTi.online();
            case NO_ONLINE -> lu && !transport.online();
            default -> false;
          };
      ErrorState previous = states.get(condition.name());
      if (previous != null && previous.value() == value) {
        continue;
      }
      states.put(
          condition.name(),
          new ErrorState(condition.name(), condition.severity(), condition.type(), value, now));
      if (report && previous != null) {
        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put("Value", Boolean.toString(value));
        if (condition.description() != null) {
          parameters.put("Bedeutung", condition.description());
        }
        systemLog.write(
            condition.type(), condition.severity(), TOPIC_PREFIX + condition.name(), parameters);
      }
    }
  }

  private static Condition op(String name, SystemLog.Severity severity, String description) {
    return new Condition(name, severity, SystemLog.Type.OP, description);
  }

  private static Condition sec(String name, SystemLog.Severity severity) {
    return new Condition(name, severity, SystemLog.Type.SEC, null);
  }
}
