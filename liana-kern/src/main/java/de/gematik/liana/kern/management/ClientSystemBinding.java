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

/**
 * Connection of the Clientsysteme (TAB_KON_506-01, TIP1-A_4518-02) as the KMS sets it (LIANA-65):
 * ANCL_TLS_MANDATORY, ANCL_CAUT_MANDATORY with ANCL_CAUT_MODE, ANCL_DVD_OPEN, plus the choice of
 * the TLS server identity: ECC or RSA identity (TLS_USE_ECC_FOR_CS, EHEX KMS) and the generated or
 * imported server certificate instead of ID.AK.AUT (TIP1-A_4514-01, A_21697-01). The values apply
 * to every new connection; changes are volatile, {@link #reset()} restores the boot state
 * (decision-4).
 */
public final class ClientSystemBinding {

  /**
   * ANCL_CAUT_MANDATORY and ANCL_CAUT_MODE in one value, like {@code authenticationMode} in the
   * EHEX KMS.
   */
  public enum Authentication {
    /** ANCL_CAUT_MANDATORY Disabled. */
    NONE,
    /**
     * ANCL_CAUT_MANDATORY Enabled, ANCL_CAUT_MODE CERTIFICATE: TLS client certificate from
     * ANCL_CCERT_LIST.
     */
    CERTIFICATE,
    /** ANCL_CAUT_MANDATORY Enabled, ANCL_CAUT_MODE PASSWORD: Basic Auth against ANCL_CUP_LIST. */
    PASSWORD
  }

  /** Boot state or snapshot. */
  public record State(
      boolean tlsMandatory,
      Authentication authentication,
      boolean dvdOpen,
      boolean eccForClientSystems,
      boolean serverSoftwareKey) {

    public State withTlsMandatory(boolean value) {
      return new State(value, authentication, dvdOpen, eccForClientSystems, serverSoftwareKey);
    }

    public State withAuthentication(Authentication value) {
      return new State(tlsMandatory, value, dvdOpen, eccForClientSystems, serverSoftwareKey);
    }

    public State withDvdOpen(boolean value) {
      return new State(tlsMandatory, authentication, value, eccForClientSystems, serverSoftwareKey);
    }

    public State withEccForClientSystems(boolean value) {
      return new State(tlsMandatory, authentication, dvdOpen, value, serverSoftwareKey);
    }

    public State withServerSoftwareKey(boolean value) {
      return new State(tlsMandatory, authentication, dvdOpen, eccForClientSystems, value);
    }

    /**
     * TIP1-A_4515: may a call without TLS reach {@code serviceDirectory} (connector.sds) or other
     * services?
     */
    public boolean allowsPlainHttp(boolean serviceDirectory) {
      return !tlsMandatory || serviceDirectory && dvdOpen;
    }
  }

  private final State boot;
  private volatile State state;

  public ClientSystemBinding(State boot) {
    this.boot = boot;
    this.state = boot;
  }

  public State state() {
    return state;
  }

  /** Sets all values at once, the way the KMS writes a settings group. */
  public void state(State state) {
    this.state = state;
  }

  /** Restores the boot state from the YAML. */
  public void reset() {
    state = boot;
  }
}
