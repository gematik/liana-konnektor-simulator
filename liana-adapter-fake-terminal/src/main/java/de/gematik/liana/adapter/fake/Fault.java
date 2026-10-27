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
package de.gematik.liana.adapter.fake;

import java.time.Duration;
import java.util.HexFormat;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * A fault at a slot of the fake KT, set via the Admin API (LIANA-41, decision-4: volatile). The
 * format is the template for the faults in {@code kartos terminal} from phase 2 on (decision-11):
 *
 * <ul>
 *   <li>{@link Type#STATUS_WORD}: the card responds only with {@code statusWord}, the command does
 *       not reach it;
 *   <li>{@link Type#RESPONSE}: like status-word, but with the whole response {@code response} (data
 *       and status word), e.g. a replaced signature (CATS {@code manipulateSignatureResponse},
 *       LIANA-67);
 *   <li>{@link Type#IO_ERROR}: communication error with the card terminal (TUC_KON_200: 4044), also
 *       on reset;
 *   <li>{@link Type#DELAY}: the card responds only after {@code delay}, also on reset; via
 *       CARD_TIMEOUT_CARD the Konnektor aborts (TUC_KON_200: 4094).
 * </ul>
 *
 * <p>{@code commandPrefix} (hex, optional) restricts the fault to command APDUs with this prefix;
 * the reset has no command and is then not affected. {@code count} (optional) counts the affected
 * calls, after which the fault is consumed; without {@code count} it applies until it is cleared.
 */
public record Fault(
    Type type,
    String statusWord,
    String response,
    Duration delay,
    String commandPrefix,
    Integer count) {

  public enum Type {
    STATUS_WORD("status-word"),
    RESPONSE("response"),
    IO_ERROR("io-error"),
    DELAY("delay");

    private final String value;

    Type(String value) {
      this.value = value;
    }

    public String value() {
      return value;
    }

    public static Type of(String value) {
      for (Type type : values()) {
        if (type.value.equals(value)) {
          return type;
        }
      }
      throw new IllegalArgumentException(
          "Störung '"
              + value
              + "' unbekannt, erwartet status-word, response, io-error oder "
              + "delay");
    }
  }

  private static final Pattern STATUS_WORD = Pattern.compile("[0-9A-F]{4}");
  private static final Pattern RESPONSE_APDU = Pattern.compile("([0-9A-F]{2}){2,}");
  private static final Pattern PREFIX = Pattern.compile("([0-9A-F]{2})+");
  private static final HexFormat HEX = HexFormat.of().withUpperCase();

  public Fault {
    if (type == null) {
      throw new IllegalArgumentException("Störung ohne type");
    }
    statusWord = upper(statusWord);
    response = upper(response);
    commandPrefix = upper(commandPrefix);
    if ((type == Type.STATUS_WORD) != (statusWord != null)) {
      throw new IllegalArgumentException("statusWord gehört genau zu type status-word");
    }
    if (statusWord != null && !STATUS_WORD.matcher(statusWord).matches()) {
      throw new IllegalArgumentException("statusWord '" + statusWord + "' ist nicht 4-stellig hex");
    }
    if ((type == Type.RESPONSE) != (response != null)) {
      throw new IllegalArgumentException("response gehört genau zu type response");
    }
    if (response != null && !RESPONSE_APDU.matcher(response).matches()) {
      throw new IllegalArgumentException(
          "response '" + response + "' ist keine Antwort-APDU (Hex, mindestens SW1 SW2)");
    }
    if ((type == Type.DELAY) != (delay != null)) {
      throw new IllegalArgumentException("delay gehört genau zu type delay");
    }
    if (delay != null && (delay.isNegative() || delay.isZero())) {
      throw new IllegalArgumentException("delay muss positiv sein");
    }
    if (commandPrefix != null && !PREFIX.matcher(commandPrefix).matches()) {
      throw new IllegalArgumentException(
          "commandPrefix '" + commandPrefix + "' ist kein Hex-Bytestring");
    }
    if (count != null && count < 1) {
      throw new IllegalArgumentException("count muss mindestens 1 sein");
    }
  }

  public static Fault statusWord(String statusWord) {
    return new Fault(Type.STATUS_WORD, statusWord, null, null, null, null);
  }

  /** The card responds with {@code response} (hex, data and status word). */
  public static Fault response(String response) {
    return new Fault(Type.RESPONSE, null, response, null, null, null);
  }

  public static Fault ioError() {
    return new Fault(Type.IO_ERROR, null, null, null, null, null);
  }

  public static Fault delay(Duration delay) {
    return new Fault(Type.DELAY, null, null, delay, null, null);
  }

  /** Only for command APDUs that start with {@code prefix} (hex). */
  public Fault onlyFor(String prefix) {
    return new Fault(type, statusWord, response, delay, prefix, count);
  }

  /** Only for the next {@code n} affected calls. */
  public Fault times(int n) {
    return new Fault(type, statusWord, response, delay, commandPrefix, n);
  }

  /** Whether the fault hits the command APDU {@code command}; {@code null} stands for the reset. */
  boolean matches(byte[] command) {
    if (command == null) {
      return commandPrefix == null && type != Type.STATUS_WORD && type != Type.RESPONSE;
    }
    return commandPrefix == null || HEX.formatHex(command).startsWith(commandPrefix);
  }

  /** The fault after an affected call; {@code null} if it is consumed. */
  Fault consumed() {
    if (count == null) {
      return this;
    }
    return count == 1 ? null : times(count - 1);
  }

  private static String upper(String value) {
    return value == null ? null : value.toUpperCase(Locale.ROOT);
  }
}
