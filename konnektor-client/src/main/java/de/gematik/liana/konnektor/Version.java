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

/**
 * Three-part version of a Konnektor interface: major, minor and revision number (gemILF_PS 4.1.3,
 * re TIP1-A_4966).
 */
public record Version(int major, int minor, int revision) implements Comparable<Version> {

  /** {@code 8.2.1}; a missing revision counts as 0. */
  public static Version parse(String text) {
    String[] parts = text.trim().split("\\.");
    if (parts.length < 2 || parts.length > 3) {
      throw new IllegalArgumentException("Keine Dienstversion: " + text);
    }
    try {
      return new Version(
          Integer.parseInt(parts[0]),
          Integer.parseInt(parts[1]),
          parts.length == 3 ? Integer.parseInt(parts[2]) : 0);
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("Keine Dienstversion: " + text, e);
    }
  }

  /** TIP1-A_4966: major and minor version match, the revision may differ. */
  public boolean compatibleWith(int otherMajor, int otherMinor) {
    return major == otherMajor && minor == otherMinor;
  }

  @Override
  public int compareTo(Version other) {
    int c = Integer.compare(major, other.major);
    if (c == 0) {
      c = Integer.compare(minor, other.minor);
    }
    return c != 0 ? c : Integer.compare(revision, other.revision);
  }

  @Override
  public String toString() {
    return major + "." + minor + "." + revision;
  }
}
