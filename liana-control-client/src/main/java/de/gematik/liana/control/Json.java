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
package de.gematik.liana.control;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal JSON reader and writer (RFC 8259) for the Admin API: objects as {@link Map}, arrays as
 * {@link List}, numbers as {@link Double}, plus {@link String}, {@link Boolean} and {@code null}.
 * Custom code instead of a library, so that the control client does not cause version conflicts in
 * test suites (decision-016); a copy of the reader from {@code konnektor-client}, because the two
 * clients must not depend on each other (LIANA-130).
 */
final class Json {

  private final String text;
  private int pos;

  private Json(String text) {
    this.text = text;
  }

  /** Writes maps, lists, strings, numbers, booleans and {@code null} as JSON. */
  static String write(Object value) {
    StringBuilder out = new StringBuilder();
    write(value, out);
    return out.toString();
  }

  private static void write(Object value, StringBuilder out) {
    if (value == null) {
      out.append("null");
    } else if (value instanceof String s) {
      out.append('"');
      for (char c : s.toCharArray()) {
        switch (c) {
          case '"' -> out.append("\\\"");
          case '\\' -> out.append("\\\\");
          case '\n' -> out.append("\\n");
          case '\r' -> out.append("\\r");
          case '\t' -> out.append("\\t");
          default -> {
            if (c < 0x20) {
              out.append(String.format("\\u%04x", (int) c));
            } else {
              out.append(c);
            }
          }
        }
      }
      out.append('"');
    } else if (value instanceof Number || value instanceof Boolean) {
      out.append(value);
    } else if (value instanceof Map<?, ?> map) {
      out.append('{');
      boolean first = true;
      for (Map.Entry<?, ?> e : map.entrySet()) {
        if (!first) {
          out.append(',');
        }
        first = false;
        write(String.valueOf(e.getKey()), out);
        out.append(':');
        write(e.getValue(), out);
      }
      out.append('}');
    } else if (value instanceof List<?> list) {
      out.append('[');
      for (int i = 0; i < list.size(); i++) {
        if (i > 0) {
          out.append(',');
        }
        write(list.get(i), out);
      }
      out.append(']');
    } else {
      throw new IllegalArgumentException(
          "nicht als JSON schreibbar: " + value.getClass().getName());
    }
  }

  static Object parse(String text) {
    Json json = new Json(text);
    json.skipWhitespace();
    Object value = json.value();
    json.skipWhitespace();
    if (json.pos != text.length()) {
      throw json.error("Zeichen nach dem Ende des Dokuments");
    }
    return value;
  }

  private Object value() {
    if (pos >= text.length()) {
      throw error("unerwartetes Ende");
    }
    char c = text.charAt(pos);
    return switch (c) {
      case '{' -> object();
      case '[' -> array();
      case '"' -> string();
      case 't' -> literal("true", Boolean.TRUE);
      case 'f' -> literal("false", Boolean.FALSE);
      case 'n' -> literal("null", null);
      default -> {
        if (c == '-' || (c >= '0' && c <= '9')) {
          yield number();
        }
        throw error("unerwartetes Zeichen");
      }
    };
  }

  private Map<String, Object> object() {
    Map<String, Object> map = new LinkedHashMap<>();
    pos++;
    skipWhitespace();
    if (peek() == '}') {
      pos++;
      return map;
    }
    while (true) {
      skipWhitespace();
      if (peek() != '"') {
        throw error("Schlüssel erwartet");
      }
      String key = string();
      skipWhitespace();
      expect(':');
      skipWhitespace();
      if (map.put(key, value()) != null) {
        throw error("Schlüssel doppelt: " + key);
      }
      skipWhitespace();
      if (peek() == ',') {
        pos++;
      } else {
        expect('}');
        return map;
      }
    }
  }

  private List<Object> array() {
    List<Object> list = new ArrayList<>();
    pos++;
    skipWhitespace();
    if (peek() == ']') {
      pos++;
      return list;
    }
    while (true) {
      skipWhitespace();
      list.add(value());
      skipWhitespace();
      if (peek() == ',') {
        pos++;
      } else {
        expect(']');
        return list;
      }
    }
  }

  private String string() {
    pos++;
    StringBuilder out = new StringBuilder();
    while (true) {
      if (pos >= text.length()) {
        throw error("Zeichenkette nicht beendet");
      }
      char c = text.charAt(pos++);
      if (c == '"') {
        return out.toString();
      }
      if (c < 0x20) {
        throw error("Steuerzeichen in Zeichenkette");
      }
      if (c != '\\') {
        out.append(c);
        continue;
      }
      if (pos >= text.length()) {
        throw error("Zeichenkette nicht beendet");
      }
      char e = text.charAt(pos++);
      switch (e) {
        case '"', '\\', '/' -> out.append(e);
        case 'b' -> out.append('\b');
        case 'f' -> out.append('\f');
        case 'n' -> out.append('\n');
        case 'r' -> out.append('\r');
        case 't' -> out.append('\t');
        case 'u' -> {
          if (pos + 4 > text.length()) {
            throw error("\\u unvollständig");
          }
          try {
            out.append((char) Integer.parseInt(text.substring(pos, pos + 4), 16));
          } catch (NumberFormatException ex) {
            throw error("\\u ungültig");
          }
          pos += 4;
        }
        default -> throw error("ungültige Escape-Sequenz");
      }
    }
  }

  private Double number() {
    int start = pos;
    if (peek() == '-') {
      pos++;
    }
    while (pos < text.length() && "0123456789.eE+-".indexOf(text.charAt(pos)) >= 0) {
      pos++;
    }
    try {
      return Double.valueOf(text.substring(start, pos));
    } catch (NumberFormatException e) {
      throw error("ungültige Zahl");
    }
  }

  private Object literal(String word, Object value) {
    if (!text.startsWith(word, pos)) {
      throw error("unerwartetes Zeichen");
    }
    pos += word.length();
    return value;
  }

  private void expect(char c) {
    if (peek() != c) {
      throw error("'" + c + "' erwartet");
    }
    pos++;
  }

  private char peek() {
    return pos < text.length() ? text.charAt(pos) : '\0';
  }

  private void skipWhitespace() {
    while (pos < text.length() && " \t\r\n".indexOf(text.charAt(pos)) >= 0) {
      pos++;
    }
  }

  private IllegalArgumentException error(String reason) {
    int line = 1;
    int column = 1;
    for (int i = 0; i < Math.min(pos, text.length()); i++) {
      if (text.charAt(i) == '\n') {
        line++;
        column = 1;
      } else {
        column++;
      }
    }
    return new IllegalArgumentException(
        "kein gültiges JSON (Zeile " + line + ", Spalte " + column + "): " + reason);
  }
}
