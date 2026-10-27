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

import de.gematik.liana.konnektor.ws.conn.connectorcontext.v2_0.ContextType;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * Requests and responses per selected binding (LIANA-135): the classes of operations with the same
 * name are built identically in every minor version (e.g. CardService 8.1 and 8.2), but live in
 * separate packages. The domain API therefore builds them via class names and setters of the
 * selected package.
 */
final class Jaxb {

  private Jaxb() {}

  static Object request(Binding binding, String simpleName) {
    try {
      return Class.forName(
              binding.javaPackage() + "." + simpleName, true, Jaxb.class.getClassLoader())
          .getConstructor()
          .newInstance();
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(binding + ": keine Klasse " + simpleName, e);
    }
  }

  static Class<?> type(Binding binding, String simpleName) {
    try {
      return Class.forName(
          binding.javaPackage() + "." + simpleName, true, Jaxb.class.getClassLoader());
    } catch (ClassNotFoundException e) {
      throw new IllegalStateException(binding + ": keine Klasse " + simpleName, e);
    }
  }

  /** Sets {@code set<property>} with the matching parameter type. */
  static Object set(Object target, String property, Object value) {
    for (Method method : target.getClass().getMethods()) {
      if (method.getName().equals("set" + property)
          && method.getParameterCount() == 1
          && (value == null || box(method.getParameterTypes()[0]).isInstance(value))) {
        try {
          method.invoke(target, value);
          return target;
        } catch (IllegalAccessException | InvocationTargetException e) {
          throw new IllegalStateException(target.getClass().getSimpleName() + ".set" + property, e);
        }
      }
    }
    throw new IllegalArgumentException(target.getClass().getName() + ": kein set" + property);
  }

  /** Reads {@code get<property>} or {@code is<property>}. */
  static Object get(Object target, String property) {
    for (String prefix : new String[] {"get", "is"}) {
      try {
        return target.getClass().getMethod(prefix + property).invoke(target);
      } catch (NoSuchMethodException e) {
        // next prefix
      } catch (IllegalAccessException | InvocationTargetException e) {
        throw new IllegalStateException(
            target.getClass().getSimpleName() + "." + prefix + property, e);
      }
    }
    throw new IllegalArgumentException(target.getClass().getName() + ": kein get" + property);
  }

  static ContextType context(Context context) {
    ContextType type = new ContextType();
    type.setMandantId(context.mandantId());
    type.setClientSystemId(context.clientSystemId());
    type.setWorkplaceId(context.workplaceId());
    type.setUserId(context.userId());
    return type;
  }

  private static Class<?> box(Class<?> type) {
    if (!type.isPrimitive()) {
      return type;
    }
    return type == boolean.class
        ? Boolean.class
        : type == int.class ? Integer.class : type == long.class ? Long.class : type;
  }
}
