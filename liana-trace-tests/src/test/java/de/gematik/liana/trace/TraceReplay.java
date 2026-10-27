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
package de.gematik.liana.trace;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Replays the client side of a golden trace against a freshly started LIANA (decision-9).
 *
 * <p>LIANA starts before the tests of the class, each HTTP request from the trace goes to LIANA in
 * trace order. What is adjusted in the trace for LIANA is stated as a separate annotation with a
 * reason on the test class: {@link LianaConfig}, {@link Replace}, {@link Carry}, {@link
 * ReplaceSteps}. Test methods get the result as a {@link Replay} parameter. All annotations also
 * work as meta-annotations, so an environment can be bundled for several test classes (e.g. {@link
 * PoppKonTuGegenLiana}).
 */
@Target({ElementType.TYPE, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@ExtendWith(TraceReplayExtension.class)
public @interface TraceReplay {

  /** Path to the {@code .tgr} file, relative to the repo root. */
  String value();
}
