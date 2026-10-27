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
package de.gematik.liana.crypto;

import io.quarkus.runtime.annotations.RegisterForReflection;

/**
 * Native image (LIANA-112.09): the JDK's XPath implementation ({@code javax.xml.xpath}, for {@code
 * dss:SignaturePlacement/XPathFirstChildOf} in {@link XadesSignatures}) creates its functions such
 * as {@code local-name()} via {@code FunctionTable} by reflection; without registration every XPath
 * with a function ends in a {@code TransformerException} „FuncLocalPart.&lt;init&gt;()“. All
 * classes of {@code com.sun.org.apache.xpath.internal.functions} (java.xml, JDK 21) are registered.
 */
@RegisterForReflection(
    classNames = {
      "com.sun.org.apache.xpath.internal.functions.FuncBoolean",
      "com.sun.org.apache.xpath.internal.functions.FuncCeiling",
      "com.sun.org.apache.xpath.internal.functions.FuncConcat",
      "com.sun.org.apache.xpath.internal.functions.FuncContains",
      "com.sun.org.apache.xpath.internal.functions.FuncCount",
      "com.sun.org.apache.xpath.internal.functions.FuncCurrent",
      "com.sun.org.apache.xpath.internal.functions.FuncDoclocation",
      "com.sun.org.apache.xpath.internal.functions.FuncExtElementAvailable",
      "com.sun.org.apache.xpath.internal.functions.FuncExtFunction",
      "com.sun.org.apache.xpath.internal.functions.FuncExtFunctionAvailable",
      "com.sun.org.apache.xpath.internal.functions.FuncFalse",
      "com.sun.org.apache.xpath.internal.functions.FuncFloor",
      "com.sun.org.apache.xpath.internal.functions.FuncGenerateId",
      "com.sun.org.apache.xpath.internal.functions.FuncHere",
      "com.sun.org.apache.xpath.internal.functions.FuncId",
      "com.sun.org.apache.xpath.internal.functions.FuncLang",
      "com.sun.org.apache.xpath.internal.functions.FuncLast",
      "com.sun.org.apache.xpath.internal.functions.FuncLocalPart",
      "com.sun.org.apache.xpath.internal.functions.FuncNamespace",
      "com.sun.org.apache.xpath.internal.functions.FuncNormalizeSpace",
      "com.sun.org.apache.xpath.internal.functions.FuncNot",
      "com.sun.org.apache.xpath.internal.functions.FuncNumber",
      "com.sun.org.apache.xpath.internal.functions.FuncPosition",
      "com.sun.org.apache.xpath.internal.functions.FuncQname",
      "com.sun.org.apache.xpath.internal.functions.FuncRound",
      "com.sun.org.apache.xpath.internal.functions.FuncStartsWith",
      "com.sun.org.apache.xpath.internal.functions.FuncString",
      "com.sun.org.apache.xpath.internal.functions.FuncStringLength",
      "com.sun.org.apache.xpath.internal.functions.FuncSubstring",
      "com.sun.org.apache.xpath.internal.functions.FuncSubstringAfter",
      "com.sun.org.apache.xpath.internal.functions.FuncSubstringBefore",
      "com.sun.org.apache.xpath.internal.functions.FuncSum",
      "com.sun.org.apache.xpath.internal.functions.FuncSystemProperty",
      "com.sun.org.apache.xpath.internal.functions.FuncTranslate",
      "com.sun.org.apache.xpath.internal.functions.FuncTrue",
      "com.sun.org.apache.xpath.internal.functions.FuncUnparsedEntityURI",
      "com.sun.org.apache.xpath.internal.functions.Function",
      "com.sun.org.apache.xpath.internal.functions.Function2Args",
      "com.sun.org.apache.xpath.internal.functions.Function3Args",
      "com.sun.org.apache.xpath.internal.functions.FunctionDef1Arg",
      "com.sun.org.apache.xpath.internal.functions.FunctionMultiArgs",
      "com.sun.org.apache.xpath.internal.functions.FunctionOneArg",
      "com.sun.org.apache.xpath.internal.functions.WrongNumberArgsException"
    })
final class XPathFunctions {

  private XPathFunctions() {}
}
