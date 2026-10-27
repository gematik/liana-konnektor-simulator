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
package de.gematik.liana.adapter.sds;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;

/**
 * {@code GET /} on the Konnektor port (LIANA-189.02): 200 with a small HTML page. There is no AFO
 * for this; Epikur uses it to check reachability before and after service discovery and treats any
 * other status as an error (secunet responds 500, pairing fails there). The no-caching headers
 * follow the secunet Konnektor. The management port has the Control Center under {@code /}.
 */
@Path("/")
public class ReachabilityResource {

  static final String BODY = "<html><head><title>LIANA</title></head><body>OK</body></html>";

  @GET
  public Response get() {
    return Response.ok(BODY, "text/html;charset=UTF-8")
        .header("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
        .header("Pragma", "no-cache")
        .header("Expires", "0")
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "DENY")
        .build();
  }
}
