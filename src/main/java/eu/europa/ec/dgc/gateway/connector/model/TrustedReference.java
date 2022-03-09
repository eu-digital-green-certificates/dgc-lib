/*-
 * ---license-start
 * WHO Digital Documentation Covid Certificate Gateway Service / ddcc-gateway-lib
 * ---
 * Copyright (C) 2022 T-Systems International GmbH and all other contributors
 * ---
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ---license-end
 */

package eu.europa.ec.dgc.gateway.connector.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TrustedReference {

    private String uuid;

    private String url;

    private String version;

    private String country;

    private ReferenceType type;

    private String service;

    private String thumbprint;

    private String name;

    private String sslPublicKey;

    private String contentType;

    private SignatureType signatureType;

    private String referenceVersion;

    public enum ReferenceType {
        DCC,
        FHIR
    }

    public enum SignatureType {
        CMS,
        JWS,
        NONE
    }
}
