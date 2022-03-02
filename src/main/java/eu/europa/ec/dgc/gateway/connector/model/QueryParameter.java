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

import java.io.Serializable;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@Getter
public class QueryParameter<T extends Serializable> {

    public static final QueryParameter<String> GROUP =
        new QueryParameter<>("group", true, String.class);

    public static final QueryParameter<String> COUNTRY_CODE =
        new QueryParameter<>("country", true, String.class);

    public static final QueryParameter<String> DOMAIN =
        new QueryParameter<>("domain", true, String.class);

    public static final QueryParameter<String> REFERENCE_TYPE =
        new QueryParameter<>("referenceType", true, String.class);

    public static final QueryParameter<String> SIGNATURE_TYPE =
        new QueryParameter<>("signatureType", true, String.class);

    public static final QueryParameter<Boolean> WITH_FEDERATION =
        new QueryParameter<>("withFederation", false, Boolean.class);

    private final String queryParamName;
    private final Boolean arrayValue;
    private final Class<T> queryParamType;
}
