/*-
 * ---license-start
 * EU Digital Green Certificate Gateway Service / dgc-lib
 * ---
 * Copyright (C) 2021 - 2022 T-Systems International GmbH and all other contributors
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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.ZonedDateTime;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
public class ValidationRule {

    @JsonProperty("Identifier")
    String identifier;

    @JsonProperty("Type")
    String type;

    @JsonProperty("Country")
    String country;

    @JsonProperty("Region")
    String region;

    @JsonProperty("Version")
    String version;

    @JsonProperty("SchemaVersion")
    String schemaVersion;

    @JsonProperty("Engine")
    String engine;

    @JsonProperty("EngineVersion")
    String engineVersion;

    @JsonProperty("CertificateType")
    String certificateType;

    @JsonProperty("Description")
    List<DescriptionItem> description;

    @JsonProperty("ValidFrom")
    ZonedDateTime validFrom;

    @JsonProperty("ValidTo")
    ZonedDateTime validTo;

    @JsonProperty("AffectedFields")
    List<String> affectedFields;

    @JsonProperty("Logic")
    JsonNode logic;

    @JsonIgnore
    String rawJson;

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class DescriptionItem {

        @JsonProperty("lang")
        String language;

        @JsonProperty("desc")
        String description;
    }
}
