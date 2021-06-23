/*-
 * ---license-start
 * EU Digital Green Certificate Gateway Service / dgc-lib
 * ---
 * Copyright (C) 2021 T-Systems International GmbH and all other contributors
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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.Getter;

public class ValidationRulesByCountry {

    @Getter
    private final Map<String, ValidationRulesByIdentifier> map = new HashMap<>();

    /**
     * Sets a ValidationRule Entry in the ValidationRuleSet.
     *
     * @param country Country Code
     * @param id      ValidationRule Identifier
     * @param version Version of Validation Rule
     * @param rule    The Rule to be added.
     */
    public void set(String country, String id, String version, ValidationRule rule) {
        map
            .computeIfAbsent(country, s -> new ValidationRulesByIdentifier())
            .getMap()
            .computeIfAbsent(id, s -> new ValidationRulesByVersion())
            .getMap().put(version, rule);
    }

    /**
     * Gets a ValidationRule from the map.
     *
     * @param country Country Code
     * @param id      ValidationRule Identifier
     * @param version Version of Validation Rule
     * @return the ValidationRule or null if it does not exist.
     */
    public ValidationRule get(String country, String id, String version) {
        return map
            .getOrDefault(country, new ValidationRulesByIdentifier())
            .getMap()
            .getOrDefault(id, new ValidationRulesByVersion())
            .getMap().getOrDefault(version, null);
    }

    /**
     * Returns a pure Map-structure of this data type.
     * This should be used when serializing this Object into JSON.
     */
    public Map<String, Map<String, Map<String, ValidationRule>>> pure() {
        return map.entrySet().stream()
            .map(e -> Map.entry(e.getKey(), e.getValue().getMap().entrySet().stream()
                .map(ee -> Map.entry(ee.getKey(), ee.getValue().getMap()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue))))
            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    /**
     * Gets a flat list of all Validation Rules.
     *
     * @return List of {@link ValidationRule}
     */
    public List<ValidationRule> flat() {
        List<ValidationRule> allRules = new ArrayList<>();

        for (ValidationRulesByIdentifier v : map.values()) {
            for (ValidationRulesByVersion vv : v.getMap().values()) {
                allRules.addAll(vv.getMap().values());
            }
        }

        return allRules;
    }

    /**
     * Gets the amount of all ValidationRules within this structure.
     *
     * @return amount of ValidationRules.
     */
    public int size() {
        int count = 0;

        for (ValidationRulesByIdentifier v : map.values()) {
            for (ValidationRulesByVersion vv : v.getMap().values()) {
                count += vv.getMap().size();
            }
        }

        return count;
    }

    public static class ValidationRulesByIdentifier {

        @Getter
        private final Map<String, ValidationRulesByVersion> map = new HashMap<>();
    }

    public static class ValidationRulesByVersion {

        @Getter
        private final Map<String, ValidationRule> map = new HashMap<>();
    }
}
