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

package eu.europa.ec.dgc.gateway.connector;

import eu.europa.ec.dgc.gateway.connector.client.DgcGatewayConnectorRestClient;
import eu.europa.ec.dgc.gateway.connector.config.DgcGatewayConnectorConfigProperties;
import eu.europa.ec.dgc.gateway.connector.model.ValidationRulesByCountry;
import feign.FeignException;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Scope;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.stereotype.Service;

@ConditionalOnProperty("dgc.gateway.connector.enabled")
@Lazy
@Service
@Scope(ConfigurableBeanFactory.SCOPE_SINGLETON)
@RequiredArgsConstructor
@EnableScheduling
@Slf4j
public class DgcGatewayValueSetDownloadConnector {

    private final DgcGatewayConnectorRestClient dgcGatewayConnectorRestClient;

    private final DgcGatewayConnectorConfigProperties properties;

    @Getter
    private LocalDateTime lastUpdated = null;

    private final Map<String, String> valueSets = new HashMap<>();

    /**
     * Gets the list of downloaded ValueSets.
     * Map Containing Key ValueSetId and Value is the JSON String
     * This call will return a cached list if caching is enabled.
     * If cache is outdated a refreshed list will be returned.
     *
     * @return {@link ValidationRulesByCountry}
     */
    public Map<String, String> getValueSets() {
        updateIfRequired();
        return valueSets;
    }

    private synchronized void updateIfRequired() {
        if (lastUpdated == null
            || ChronoUnit.SECONDS.between(lastUpdated, LocalDateTime.now()) >= properties.getMaxCacheAge()) {
            log.info("Maximum age of cache reached. Fetching new ValueSets from DGCG.");

            valueSets.clear();

            List<String> valueSetIds = fetchValueSetIds();
            log.info("Got List of ValueSet Ids");

            valueSetIds.forEach(this::fetchValueSet);
            log.info("ValueSet Cache contains {} ValueSets.", valueSets.size());
        } else {
            log.debug("Cache needs no refresh.");
        }
    }

    private List<String> fetchValueSetIds() {
        log.info("Fetching ValueSet IDs from DGCG");

        ResponseEntity<List<String>> responseEntity;
        try {
            responseEntity = dgcGatewayConnectorRestClient.downloadValueSetIds();
        } catch (FeignException e) {
            log.error("Download of ValueSet IDs failed. DGCG responded with status code: {}",
                e.status());
            return Collections.emptyList();
        }

        List<String> valueSetIds = responseEntity.getBody();

        if (responseEntity.getStatusCode() != HttpStatus.OK || valueSetIds == null) {
            log.error("Download of ValueSet IDs failed. DGCG responded with status code: {}",
                responseEntity.getStatusCode());
            return Collections.emptyList();
        } else {
            log.info("Got Response from DGCG, downloaded {} ValueSet IDs.", valueSetIds.size());
        }

        return valueSetIds;
    }

    private void fetchValueSet(String id) {
        log.info("Fetching ValueSet from DGCG with Id {}", id);

        ResponseEntity<String> responseEntity;
        try {
            responseEntity = dgcGatewayConnectorRestClient.downloadValueSet(id);
        } catch (FeignException e) {
            log.error("Download of ValueSet with ID {} failed. DGCG responded with status code: {}",
                id, e.status());
            return;
        }

        String valueSet = responseEntity.getBody();

        if (responseEntity.getStatusCode() != HttpStatus.OK || valueSet == null) {
            log.error("Download of ValueSet with ID {} failed. DGCG responded with status code: {}",
                id, responseEntity.getStatusCode());
            return;
        } else {
            log.info("Got Response from DGCG, ValueSet downloaded.");
        }

        valueSets.put(id, valueSet);
        lastUpdated = LocalDateTime.now();
    }
}
