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

package eu.europa.ec.dgc.gateway.connector;

import eu.europa.ec.dgc.gateway.connector.client.DgcGatewayConnectorRestClient;
import eu.europa.ec.dgc.gateway.connector.config.DgcGatewayConnectorConfigProperties;
import feign.FeignException;
import jakarta.annotation.PostConstruct;
import java.security.Security;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
public class DgcGatewayCountryListDownloadConnector {

    private final DgcGatewayConnectorRestClient dgcGatewayConnectorRestClient;

    private final DgcGatewayConnectorConfigProperties properties;

    @Getter
    private LocalDateTime lastUpdated = null;

    private List<String> countryList = new ArrayList<>();

    @PostConstruct
    void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Gets the list of downloaded Country Codes.
     * This call will return a cached list if caching is enabled.
     * If cache is outdated a refreshed list will be returned.
     *
     * @return List of {@link String}
     */
    public List<String> getCountryList() {
        updateIfRequired();
        return Collections.unmodifiableList(countryList);
    }

    private synchronized void updateIfRequired() {
        if (lastUpdated == null
            || ChronoUnit.SECONDS.between(lastUpdated, LocalDateTime.now()) >= properties.getMaxCacheAge()) {
            log.info("Maximum age of cache reached. Fetching new CountryList from DGCG.");

            countryList = new ArrayList<>();
            fetchCountryList();
            log.info("CountryList contains {} country codes.", countryList.size());
        } else {
            log.debug("Cache needs no refresh.");
        }
    }

    private void fetchCountryList() {
        log.info("Fetching CountryList from DGCG");

        ResponseEntity<List<String>> responseEntity;
        try {
            responseEntity = dgcGatewayConnectorRestClient.downloadCountryList();
        } catch (FeignException e) {
            log.error("Download of CountryList failed. DGCG responded with status code: {}",
                e.status());
            return;
        }

        List<String> downloadedCountries = responseEntity.getBody();

        if (responseEntity.getStatusCode() != HttpStatus.OK || downloadedCountries == null) {
            log.error("Download of CountryList failed. DGCG responded with status code: {}",
                responseEntity.getStatusCode());
            return;
        } else {
            log.info("Got Response from DGCG, Downloaded Countries: {}", downloadedCountries.size());
        }

        countryList = downloadedCountries;

        lastUpdated = LocalDateTime.now();
        log.info("Put {} country codes CountryList", countryList.size());
    }
}
