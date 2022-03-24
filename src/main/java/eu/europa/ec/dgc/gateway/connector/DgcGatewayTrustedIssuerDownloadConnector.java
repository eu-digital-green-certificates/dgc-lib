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

import eu.europa.ec.dgc.gateway.connector.config.DgcGatewayConnectorConfigProperties;
import eu.europa.ec.dgc.gateway.connector.model.QueryParameter;
import eu.europa.ec.dgc.gateway.connector.model.TrustedIssuer;
import java.io.Serializable;
import java.security.Security;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import javax.annotation.PostConstruct;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Scope;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.stereotype.Service;

@ConditionalOnProperty("dgc.gateway.connector.enabled")
@Lazy
@Service
@Scope(ConfigurableBeanFactory.SCOPE_SINGLETON)
@RequiredArgsConstructor
@EnableScheduling
@Slf4j
public class DgcGatewayTrustedIssuerDownloadConnector {

    private final DgcGatewayConnectorUtils connectorUtils;

    private final DgcGatewayConnectorConfigProperties properties;


    @Getter
    private String status = null;

    @Getter
    private LocalDateTime lastUpdated = null;

    private List<TrustedIssuer> trustedIssuers = new ArrayList<>();

    private final HashMap<QueryParameter<? extends Serializable>, List<? extends Serializable>> queryParameterMap =
        new HashMap<>();

    @PostConstruct
    void init() {
        Security.addProvider(new BouncyCastleProvider());
    }


    /**
     * Set Query Params to filter requests to Gateway. If an entry for given Key already exists it will be overridden.
     *
     * @param queryParameter The Query Parameter
     * @param value          Values to filter for.
     */
    public <T extends Serializable> void setQueryParameter(QueryParameter<T> queryParameter, T value) {
        setQueryParameter(queryParameter, List.of(value));
    }

    /**
     * Set Query Params to filter requests to Gateway. If an entry for given Key already exists it will be overridden.
     *
     * @param queryParameter The Query Parameter
     * @param values         List of values (filtering is additive, e.g.: Providing values "CSCA" and "UPLOAD" will
     *                       result in a list of "CSCA" and "UPLOAD" certificates with at least one matching property.
     */
    public <T extends Serializable> void setQueryParameter(QueryParameter<T> queryParameter, List<T> values) {
        if (!queryParameter.getArrayValue() && values.size() > 1) {
            throw new IllegalArgumentException("Only one value is allowed for non-array query parameters.");
        }

        // Check if Key will be added or value has changed if key already exists
        if ((!queryParameterMap.containsKey(queryParameter))
            || queryParameterMap.containsKey(queryParameter)
            && queryParameterMap.get(queryParameter).hashCode() != values.hashCode()) {

            // value has changed, invalidate cache
            lastUpdated = null;
        }

        queryParameterMap.put(queryParameter, values);
    }

    /**
     * Resets the Query Params. Cache will also be invalidated.
     */
    public void resetQueryParameter() {
        queryParameterMap.clear();
        lastUpdated = null;
    }


    /**
     * Gets the list of downloaded and validated TrustedIssuers.
     * This call will return a cached list if caching is enabled.
     * If cache is outdated a refreshed list will be returned.
     *
     * @return List of {@link TrustedIssuer}
     */
    public List<TrustedIssuer> getTrustedIssuers() {
        updateIfRequired();
        return Collections.unmodifiableList(trustedIssuers);
    }


    private synchronized void updateIfRequired() {
        if (lastUpdated == null
            || ChronoUnit.SECONDS.between(lastUpdated, LocalDateTime.now()) >= properties.getMaxCacheAge()) {
            log.info("Maximum age of cache reached. Fetching new TrustList from DGCG.");

            try {
                // Fetching TrustedIssuers
                trustedIssuers = connectorUtils.fetchTrustedIssuersAndVerifyByTrustAnchor(queryParameterMap);
                log.info("TrustedIssuers contains {} entries", trustedIssuers.size());
                status = null;
            } catch (DgcGatewayConnectorUtils.DgcGatewayConnectorException e) {
                log.error("Failed to Download Trusted Certificates: {} - {}", e.getHttpStatusCode(), e.getMessage());
                status = "Download Failed: " + e.getHttpStatusCode() + " - " + e.getMessage();
            }
        } else {
            log.debug("Cache needs no refresh.");
        }
    }

}
