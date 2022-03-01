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
import eu.europa.ec.dgc.gateway.connector.dto.CertificateTypeDto;
import eu.europa.ec.dgc.gateway.connector.dto.TrustListItemDto;
import eu.europa.ec.dgc.gateway.connector.dto.TrustedCertificateTrustListDto;
import eu.europa.ec.dgc.gateway.connector.mapper.TrustListMapper;
import eu.europa.ec.dgc.gateway.connector.mapper.TrustedCertificateMapper;
import eu.europa.ec.dgc.gateway.connector.model.QueryParameter;
import eu.europa.ec.dgc.gateway.connector.model.TrustListItem;
import eu.europa.ec.dgc.gateway.connector.model.TrustedCertificateTrustListItem;
import eu.europa.ec.dgc.gateway.connector.model.TrustedIssuer;
import eu.europa.ec.dgc.gateway.connector.model.TrustedReference;
import eu.europa.ec.dgc.signing.SignedCertificateMessageParser;
import feign.FeignException;
import java.io.Serializable;
import java.security.Security;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.annotation.PostConstruct;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
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
public class DgcGatewayDownloadConnector {

    private final DgcGatewayConnectorUtils connectorUtils;

    private final DgcGatewayConnectorRestClient dgcGatewayConnectorRestClient;

    private final DgcGatewayConnectorConfigProperties properties;

    private final TrustListMapper trustListMapper;

    private final TrustedCertificateMapper trustedCertificateMapper;

    @Getter
    private String status = null;

    @Getter
    private LocalDateTime lastUpdated = null;

    private List<TrustListItem> trustedCertificates = new ArrayList<>();
    private List<TrustedCertificateTrustListItem> ddccTrustedCertificates = new ArrayList<>();

    private List<TrustListItem> trustedCscaTrustList = new ArrayList<>();
    private List<X509CertificateHolder> trustedCscaCertificates = new ArrayList<>();
    private Map<String, List<X509CertificateHolder>> trustedCscaCertificateMap = new HashMap<>();

    private List<TrustListItem> trustedUploadCertificateTrustList = new ArrayList<>();
    private List<X509CertificateHolder> trustedUploadCertificates = new ArrayList<>();

    private List<TrustedIssuer> trustedIssuers = new ArrayList<>();

    private List<TrustedReference> trustedReferences = new ArrayList<>();

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
     * Gets the list of downloaded and validated trusted signer certificates.
     * This call will return a cached list if caching is enabled.
     * If cache is outdated a refreshed list will be returned.
     *
     * @return List of {@link TrustListItem}
     */
    public List<TrustListItem> getTrustedCertificates() {
        updateIfRequired();
        return Collections.unmodifiableList(trustedCertificates);
    }

    /**
     * Gets the list of downloaded and validated DDCC TrustedCertificates.
     * This call will return a cached list if caching is enabled.
     * If cache is outdated a refreshed list will be returned.
     *
     * @return List of {@link TrustedCertificateTrustListItem}
     */
    public List<TrustedCertificateTrustListItem> getDdccTrustedCertificates() {
        updateIfRequired();
        return Collections.unmodifiableList(ddccTrustedCertificates);
    }

    /**
     * Gets the list of downloaded and validated CSCA certificates.
     * This call will return a cached list. It requires that the getTrustedCertificates
     * method was called before. Otherwise, the returned list will be empty.
     *
     * @return List of {@link TrustListItem}
     */
    public List<TrustListItem> getTrustedCscaCertificates() {
        return Collections.unmodifiableList(trustedCscaTrustList);
    }

    /**
     * Gets the list of downloaded and validated Upload certificates.
     * This call will return a cached list. It requires that the getTrustedCertificates
     * method was called before. Otherwise, the returned list will be empty.
     *
     * @return List of {@link TrustListItem}
     */
    public List<TrustListItem> getTrustedUploadCertificates() {
        return Collections.unmodifiableList(trustedUploadCertificateTrustList);
    }

    /**
     * Gets the list of downloaded and validated TrustedIssuers.
     * This call will return a cached list if caching is enabled.
     * If cache is outdated a refreshed list will be returned.
     *
     * @return List of {@link TrustedIssuer}
     */
    public List<TrustedIssuer> getTrustedIssuers() {
        if (!properties.isEnableDdccSupport()) {
            log.error("DDCC Support needs to be enabled in order to request TrustedIssuers");
        }

        updateIfRequired();
        return Collections.unmodifiableList(trustedIssuers);
    }

    /**
     * Gets the list of downloaded and validated TrustedReferences.
     * This call will return a cached list if caching is enabled.
     * If cache is outdated a refreshed list will be returned.
     *
     * @return List of {@link TrustedIssuer}
     */
    public List<TrustedReference> getTrustedReferences() {
        if (!properties.isEnableDdccSupport()) {
            log.error("DDCC Support needs to be enabled in order to request TrustedCertificates");
        }

        updateIfRequired();
        return Collections.unmodifiableList(trustedReferences);
    }

    private synchronized void updateIfRequired() {
        if (lastUpdated == null
            || ChronoUnit.SECONDS.between(lastUpdated, LocalDateTime.now()) >= properties.getMaxCacheAge()) {
            log.info("Maximum age of cache reached. Fetching new TrustList from DGCG.");

            // Fetching CSCA Certs
            try {
                trustedCscaTrustList = connectorUtils.fetchCertificatesAndVerifyByTrustAnchor(
                    CertificateTypeDto.CSCA, queryParameterMap);
                trustedCscaCertificates = trustedCscaTrustList.stream()
                    .map(connectorUtils::getCertificateFromTrustListItem)
                    .collect(Collectors.toList());
                log.info("CSCA TrustStore contains {} trusted certificates.", trustedCscaCertificates.size());
                trustedCscaCertificateMap = trustedCscaCertificates.stream()
                    .collect(Collectors.groupingBy(ca -> ca.getSubject().toString(),
                        Collectors.mapping(ca -> ca, Collectors.toList())));

                // Fetching Upload Certs
                trustedUploadCertificateTrustList = connectorUtils.fetchCertificatesAndVerifyByTrustAnchor(
                    CertificateTypeDto.UPLOAD, queryParameterMap);
                trustedUploadCertificates = trustedUploadCertificateTrustList.stream()
                    .map(connectorUtils::getCertificateFromTrustListItem)
                    .collect(Collectors.toList());
                log.info("Upload TrustStore contains {} trusted certificates.", trustedUploadCertificates.size());

                fetchTrustListAndVerifyByCscaAndUpload();
                log.info("DSC TrustStore contains {} trusted certificates.", trustedCertificates.size());

                if (properties.isEnableDdccSupport()) {
                    // Fetching TrustedCertificates
                    fetchTrustedCertificatesAndVerifyByCscaAndUpload();

                    // Fetching TrustedIssuers
                    trustedIssuers = connectorUtils.fetchTrustedIssuersAndVerifyByTrustAnchor(queryParameterMap);
                    log.info("TrustedIssuers contains {} entries", trustedIssuers.size());

                    // Fetching TrustedReferences
                    trustedReferences =
                        connectorUtils.fetchTrustedReferencesAndVerifyByUploadCertificate(queryParameterMap);
                    log.info("TrustedReferences contains {} entries", trustedReferences.size());
                }
                status = null;
            } catch (DgcGatewayConnectorUtils.DgcGatewayConnectorException e) {
                log.error("Failed to Download Trusted Certificates: {} - {}", e.getHttpStatusCode(), e.getMessage());
                status = "Download Failed: " + e.getHttpStatusCode() + " - " + e.getMessage();
            }
        } else {
            log.debug("Cache needs no refresh.");
        }
    }

    private void fetchTrustListAndVerifyByCscaAndUpload() throws DgcGatewayConnectorUtils.DgcGatewayConnectorException {
        log.info("Fetching TrustList from DGCG");

        List<TrustListItemDto> downloadedCertificates;
        HttpStatus responseStatus;
        try {
            if (properties.isEnableDdccSupport()) {
                // clone and modify parameter map to only get certs of requested type
                HashMap<QueryParameter<? extends Serializable>, List<? extends Serializable>> clonedMap =
                    new HashMap<>(queryParameterMap);
                clonedMap.put(QueryParameter.GROUP, List.of("DSC"));

                ResponseEntity<List<TrustedCertificateTrustListDto>> responseEntity =
                    dgcGatewayConnectorRestClient.downloadTrustedCertificates(
                        connectorUtils.convertQueryParams(clonedMap));

                downloadedCertificates = trustedCertificateMapper.mapToTrustList(responseEntity.getBody());
                responseStatus = responseEntity.getStatusCode();

            } else {
                ResponseEntity<List<TrustListItemDto>> responseEntity =
                    dgcGatewayConnectorRestClient.getTrustList(CertificateTypeDto.DSC);
                downloadedCertificates = responseEntity.getBody();
                responseStatus = responseEntity.getStatusCode();
            }
        } catch (FeignException e) {
            throw new DgcGatewayConnectorUtils.DgcGatewayConnectorException(
                e.status(), "Download of TrustListItems failed.");
        }

        if (responseStatus != HttpStatus.OK || downloadedCertificates == null) {
            throw new DgcGatewayConnectorUtils.DgcGatewayConnectorException(
                responseStatus.value(), "Download of TrustListItems failed.");
        } else {
            log.info("Got Response from DGCG, Downloaded Certificates: {}", downloadedCertificates.size());
        }

        trustedCertificates = downloadedCertificates.stream()
            .filter(this::checkCscaCertificate)
            .filter(this::checkUploadCertificate)
            .map(trustListMapper::map)
            .collect(Collectors.toList());

        lastUpdated = LocalDateTime.now();
        log.info("Put {} trusted certificates into TrustList", trustedCertificates.size());
    }

    private void fetchTrustedCertificatesAndVerifyByCscaAndUpload() throws
        DgcGatewayConnectorUtils.DgcGatewayConnectorException {
        if (!properties.isEnableDdccSupport()) {
            log.info("DDCC Support is disabled, Skipping TrustedCertificate Download.");
            return;
        }

        log.info("Fetching Trusted Certificate from DGCG");

        ResponseEntity<List<TrustedCertificateTrustListDto>> responseEntity;
        try {
            responseEntity = dgcGatewayConnectorRestClient.downloadTrustedCertificates(
                connectorUtils.convertQueryParams(queryParameterMap));
        } catch (FeignException e) {
            throw new DgcGatewayConnectorUtils.DgcGatewayConnectorException(
                e.status(), "Download of TrustListItems failed.");
        }

        if (responseEntity.getStatusCode() != HttpStatus.OK || responseEntity.getBody() == null) {
            throw new DgcGatewayConnectorUtils.DgcGatewayConnectorException(
                responseEntity.getStatusCodeValue(), "Download of TrustedCertificates failed.");
        } else {
            log.info("Got Response from DGCG, Downloaded Trusted Certificates: {}", responseEntity.getBody().size());
        }

        ddccTrustedCertificates = responseEntity.getBody().stream()
            .filter(this::checkCscaCertificate)
            .filter(this::checkUploadCertificate)
            .map(trustedCertificateMapper::map)
            .collect(Collectors.toList());

        lastUpdated = LocalDateTime.now();
        log.info("Put {} DDCC TrustedCertificates into TrustList", ddccTrustedCertificates.size());
    }

    private boolean checkCscaCertificate(TrustedCertificateTrustListDto trustListItem) {
        return checkCscaCertificate(trustedCertificateMapper.mapToTrustList(trustListItem));
    }

    private boolean checkCscaCertificate(TrustListItemDto trustListItem) {
        boolean result = connectorUtils.trustListItemSignedByCa(trustListItem, trustedCscaCertificateMap);

        if (!result) {
            log.info("Could not find valid CSCA for DSC/TrustedCertificate {}", trustListItem.getKid());
        }

        return result;
    }

    private boolean checkUploadCertificate(TrustedCertificateTrustListDto trustListItem) {
        return checkUploadCertificate(trustedCertificateMapper.mapToTrustList(trustListItem));
    }

    private boolean checkUploadCertificate(TrustListItemDto trustListItem) {
        if (properties.isDisableUploadCertificateCheck()) {
            log.debug("Upload Certificate Check is disabled. Skipping Check.");
            return true;
        }

        SignedCertificateMessageParser parser =
            new SignedCertificateMessageParser(trustListItem.getSignature(), trustListItem.getRawData());
        X509CertificateHolder uploadCertificate = parser.getSigningCertificate();

        if (uploadCertificate == null) {
            log.error("Invalid CMS for DSC/TrustedCertificate {} of {}",
                trustListItem.getKid(), trustListItem.getCountry());
            return false;
        }

        if (!parser.isSignatureVerified()) {
            log.error("Invalid CMS Signature for DSC/TrustedCertificate {} of {}",
                trustListItem.getKid(), trustListItem.getCountry());
        }

        return trustedUploadCertificates
            .stream()
            .anyMatch(uploadCertificate::equals);
    }
}
