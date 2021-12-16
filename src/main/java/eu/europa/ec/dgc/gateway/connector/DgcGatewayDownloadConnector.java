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
import eu.europa.ec.dgc.gateway.connector.mapper.TrustListMapper;
import eu.europa.ec.dgc.gateway.connector.model.TrustListItem;
import eu.europa.ec.dgc.signing.SignedCertificateMessageParser;
import feign.FeignException;
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

    @Getter
    private LocalDateTime lastUpdated = null;

    private List<TrustListItem> trustedCertificates = new ArrayList<>();

    private List<X509CertificateHolder> trustedCscaCertificates = new ArrayList<>();
    private Map<String, X509CertificateHolder> trustedCscaCertificateMap = new HashMap<>();
    private List<X509CertificateHolder> trustedUploadCertificates = new ArrayList<>();

    @PostConstruct
    void init() {
        Security.addProvider(new BouncyCastleProvider());
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

    private synchronized void updateIfRequired() {
        if (lastUpdated == null
            || ChronoUnit.SECONDS.between(lastUpdated, LocalDateTime.now()) >= properties.getMaxCacheAge()) {
            log.info("Maximum age of cache reached. Fetching new TrustList from DGCG.");

            trustedCscaCertificates = connectorUtils.fetchCertificatesAndVerifyByTrustAnchor(CertificateTypeDto.CSCA);
            log.info("CSCA TrustStore contains {} trusted certificates.", trustedCscaCertificates.size());
            trustedCscaCertificateMap = trustedCscaCertificates.stream()
                    .collect(Collectors.toMap((ca) -> ca.getSubject().toString(), (ca) -> ca));

            trustedUploadCertificates =
                connectorUtils.fetchCertificatesAndVerifyByTrustAnchor(CertificateTypeDto.UPLOAD);
            log.info("Upload TrustStore contains {} trusted certificates.", trustedUploadCertificates.size());

            fetchTrustListAndVerifyByCscaAndUpload();
            log.info("DSC TrustStore contains {} trusted certificates.", trustedCertificates.size());
        } else {
            log.debug("Cache needs no refresh.");
        }
    }

    private void fetchTrustListAndVerifyByCscaAndUpload() {
        log.info("Fetching TrustList from DGCG");

        ResponseEntity<List<TrustListItemDto>> responseEntity;
        try {
            responseEntity = dgcGatewayConnectorRestClient.getTrustedCertificates(CertificateTypeDto.DSC);
        } catch (FeignException e) {
            log.error("Download of TrustListItems failed. DGCG responded with status code: {}",
                e.status());
            return;
        }

        List<TrustListItemDto> downloadedDcs = responseEntity.getBody();

        if (responseEntity.getStatusCode() != HttpStatus.OK || downloadedDcs == null) {
            log.error("Download of TrustListItems failed. DGCG responded with status code: {}",
                responseEntity.getStatusCode());
            return;
        } else {
            log.info("Got Response from DGCG, Downloaded Certificates: {}", downloadedDcs.size());
        }

        trustedCertificates = downloadedDcs.stream()
            .filter(this::checkCscaCertificate)
            .filter(this::checkUploadCertificate)
            .map(trustListMapper::map)
            .collect(Collectors.toList());

        lastUpdated = LocalDateTime.now();
        log.info("Put {} trusted certificates into TrustList", trustedCertificates.size());
    }

    private boolean checkCscaCertificate(TrustListItemDto trustListItem) {
        boolean result = connectorUtils.trustListItemSignedByCa(trustListItem, trustedCscaCertificateMap);

        if (!result) {
            log.info("Could not find valid CSCA for DSC {}", trustListItem.getKid());
        }

        return result;
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
            log.error("Invalid CMS for DSC {} of {}", trustListItem.getKid(), trustListItem.getCountry());
            return false;
        }

        if (!parser.isSignatureVerified()) {
            log.error("Invalid CMS Signature for DSC {} of {}", trustListItem.getKid(), trustListItem.getCountry());
        }

        return trustedUploadCertificates
            .stream()
            .anyMatch(uploadCertificate::equals);
    }
}
