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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.gateway.connector.client.DgcGatewayConnectorRestClient;
import eu.europa.ec.dgc.gateway.connector.config.DgcGatewayConnectorConfigProperties;
import eu.europa.ec.dgc.gateway.connector.dto.CertificateTypeDto;
import eu.europa.ec.dgc.gateway.connector.dto.ValidationRuleDto;
import eu.europa.ec.dgc.gateway.connector.model.ValidationRule;
import eu.europa.ec.dgc.gateway.connector.model.ValidationRulesByCountry;
import eu.europa.ec.dgc.signing.SignedMessageParser;
import eu.europa.ec.dgc.signing.SignedStringMessageParser;
import feign.FeignException;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
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
public class DgcGatewayValidationRuleDownloadConnector {

    private final DgcGatewayConnectorUtils connectorUtils;

    private final DgcGatewayConnectorRestClient dgcGatewayConnectorRestClient;

    private final DgcGatewayConnectorConfigProperties properties;

    private final DgcGatewayCountryListDownloadConnector countryListDownloadConnector;

    private final ObjectMapper objectMapper;

    @Getter
    private LocalDateTime lastUpdated = null;

    private ValidationRulesByCountry validationRules = new ValidationRulesByCountry();

    private List<X509CertificateHolder> trustedUploadCertificates = new ArrayList<>();

    /**
     * Gets the list of downloaded and validated validation rules.
     * This call will return a cached list if caching is enabled.
     * If cache is outdated a refreshed list will be returned.
     *
     * @return {@link ValidationRulesByCountry}
     */
    public ValidationRulesByCountry getValidationRules() {
        updateIfRequired();
        return validationRules;
    }

    private synchronized void updateIfRequired() {
        if (lastUpdated == null
            || ChronoUnit.SECONDS.between(lastUpdated, LocalDateTime.now()) >= properties.getMaxCacheAge()) {
            log.info("Maximum age of cache reached. Fetching new TrustList from DGCG.");

            validationRules = new ValidationRulesByCountry();

            trustedUploadCertificates =
                connectorUtils.fetchCertificatesAndVerifyByTrustAnchor(CertificateTypeDto.UPLOAD).stream()
                    .map(connectorUtils::getCertificateFromTrustListItem)
                    .collect(Collectors.toList());
            log.info("Upload TrustStore contains {} trusted certificates.", trustedUploadCertificates.size());

            List<String> countryCodes = countryListDownloadConnector.getCountryList();
            log.info("Downloaded Countrylist");

            countryCodes.forEach(this::fetchValidationRulesAndVerify);
            log.info("ValidationRule Cache contains {} ValidationRules.", validationRules.size());
        } else {
            log.debug("Cache needs no refresh.");
        }
    }

    private void fetchValidationRulesAndVerify(String countryCode) {
        log.info("Fetching ValidationRules from DGCG for Country {}", countryCode);

        ResponseEntity<Map<String, List<ValidationRuleDto>>> responseEntity;
        try {
            responseEntity = dgcGatewayConnectorRestClient.downloadValidationRule(countryCode);
        } catch (FeignException e) {
            log.error("Download of ValidationRules for country {} failed. DGCG responded with status code: {}",
                countryCode, e.status());
            return;
        }

        Map<String, List<ValidationRuleDto>> downloadedValidationRules = responseEntity.getBody();

        if (responseEntity.getStatusCode() != HttpStatus.OK || downloadedValidationRules == null) {
            log.error("Download of ValidationRules for country {} failed. DGCG responded with status code: {}",
                countryCode, responseEntity.getStatusCode());
            return;
        } else {
            log.info("Got Response from DGCG, Downloaded ValidationRules: {}", downloadedValidationRules.size());
        }

        downloadedValidationRules.values().stream()
            .flatMap(Collection::stream)
            .filter(v -> checkCmsSignature(v, countryCode))
            .filter(this::checkUploadCertificate)
            .map(this::map)
            .filter(Objects::nonNull)
            .forEach(rule -> validationRules.set(countryCode, rule.getIdentifier(), rule.getVersion(), rule));

        lastUpdated = LocalDateTime.now();
    }

    private boolean checkCmsSignature(ValidationRuleDto validationRuleDto, String countryCode) {
        SignedStringMessageParser parser =
            new SignedStringMessageParser(validationRuleDto.getCms());

        if (parser.getParserState() != SignedMessageParser.ParserState.SUCCESS) {
            log.error("Invalid CMS for Validation Rule of {}", countryCode);
            return false;
        }

        if (!parser.isSignatureVerified()) {
            log.error("Invalid CMS Signature for Validation Rule of {}", countryCode);
            return false;
        }

        return true;
    }

    private ValidationRule map(ValidationRuleDto dto) {
        SignedStringMessageParser parser =
            new SignedStringMessageParser(dto.getCms());

        try {
            ValidationRule parsedRule = objectMapper.readValue(parser.getPayload(), ValidationRule.class);
            parsedRule.setRawJson(parser.getPayload());
            return parsedRule;
        } catch (JsonProcessingException e) {
            log.error("Failed to parse Validation Rule JSON: {}", e.getMessage());
            return null;
        }
    }

    private boolean checkUploadCertificate(ValidationRuleDto validationRule) {
        SignedStringMessageParser parser =
            new SignedStringMessageParser(validationRule.getCms());
        X509CertificateHolder uploadCertificate = parser.getSigningCertificate();

        if (uploadCertificate == null) {
            return false;
        }

        return trustedUploadCertificates
            .stream()
            .anyMatch(uploadCertificate::equals);
    }
}
