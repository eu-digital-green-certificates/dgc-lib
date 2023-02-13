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

package eu.europa.ec.dgc.gateway.connector;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.gateway.connector.client.DgcGatewayConnectorRestClient;
import eu.europa.ec.dgc.gateway.connector.config.DgcGatewayConnectorConfigProperties;
import eu.europa.ec.dgc.gateway.connector.dto.ProblemReportDto;
import eu.europa.ec.dgc.signing.SignedStringMessageBuilder;
import eu.europa.ec.dgc.utils.CertificateUtils;
import feign.FeignException;
import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.beans.factory.annotation.Qualifier;
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
public class DgcGatewayValidationRuleUploadConnector {

    private final DgcGatewayConnectorRestClient dgcGatewayConnectorRestClient;

    private final DgcGatewayConnectorConfigProperties properties;

    private final CertificateUtils certificateUtils;

    @Qualifier("upload")
    private final KeyStore uploadKeyStore;

    private X509CertificateHolder uploadCertificateHolder;

    private PrivateKey uploadCertificatePrivateKey;

    @PostConstruct
    void init() throws KeyStoreException, CertificateEncodingException, IOException {
        String uploadCertAlias = properties.getUploadKeyStore().getAlias();
        X509Certificate uploadCertificate = (X509Certificate) uploadKeyStore.getCertificate(uploadCertAlias);

        try {
            uploadCertificatePrivateKey =
                (PrivateKey) uploadKeyStore.getKey(uploadCertAlias, properties.getUploadKeyStore().getPassword());
        } catch (NoSuchAlgorithmException | UnrecoverableKeyException e) {
            log.error("Failed to load PrivateKey from KeyStore");
        }

        if (uploadCertificatePrivateKey == null) {
            log.error("Could not find UploadCertificate PrivateKey in Keystore");
            throw new KeyStoreException("Could not find UploadCertificate PrivateKey in Keystore");
        }

        if (uploadCertificate == null) {
            log.error("Could not find UploadCertificate in Keystore");
            throw new KeyStoreException("Could not find UploadCertificate in Keystore");
        }

        uploadCertificateHolder = certificateUtils.convertCertificate(uploadCertificate);
    }

    /**
     * Uploads a JSON-File as ValidationRule to DGC Gateway.
     *
     * @param json the JSON containing the ValidationRUle to upload.
     * @throws DgcValidationRuleUploadException with detailed information why the upload has failed.
     */
    public void uploadValidationRule(String json) throws DgcValidationRuleUploadException {

        String payload = new SignedStringMessageBuilder()
            .withPayload(json)
            .withSigningCertificate(uploadCertificateHolder, uploadCertificatePrivateKey)
            .buildAsString();

        try {
            ResponseEntity<Void> response = dgcGatewayConnectorRestClient.uploadValidationRule(payload);
            if (response.getStatusCode() == HttpStatus.CREATED) {
                log.info("Successfully uploaded ValidationRule");
            }
        } catch (FeignException e) {
            if (e.status() == HttpStatus.BAD_REQUEST.value()) {
                handleBadRequest(e);
            } else if (e.status() == HttpStatus.INTERNAL_SERVER_ERROR.value()) {
                throw new DgcValidationRuleUploadException(DgcValidationRuleUploadException.Reason.SERVER_ERROR);
            } else if (e.status() == HttpStatus.UNAUTHORIZED.value()
                || e.status() == HttpStatus.FORBIDDEN.value()) {
                log.error("Client is not authorized. (Invalid Client Certificate)");
                throw new DgcValidationRuleUploadException(
                    DgcValidationRuleUploadException.Reason.INVALID_AUTHORIZATION);
            }
        }
    }

    /**
     * Deletes a all ValidationRules with given ID from DGC Gateway.
     *
     * @param ruleId The ID of the Rules to be deleted.
     * @throws DgcValidationRuleUploadException with detailed information why the delete has failed.
     */
    public void deleteValidationRules(String ruleId) throws DgcValidationRuleUploadException {

        String payload = new SignedStringMessageBuilder()
            .withPayload(ruleId)
            .withSigningCertificate(uploadCertificateHolder, uploadCertificatePrivateKey)
            .buildAsString();

        try {
            ResponseEntity<Void> response = dgcGatewayConnectorRestClient.deleteValidationRule(payload);
            if (response.getStatusCode() == HttpStatus.NO_CONTENT) {
                log.info("Successfully deleted ValidationRule");
            }
        } catch (FeignException e) {
            if (e.status() == HttpStatus.BAD_REQUEST.value()) {
                handleBadRequest(e);
            } else if (e.status() == HttpStatus.INTERNAL_SERVER_ERROR.value()) {
                throw new DgcValidationRuleUploadException(DgcValidationRuleUploadException.Reason.SERVER_ERROR);
            } else if (e.status() == HttpStatus.UNAUTHORIZED.value()
                || e.status() == HttpStatus.FORBIDDEN.value()) {
                log.error("Client is not authorized. (Invalid Client Certificate)");
                throw new DgcValidationRuleUploadException(
                    DgcValidationRuleUploadException.Reason.INVALID_AUTHORIZATION);

            } else if (e.status() == HttpStatus.NOT_FOUND.value()) {
                log.info("ValidationRules with ID {} does not exists on DGCG", ruleId);
            }
        }
    }

    private void handleBadRequest(FeignException e) throws DgcValidationRuleUploadException {
        if (e.responseBody().isPresent()) {
            ObjectMapper objectMapper = new ObjectMapper();
            try {
                ProblemReportDto problemReport = objectMapper.readValue(e.contentUTF8(), ProblemReportDto.class);

                throw new DgcValidationRuleUploadException(DgcValidationRuleUploadException.Reason.INVALID_RULE,
                    String.format(
                        "%s: %s, %s",
                        problemReport.getCode(),
                        problemReport.getProblem(),
                        problemReport.getDetails()));
            } catch (JsonProcessingException jsonException) {
                throw new DgcValidationRuleUploadException(DgcValidationRuleUploadException.Reason.UNKNOWN_ERROR);
            }
        }
    }

    public static class DgcValidationRuleUploadException extends Exception {

        @Getter
        private final Reason reason;

        public DgcValidationRuleUploadException(Reason reason) {
            super();
            this.reason = reason;
        }

        public DgcValidationRuleUploadException(Reason reason, String message) {
            super(message);
            this.reason = reason;
        }

        public enum Reason {
            UNKNOWN_ERROR,
            INVALID_AUTHORIZATION,
            INVALID_UPLOAD_CERT,
            INVALID_RULE,
            SERVER_ERROR
        }
    }

}
