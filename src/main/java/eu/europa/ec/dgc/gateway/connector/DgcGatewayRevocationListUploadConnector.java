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
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import eu.europa.ec.dgc.gateway.connector.client.DgcGatewayConnectorRestClient;
import eu.europa.ec.dgc.gateway.connector.config.DgcGatewayConnectorConfigProperties;
import eu.europa.ec.dgc.gateway.connector.dto.ProblemReportDto;
import eu.europa.ec.dgc.gateway.connector.dto.RevocationBatchDeleteRequestDto;
import eu.europa.ec.dgc.gateway.connector.dto.RevocationBatchDto;
import eu.europa.ec.dgc.signing.SignedStringMessageBuilder;
import eu.europa.ec.dgc.utils.CertificateUtils;
import feign.FeignException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import javax.annotation.PostConstruct;
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
public class DgcGatewayRevocationListUploadConnector {

    private final DgcGatewayConnectorRestClient dgcGatewayConnectorRestClient;

    private final DgcGatewayConnectorConfigProperties properties;

    private final ObjectMapper objectMapper;

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
     * Uploads a JSON-File as RevocationBatch to DGC Gateway.
     *
     * @param revocationBatchDto the RevocationBatchDto to upload.
     * @throws DgcRevocationBatchUploadException with detailed information why the upload has failed.
     */
    public String uploadRevocationBatch(RevocationBatchDto revocationBatchDto)
        throws DgcRevocationBatchUploadException, JsonProcessingException {

        objectMapper.registerModule(new JavaTimeModule());
        String jsonString = objectMapper.writeValueAsString(revocationBatchDto);
        String payload = new SignedStringMessageBuilder().withPayload(jsonString)
            .withSigningCertificate(uploadCertificateHolder, uploadCertificatePrivateKey).buildAsString();

        try {
            ResponseEntity<Void> response = dgcGatewayConnectorRestClient.uploadBatch(payload);
            if (response.getStatusCode() == HttpStatus.CREATED) {
                log.info("Successfully uploaded RevocationBatch");
                return response.getHeaders().getETag();
            }
        } catch (FeignException e) {
            if (e.status() == HttpStatus.BAD_REQUEST.value()) {
                handleBadRequest(e);
            } else if (e.status() == HttpStatus.INTERNAL_SERVER_ERROR.value()) {
                throw new DgcRevocationBatchUploadException(DgcRevocationBatchUploadException.Reason.SERVER_ERROR);
            } else if (e.status() == HttpStatus.UNAUTHORIZED.value() || e.status() == HttpStatus.FORBIDDEN.value()) {
                log.error("Client is not authorized. (Invalid Client Certificate)");
                throw new DgcRevocationBatchUploadException(
                    DgcRevocationBatchUploadException.Reason.INVALID_AUTHORIZATION);
            }
        }
        return null;
    }

    /**
     * Deletes a RevocationBatch with given ID from DGC Gateway.
     *
     * @param batchId The ID of the batch to be deleted.
     * @throws DgcRevocationBatchUploadException with detailed information why the delete has failed.
     */
    public void deleteRevocationBatch(String batchId) throws DgcRevocationBatchUploadException,
        JsonProcessingException {

        RevocationBatchDeleteRequestDto deleteRequest = new RevocationBatchDeleteRequestDto();
        deleteRequest.setBatchId(batchId);
        String jsonString = objectMapper.writeValueAsString(deleteRequest);

        String payload = new SignedStringMessageBuilder().withPayload(jsonString)
            .withSigningCertificate(uploadCertificateHolder, uploadCertificatePrivateKey).buildAsString();

        try {
            ResponseEntity<Void> response = dgcGatewayConnectorRestClient.deleteBatch(payload);
            if (response.getStatusCode() == HttpStatus.NO_CONTENT) {
                log.info("Successfully deleted ValidationRule");
            }
        } catch (FeignException e) {
            if (e.status() == HttpStatus.BAD_REQUEST.value()) {
                handleBadRequest(e);
            } else if (e.status() == HttpStatus.INTERNAL_SERVER_ERROR.value()) {
                throw new DgcRevocationBatchUploadException(DgcRevocationBatchUploadException.Reason.SERVER_ERROR);
            } else if (e.status() == HttpStatus.UNAUTHORIZED.value() || e.status() == HttpStatus.FORBIDDEN.value()) {
                log.error("Client is not authorized. (Invalid Client Certificate)");
                throw new DgcRevocationBatchUploadException(
                    DgcRevocationBatchUploadException.Reason.INVALID_AUTHORIZATION);

            } else if (e.status() == HttpStatus.NOT_FOUND.value()) {
                log.info("ValidationRules with ID {} does not exists on DGCG", batchId);
            }
        }
    }

    private void handleBadRequest(FeignException e) throws DgcRevocationBatchUploadException {
        if (e.responseBody().isPresent()) {
            try {
                ProblemReportDto problemReport = objectMapper.readValue(e.contentUTF8(), ProblemReportDto.class);

                throw new DgcRevocationBatchUploadException(DgcRevocationBatchUploadException.Reason.INVALID_BATCH,
                    String.format("%s: %s, %s", problemReport.getCode(), problemReport.getProblem(),
                        problemReport.getDetails()));
            } catch (JsonProcessingException jsonException) {
                throw new DgcRevocationBatchUploadException(DgcRevocationBatchUploadException.Reason.UNKNOWN_ERROR);
            }
        }
    }

    public static class DgcRevocationBatchUploadException extends Exception {

        @Getter
        private final Reason reason;

        public DgcRevocationBatchUploadException(Reason reason) {
            super();
            this.reason = reason;
        }

        public DgcRevocationBatchUploadException(Reason reason, String message) {
            super(message);
            this.reason = reason;
        }

        public enum Reason {
            UNKNOWN_ERROR, INVALID_AUTHORIZATION, INVALID_UPLOAD_CERT, INVALID_BATCH, SERVER_ERROR
        }
    }

}
