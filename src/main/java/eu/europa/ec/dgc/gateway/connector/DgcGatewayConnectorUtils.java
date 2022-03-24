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
import eu.europa.ec.dgc.gateway.connector.dto.CertificateTypeDto;
import eu.europa.ec.dgc.gateway.connector.dto.TrustListItemDto;
import eu.europa.ec.dgc.gateway.connector.dto.TrustedIssuerDto;
import eu.europa.ec.dgc.gateway.connector.mapper.TrustedIssuerMapper;
import eu.europa.ec.dgc.gateway.connector.model.QueryParameter;
import eu.europa.ec.dgc.gateway.connector.model.TrustedIssuer;
import eu.europa.ec.dgc.signing.SignedCertificateMessageParser;
import eu.europa.ec.dgc.signing.SignedMessageParser;
import eu.europa.ec.dgc.signing.SignedStringMessageParser;
import eu.europa.ec.dgc.utils.CertificateUtils;
import feign.FeignException;
import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import javax.annotation.PostConstruct;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@ConditionalOnProperty("dgc.gateway.connector.enabled")
@RequiredArgsConstructor
class DgcGatewayConnectorUtils {

    private final CertificateUtils certificateUtils;

    private final DgcGatewayConnectorRestClient dgcGatewayConnectorRestClient;

    private final DgcGatewayConnectorConfigProperties properties;

    private final TrustedIssuerMapper trustedIssuerMapper;

    @Qualifier("trustAnchor")
    private final KeyStore trustAnchorKeyStore;

    @Setter
    private List<X509CertificateHolder> trustAnchors;

    private static final String HASH_SEPARATOR = ";";


    @PostConstruct
    void init() throws KeyStoreException, CertificateEncodingException, IOException {
        Security.addProvider(new BouncyCastleProvider());

        String trustAnchorAlias = properties.getTrustAnchor().getAlias();
        X509Certificate trustAnchorCert = (X509Certificate) trustAnchorKeyStore.getCertificate(trustAnchorAlias);

        if (trustAnchorCert == null) {
            log.error("Could not find TrustAnchor Certificate in Keystore");
            throw new KeyStoreException("Could not find TrustAnchor Certificate in Keystore");
        }
        trustAnchors = Collections.singletonList(certificateUtils.convertCertificate(trustAnchorCert));
    }

    public boolean trustListItemSignedByCa(TrustListItemDto certificate, X509CertificateHolder ca) {
        ContentVerifierProvider verifier;
        try {
            verifier = new JcaContentVerifierProviderBuilder().build(ca);
        } catch (OperatorCreationException | CertificateException e) {
            log.error("Failed to instantiate JcaContentVerifierProvider from cert. KID: {}, Country: {}",
                certificate.getKid(), certificate.getCountry());
            return false;
        }

        X509CertificateHolder dcs;
        try {
            dcs = new X509CertificateHolder(Base64.getDecoder().decode(certificate.getRawData()));
        } catch (IOException e) {
            log.error("Could not parse certificate. KID: {}, Country: {}",
                certificate.getKid(), certificate.getCountry());
            return false;
        }

        try {
            return dcs.isSignatureValid(verifier);
        } catch (CertException | RuntimeOperatorException e) {
            log.debug("Could not verify that certificate was issued by ca. Certificate: {}, CA: {}",
                dcs.getSubject().toString(), ca.getSubject().toString());
            return false;
        }
    }

    public boolean trustListItemSignedByCa(TrustListItemDto certificate, Map<String,
            List<X509CertificateHolder>> caMap) {

        X509CertificateHolder dcs;
        try {
            dcs = new X509CertificateHolder(Base64.getDecoder().decode(certificate.getRawData()));
        } catch (IOException e) {
            log.error("Could not parse certificate. KID: {}, Country: {}",
                    certificate.getKid(), certificate.getCountry());
            return false;
        }

        List<X509CertificateHolder> caList = caMap.get(dcs.getIssuer().toString());
        if (caList == null) {
            log.error("Failed to find issuer certificate from cert. KID: {}, Country: {}",
                    certificate.getKid(), certificate.getCountry());
            return false;
        }

        return caList
                .stream()
                .anyMatch(ca -> trustListItemSignedByCa(certificate, ca));
    }

    boolean checkTrustAnchorSignature(TrustListItemDto trustListItem, List<X509CertificateHolder> trustAnchors) {
        SignedCertificateMessageParser parser = new SignedCertificateMessageParser(
            trustListItem.getSignature(), trustListItem.getRawData());

        if (parser.getParserState() != SignedMessageParser.ParserState.SUCCESS) {
            log.error("Could not parse trustListItem CMS. ParserState: {}", parser.getParserState());
            return false;
        } else if (!parser.isSignatureVerified()) {
            log.error("Could not verify trustListItem CMS Signature, KID: {}, Country: {}",
                trustListItem.getKid(), trustListItem.getCountry());
            return false;
        }

        return trustAnchors.stream().anyMatch(trustAnchor -> parser.getSigningCertificate().equals(trustAnchor));
    }

    boolean checkTrustAnchorSignature(TrustedIssuerDto trustedIssuer, List<X509CertificateHolder> trustAnchors) {
        SignedStringMessageParser parser = new SignedStringMessageParser(trustedIssuer.getSignature(),
            Base64.getEncoder().encodeToString(getHashData(trustedIssuer).getBytes(StandardCharsets.UTF_8)));

        if (parser.getParserState() != SignedCertificateMessageParser.ParserState.SUCCESS) {
            log.error("Could not parse trustedIssuer signature. ParserState: {}", parser.getParserState());
            return false;
        } else if (!parser.isSignatureVerified()) {
            log.error("Could not verify trustedIssuer Signature, Country: {}, URL: {}",
                trustedIssuer.getCountry(), trustedIssuer.getUrl());
            return false;
        }

        return trustAnchors.stream().anyMatch(trustAnchor -> parser.getSigningCertificate().equals(trustAnchor));
    }

    X509CertificateHolder getCertificateFromTrustListItem(TrustListItemDto trustListItem) {
        byte[] decodedBytes = Base64.getDecoder().decode(trustListItem.getRawData());

        try {
            return new X509CertificateHolder(decodedBytes);
        } catch (IOException e) {
            log.error("Failed to parse Certificate Raw Data. KID: {}, Country: {}",
                trustListItem.getKid(), trustListItem.getCountry());
            return null;
        }
    }

    public List<X509CertificateHolder> fetchCertificatesAndVerifyByTrustAnchor(CertificateTypeDto type) {
        ResponseEntity<List<TrustListItemDto>> downloadedCertificates;
        try {
            downloadedCertificates = dgcGatewayConnectorRestClient.getTrustedCertificates(type);
        } catch (FeignException e) {
            log.error("Failed to Download certificates from DGC Gateway. Type: {}, status code: {}", type, e.status());
            return Collections.emptyList();
        }

        if (downloadedCertificates.getStatusCode() != HttpStatus.OK || downloadedCertificates.getBody() == null) {
            log.error("Failed to Download certificates from DGC Gateway, Type: {}, Status Code: {}",
                type, downloadedCertificates.getStatusCodeValue());
            return Collections.emptyList();
        }

        return downloadedCertificates.getBody().stream()
            .filter(this::checkThumbprintIntegrity)
            .filter(c -> this.checkTrustAnchorSignature(c, trustAnchors))
            .map(this::getCertificateFromTrustListItem)
            .filter(Objects::nonNull)
            .collect(Collectors.toList());
    }

    public List<TrustedIssuer> fetchTrustedIssuersAndVerifyByTrustAnchor(
        Map<QueryParameter<? extends Serializable>, List<? extends Serializable>> queryParameterMap
    )
        throws DgcGatewayConnectorUtils.DgcGatewayConnectorException {
        log.info("Fetching TrustedIssuers from DGCG");

        ResponseEntity<List<TrustedIssuerDto>> responseEntity;
        try {
            responseEntity = dgcGatewayConnectorRestClient.downloadTrustedIssuers(
                convertQueryParams(queryParameterMap)
            );
        } catch (FeignException e) {
            throw new DgcGatewayConnectorUtils.DgcGatewayConnectorException(
                e.status(), "Download of TrustedIssuers failed.");
        }

        List<TrustedIssuerDto> downloadedTrustedIssuers = responseEntity.getBody();

        if (responseEntity.getStatusCode() != HttpStatus.OK || downloadedTrustedIssuers == null) {
            throw new DgcGatewayConnectorUtils.DgcGatewayConnectorException(
                responseEntity.getStatusCodeValue(), "Download of TrustedIssuers failed.");
        } else {
            log.info("Got Response from DGCG, Downloaded TrustedIssuers: {}",
                downloadedTrustedIssuers.size());
        }

        return downloadedTrustedIssuers.stream()
            .filter(c -> this.checkTrustAnchorSignature(c, trustAnchors))
            .map(trustedIssuerMapper::map)
            .collect(Collectors.toList());

    }

    private boolean checkThumbprintIntegrity(TrustListItemDto trustListItem) {
        byte[] certificateRawData = Base64.getDecoder().decode(trustListItem.getRawData());
        try {
            return trustListItem.getThumbprint().equals(
                certificateUtils.getCertThumbprint(new X509CertificateHolder(certificateRawData)));

        } catch (IOException e) {
            log.error("Could not parse certificate raw data");
            return false;
        }
    }

    protected Map<String, String> convertQueryParams(
        Map<QueryParameter<? extends Serializable>, List<? extends Serializable>> queryParameterMap) {

        return queryParameterMap.entrySet()
            .stream()
            .map(mapEntry -> {
                String queryKey = mapEntry.getKey().getQueryParamName();
                String queryValue = mapEntry.getValue().stream()
                    .map(Serializable::toString)
                    .collect(Collectors.joining(","));
                return Map.entry(queryKey, queryValue);
            })
            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    private String getHashData(TrustedIssuerDto trustedIssuerDto) {
        return trustedIssuerDto.getUuid() + HASH_SEPARATOR
            + trustedIssuerDto.getCountry() + HASH_SEPARATOR
            + trustedIssuerDto.getName() + HASH_SEPARATOR
            + trustedIssuerDto.getUrl() + HASH_SEPARATOR
            + trustedIssuerDto.getType().name() + HASH_SEPARATOR;
    }

    @RequiredArgsConstructor
    @Getter
    public static class DgcGatewayConnectorException extends Exception {
        private final int httpStatusCode;
        private final String message;
    }
}
