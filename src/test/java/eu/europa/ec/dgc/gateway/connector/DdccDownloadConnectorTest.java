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
import eu.europa.ec.dgc.gateway.connector.dto.CertificateTypeDto;
import eu.europa.ec.dgc.gateway.connector.dto.TrustedCertificateTrustListDto;
import eu.europa.ec.dgc.gateway.connector.dto.TrustedIssuerDto;
import eu.europa.ec.dgc.gateway.connector.dto.TrustedReferenceDto;
import eu.europa.ec.dgc.gateway.connector.model.QueryParameter;
import eu.europa.ec.dgc.gateway.connector.model.TrustListItem;
import eu.europa.ec.dgc.gateway.connector.model.TrustedIssuer;
import eu.europa.ec.dgc.gateway.connector.model.TrustedReference;
import eu.europa.ec.dgc.signing.SignedCertificateMessageBuilder;
import eu.europa.ec.dgc.signing.SignedStringMessageBuilder;
import eu.europa.ec.dgc.testdata.CertificateTestUtils;
import eu.europa.ec.dgc.testdata.DgcTestKeyStore;
import eu.europa.ec.dgc.utils.CertificateUtils;
import feign.FeignException;
import feign.Request;
import feign.RequestTemplate;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.ResponseEntity;

@SpringBootTest(properties = "dgc.gateway.connector.enable-ddcc-support=true")
@Slf4j
class DdccDownloadConnectorTest {

    @MockBean
    DgcGatewayConnectorRestClient restClientMock;

    @Autowired
    DgcGatewayDownloadConnector connector;

    @Autowired
    CertificateUtils certificateUtils;

    @Autowired
    DgcTestKeyStore testKeyStore;

    @AfterEach
    void cleanup() {
        connector.resetQueryParameter();
    }

    @Test
    void testDownloadOfCertificates() throws Exception {

        KeyPair keyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate csca = CertificateTestUtils.generateCertificate(keyPair, "EU", "CSCA");

        String cscaSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayload(certificateUtils.convertCertificate(csca))
            .buildAsString(true);

        TrustedCertificateTrustListDto cscaTrustListItem = new TrustedCertificateTrustListDto();
        cscaTrustListItem.setCountry("EU");
        cscaTrustListItem.setKid("KID_EU");
        cscaTrustListItem.setGroup("CSCA");
        cscaTrustListItem.setSignature(cscaSignature);
        cscaTrustListItem.setCertificate(Base64.getEncoder().encodeToString(csca.getEncoded()));

        KeyPair keyPairUpload = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate upload = CertificateTestUtils.generateCertificate(keyPairUpload, "EU", "UPLOAD");

        String uploadSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayload(certificateUtils.convertCertificate(upload))
            .buildAsString(true);

        TrustedCertificateTrustListDto uploadTrustListItem = new TrustedCertificateTrustListDto();
        uploadTrustListItem.setCountry("EU");
        uploadTrustListItem.setKid("KID_EU_UPLOAD");
        uploadTrustListItem.setGroup("UPLOAD");
        uploadTrustListItem.setSignature(uploadSignature);
        uploadTrustListItem.setCertificate(Base64.getEncoder().encodeToString(upload.getEncoded()));

        KeyPair keyPairDsc = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate dsc = CertificateTestUtils.generateCertificate(keyPairDsc, "EU", "DSC", csca, keyPair.getPrivate());

        String dscSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(upload), keyPairUpload.getPrivate())
            .withPayload(certificateUtils.convertCertificate(dsc))
            .buildAsString(true);

        TrustedCertificateTrustListDto dscTrustListItem = new TrustedCertificateTrustListDto();
        dscTrustListItem.setCountry("EU");
        dscTrustListItem.setKid("KID_EU_DSC");
        dscTrustListItem.setGroup("DSC");
        dscTrustListItem.setSignature(dscSignature);
        dscTrustListItem.setCertificate(Base64.getEncoder().encodeToString(dsc.getEncoded()));

        when(restClientMock.downloadTrustedCertificates(any())).thenAnswer(call -> {
            Map<String, String> queryParameter = call.getArgument(0, Map.class);

            if (queryParameter.containsKey("group")) {
                if (queryParameter.get("group").equalsIgnoreCase("CSCA")) {
                    return ResponseEntity.ok(Collections.singletonList(cscaTrustListItem));
                } else if (queryParameter.get("group").equalsIgnoreCase("DSC")) {
                    return ResponseEntity.ok(Collections.singletonList(dscTrustListItem));
                } else if (queryParameter.get("group").equalsIgnoreCase("UPLOAD")) {
                    return ResponseEntity.ok(Collections.singletonList(uploadTrustListItem));
                }
            }
            return null;
        });

        when(restClientMock.downloadTrustedIssuers(any())).thenReturn(ResponseEntity.ok(Collections.emptyList()));
        when(restClientMock.downloadTrustedReferences(any())).thenReturn(ResponseEntity.ok(Collections.emptyList()));

        List<TrustListItem> result = connector.getTrustedCertificates();
        Assertions.assertEquals(1, result.size());

        Assertions.assertEquals(dscTrustListItem.getCertificate(), result.get(0).getRawData());
        Assertions.assertEquals(dscTrustListItem.getKid(), result.get(0).getKid());

        log.info("Trusted Certs: {}", connector.getTrustedCertificates());
        Assertions.assertNotNull(connector.getLastUpdated());
    }

    @Test
    void testDownloadOfCertificatesShouldFailWrongTrustAnchorSignatureForCsca() throws Exception {

        KeyPair cscaKayPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate csca = CertificateTestUtils.generateCertificate(cscaKayPair, "EU", "CSCA");

        KeyPair fakeTrustAnchorKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate fakeTrustAnchor = CertificateTestUtils.generateCertificate(fakeTrustAnchorKeyPair, "EU", "TA");

        String cscaSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(fakeTrustAnchor), fakeTrustAnchorKeyPair.getPrivate())
            .withPayload(certificateUtils.convertCertificate(csca))
            .buildAsString(true);

        TrustedCertificateTrustListDto cscaTrustListItem = new TrustedCertificateTrustListDto();
        cscaTrustListItem.setCountry("EU");
        cscaTrustListItem.setKid("KID_EU");
        cscaTrustListItem.setGroup("CSCA");
        cscaTrustListItem.setSignature(cscaSignature);
        cscaTrustListItem.setCertificate(Base64.getEncoder().encodeToString(csca.getEncoded()));

        KeyPair keyPairUpload = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate upload = CertificateTestUtils.generateCertificate(keyPairUpload, "EU", "UPLOAD");

        String uploadSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayload(certificateUtils.convertCertificate(upload))
            .buildAsString(true);

        TrustedCertificateTrustListDto uploadTrustListItem = new TrustedCertificateTrustListDto();
        uploadTrustListItem.setCountry("EU");
        uploadTrustListItem.setKid("KID_EU_UPLOAD");
        uploadTrustListItem.setGroup("UPLOAD");
        uploadTrustListItem.setSignature(uploadSignature);
        uploadTrustListItem.setCertificate(Base64.getEncoder().encodeToString(upload.getEncoded()));

        KeyPair keyPairDsc = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate dsc = CertificateTestUtils.generateCertificate(keyPairDsc, "EU", "DSC", csca, testKeyStore.getTrustAnchorPrivateKey());

        String dscSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(upload), keyPairUpload.getPrivate())
            .withPayload(certificateUtils.convertCertificate(dsc))
            .buildAsString(true);

        TrustedCertificateTrustListDto dscTrustListItem = new TrustedCertificateTrustListDto();
        dscTrustListItem.setCountry("EU");
        dscTrustListItem.setKid("KID_EU_DSC");
        dscTrustListItem.setGroup("DSC");
        dscTrustListItem.setSignature(dscSignature);
        dscTrustListItem.setCertificate(Base64.getEncoder().encodeToString(dsc.getEncoded()));

        when(restClientMock.downloadTrustedCertificates(any())).thenAnswer(call -> {
            Map<String, String> queryParameter = call.getArgument(0, Map.class);

            if (queryParameter.containsKey("group")) {
                if (queryParameter.get("group").equalsIgnoreCase("CSCA")) {
                    return ResponseEntity.ok(Collections.singletonList(cscaTrustListItem));
                } else if (queryParameter.get("group").equalsIgnoreCase("DSC")) {
                    return ResponseEntity.ok(Collections.singletonList(dscTrustListItem));
                } else if (queryParameter.get("group").equalsIgnoreCase("UPLOAD")) {
                    return ResponseEntity.ok(Collections.singletonList(uploadTrustListItem));
                }
            }
            return null;
        });

        when(restClientMock.downloadTrustedIssuers(any())).thenReturn(ResponseEntity.ok(Collections.emptyList()));
        when(restClientMock.downloadTrustedReferences(any())).thenReturn(ResponseEntity.ok(Collections.emptyList()));

        Assertions.assertEquals(0, connector.getTrustedCertificates().size());
        Assertions.assertNotNull(connector.getLastUpdated());
    }

    @Test
    void testDownloadOfCertificatesShouldFailWrongTrustAnchorSignatureForUpload() throws Exception {

        KeyPair keyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate csca = CertificateTestUtils.generateCertificate(keyPair, "EU", "CSCA");

        String cscaSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayload(certificateUtils.convertCertificate(csca))
            .buildAsString(true);

        TrustedCertificateTrustListDto cscaTrustListItem = new TrustedCertificateTrustListDto();
        cscaTrustListItem.setCountry("EU");
        cscaTrustListItem.setKid("KID_EU");
        cscaTrustListItem.setGroup("CSCA");
        cscaTrustListItem.setSignature(cscaSignature);
        cscaTrustListItem.setCertificate(Base64.getEncoder().encodeToString(csca.getEncoded()));

        KeyPair fakeTrustAnchorKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate fakeTrustAnchor = CertificateTestUtils.generateCertificate(fakeTrustAnchorKeyPair, "EU", "TA");

        KeyPair keyPairUpload = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate upload = CertificateTestUtils.generateCertificate(keyPairUpload, "EU", "UPLOAD");

        String uploadSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(fakeTrustAnchor), fakeTrustAnchorKeyPair.getPrivate())
            .withPayload(certificateUtils.convertCertificate(upload))
            .buildAsString(true);

        TrustedCertificateTrustListDto uploadTrustListItem = new TrustedCertificateTrustListDto();
        uploadTrustListItem.setCountry("EU");
        uploadTrustListItem.setKid("KID_EU_UPLOAD");
        uploadTrustListItem.setGroup("UPLOAD");
        uploadTrustListItem.setSignature(uploadSignature);
        uploadTrustListItem.setCertificate(Base64.getEncoder().encodeToString(upload.getEncoded()));

        KeyPair keyPairDsc = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate dsc = CertificateTestUtils.generateCertificate(keyPairDsc, "EU", "DSC", csca, keyPair.getPrivate());

        String dscSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(upload), keyPairUpload.getPrivate())
            .withPayload(certificateUtils.convertCertificate(dsc))
            .buildAsString(true);

        TrustedCertificateTrustListDto dscTrustListItem = new TrustedCertificateTrustListDto();
        dscTrustListItem.setCountry("EU");
        dscTrustListItem.setKid("KID_EU_DSC");
        dscTrustListItem.setGroup("DSC");
        dscTrustListItem.setSignature(dscSignature);
        dscTrustListItem.setCertificate(Base64.getEncoder().encodeToString(dsc.getEncoded()));

        when(restClientMock.downloadTrustedCertificates(any())).thenAnswer(call -> {
            Map<String, String> queryParameter = call.getArgument(0, Map.class);

            if (queryParameter.containsKey("group")) {
                if (queryParameter.get("group").equalsIgnoreCase("CSCA")) {
                    return ResponseEntity.ok(Collections.singletonList(cscaTrustListItem));
                } else if (queryParameter.get("group").equalsIgnoreCase("DSC")) {
                    return ResponseEntity.ok(Collections.singletonList(dscTrustListItem));
                } else if (queryParameter.get("group").equalsIgnoreCase("UPLOAD")) {
                    return ResponseEntity.ok(Collections.singletonList(uploadTrustListItem));
                }
            }
            return null;
        });

        when(restClientMock.downloadTrustedIssuers(any())).thenReturn(ResponseEntity.ok(Collections.emptyList()));
        when(restClientMock.downloadTrustedReferences(any())).thenReturn(ResponseEntity.ok(Collections.emptyList()));

        Assertions.assertEquals(0, connector.getTrustedCertificates().size());
        Assertions.assertNotNull(connector.getLastUpdated());
    }

    @Test
    void shouldReturnEmptyListWhenTrustedCertificateDownloadFails() {
        when(restClientMock.downloadTrustedCertificates(any()))
            .thenReturn(ResponseEntity.status(500).build());

        Assertions.assertTrue(connector.getTrustedCertificates().isEmpty());

        doThrow(new FeignException.InternalServerError("", dummyRequest(), null, null))
            .when(restClientMock).downloadTrustedCertificates(any());

        when(restClientMock.downloadTrustedIssuers(any())).thenReturn(ResponseEntity.ok(Collections.emptyList()));
        when(restClientMock.downloadTrustedReferences(any())).thenReturn(ResponseEntity.ok(Collections.emptyList()));

        Assertions.assertTrue(connector.getTrustedCertificates().isEmpty());
    }

    @Test
    void testCscaCheckWithInvalidDscRawData() throws Exception {

        KeyPair keyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate csca = CertificateTestUtils.generateCertificate(keyPair, "EU", "CSCA");

        String cscaSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayload(certificateUtils.convertCertificate(csca))
            .buildAsString(true);

        TrustedCertificateTrustListDto cscaTrustListItem = new TrustedCertificateTrustListDto();
        cscaTrustListItem.setCountry("EU");
        cscaTrustListItem.setKid("KID_EU");
        cscaTrustListItem.setGroup("CSCA");
        cscaTrustListItem.setSignature(cscaSignature);
        cscaTrustListItem.setCertificate(Base64.getEncoder().encodeToString(csca.getEncoded()));

        KeyPair keyPairUpload = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate upload = CertificateTestUtils.generateCertificate(keyPairUpload, "EU", "UPLOAD");

        String uploadSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayload(certificateUtils.convertCertificate(upload))
            .buildAsString(true);

        TrustedCertificateTrustListDto uploadTrustListItem = new TrustedCertificateTrustListDto();
        uploadTrustListItem.setCountry("EU");
        uploadTrustListItem.setKid("KID_EU_UPLOAD");
        uploadTrustListItem.setGroup("UPLOAD");
        uploadTrustListItem.setSignature(uploadSignature);
        uploadTrustListItem.setCertificate(Base64.getEncoder().encodeToString(upload.getEncoded()));

        KeyPair keyPairDsc = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate dsc = CertificateTestUtils.generateCertificate(keyPairDsc, "EU", "DSC", csca, keyPair.getPrivate());

        String dscSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(upload), keyPairUpload.getPrivate())
            .withPayload(certificateUtils.convertCertificate(dsc))
            .buildAsString(true);

        TrustedCertificateTrustListDto dscTrustListItem = new TrustedCertificateTrustListDto();
        dscTrustListItem.setCountry("EU");
        dscTrustListItem.setKid("KID_EU_DSC");
        dscTrustListItem.setGroup("DSC");
        dscTrustListItem.setSignature(dscSignature);
        dscTrustListItem.setCertificate(Base64.getEncoder().encodeToString(new byte[]{}));

        when(restClientMock.downloadTrustedCertificates(any())).thenAnswer(call -> {
            Map<String, String> queryParameter = call.getArgument(0, Map.class);

            if (queryParameter.containsKey("group")) {
                if (queryParameter.get("group").equalsIgnoreCase("CSCA")) {
                    return ResponseEntity.ok(Collections.singletonList(cscaTrustListItem));
                } else if (queryParameter.get("group").equalsIgnoreCase("DSC")) {
                    return ResponseEntity.ok(Collections.singletonList(dscTrustListItem));
                } else if (queryParameter.get("group").equalsIgnoreCase("UPLOAD")) {
                    return ResponseEntity.ok(Collections.singletonList(uploadTrustListItem));
                }
            }
            return null;
        });

        when(restClientMock.downloadTrustedIssuers(any())).thenReturn(ResponseEntity.ok(Collections.emptyList()));
        when(restClientMock.downloadTrustedReferences(any())).thenReturn(ResponseEntity.ok(Collections.emptyList()));


        List<TrustListItem> result = connector.getTrustedCertificates();
        Assertions.assertTrue(result.isEmpty());

        log.info("Trusted Certs: {}", connector.getTrustedCertificates());
        Assertions.assertNotNull(connector.getLastUpdated());
    }

    @Test
    void testTrustAnchorCheckInvalidSignatureFormat() throws Exception {

        KeyPair keyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate csca = CertificateTestUtils.generateCertificate(keyPair, "EU", "CSCA");

        TrustedCertificateTrustListDto cscaTrustListItem = new TrustedCertificateTrustListDto();
        cscaTrustListItem.setCountry("EU");
        cscaTrustListItem.setKid("KID_EU");
        cscaTrustListItem.setGroup("CSCA");
        cscaTrustListItem.setSignature("BADSIGNATURE");
        cscaTrustListItem.setCertificate(Base64.getEncoder().encodeToString(csca.getEncoded()));

        KeyPair keyPairUpload = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate upload = CertificateTestUtils.generateCertificate(keyPairUpload, "EU", "UPLOAD");

        String uploadSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayload(certificateUtils.convertCertificate(upload))
            .buildAsString(true);

        TrustedCertificateTrustListDto uploadTrustListItem = new TrustedCertificateTrustListDto();
        uploadTrustListItem.setCountry("EU");
        uploadTrustListItem.setKid("KID_EU_UPLOAD");
        uploadTrustListItem.setGroup("UPLOAD");
        uploadTrustListItem.setSignature(uploadSignature);
        uploadTrustListItem.setCertificate(Base64.getEncoder().encodeToString(upload.getEncoded()));

        KeyPair keyPairDsc = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate dsc = CertificateTestUtils.generateCertificate(keyPairDsc, "EU", "DSC", csca, keyPair.getPrivate());

        String dscSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(upload), keyPairUpload.getPrivate())
            .withPayload(certificateUtils.convertCertificate(dsc))
            .buildAsString(true);

        TrustedCertificateTrustListDto dscTrustListItem = new TrustedCertificateTrustListDto();
        dscTrustListItem.setCountry("EU");
        dscTrustListItem.setKid("KID_EU_DSC");
        dscTrustListItem.setGroup("DSC");
        dscTrustListItem.setSignature(dscSignature);
        dscTrustListItem.setCertificate(Base64.getEncoder().encodeToString(dsc.getEncoded()));

        when(restClientMock.downloadTrustedCertificates(any())).thenAnswer(call -> {
            Map<String, String> queryParameter = call.getArgument(0, Map.class);

            if (queryParameter.containsKey("group")) {
                if (queryParameter.get("group").equalsIgnoreCase("CSCA")) {
                    return ResponseEntity.ok(Collections.singletonList(cscaTrustListItem));
                } else if (queryParameter.get("group").equalsIgnoreCase("DSC")) {
                    return ResponseEntity.ok(Collections.singletonList(dscTrustListItem));
                } else if (queryParameter.get("group").equalsIgnoreCase("UPLOAD")) {
                    return ResponseEntity.ok(Collections.singletonList(uploadTrustListItem));
                }
            }
            return null;
        });
        when(restClientMock.downloadTrustedIssuers(any())).thenReturn(ResponseEntity.ok(Collections.emptyList()));
        when(restClientMock.downloadTrustedReferences(any())).thenReturn(ResponseEntity.ok(Collections.emptyList()));

        Assertions.assertEquals(0, connector.getTrustedCertificates().size());
        Assertions.assertNotNull(connector.getLastUpdated());
    }

    @Test
    void testTrustAnchorCheckWrongSignature() throws Exception {

        KeyPair cscaKayPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate csca = CertificateTestUtils.generateCertificate(cscaKayPair, "EU", "CSCA");

        KeyPair keyPairUpload = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate upload = CertificateTestUtils.generateCertificate(keyPairUpload, "EU", "UPLOAD");

        String uploadSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayload(certificateUtils.convertCertificate(upload))
            .buildAsString(true);

        TrustedCertificateTrustListDto cscaTrustListItem = new TrustedCertificateTrustListDto();
        cscaTrustListItem.setCountry("EU");
        cscaTrustListItem.setKid("KID_EU");
        cscaTrustListItem.setGroup("CSCA");
        cscaTrustListItem.setSignature(uploadSignature);
        cscaTrustListItem.setCertificate(Base64.getEncoder().encodeToString(csca.getEncoded()));

        TrustedCertificateTrustListDto uploadTrustListItem = new TrustedCertificateTrustListDto();
        uploadTrustListItem.setCountry("EU");
        uploadTrustListItem.setKid("KID_EU_UPLOAD");
        uploadTrustListItem.setGroup("UPLOAD");
        uploadTrustListItem.setSignature(uploadSignature);
        uploadTrustListItem.setCertificate(Base64.getEncoder().encodeToString(upload.getEncoded()));

        KeyPair keyPairDsc = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate dsc = CertificateTestUtils.generateCertificate(keyPairDsc, "EU", "DSC", csca, cscaKayPair.getPrivate());

        String dscSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(upload), keyPairUpload.getPrivate())
            .withPayload(certificateUtils.convertCertificate(dsc))
            .buildAsString(true);

        TrustedCertificateTrustListDto dscTrustListItem = new TrustedCertificateTrustListDto();
        dscTrustListItem.setCountry("EU");
        dscTrustListItem.setKid("KID_EU_DSC");
        dscTrustListItem.setGroup("DSC");
        dscTrustListItem.setSignature(dscSignature);
        dscTrustListItem.setCertificate(Base64.getEncoder().encodeToString(dsc.getEncoded()));

        when(restClientMock.downloadTrustedCertificates(any())).thenAnswer(call -> {
            Map<String, String> queryParameter = call.getArgument(0, Map.class);

            if (queryParameter.containsKey("group")) {
                if (queryParameter.get("group").equalsIgnoreCase("CSCA")) {
                    return ResponseEntity.ok(Collections.singletonList(cscaTrustListItem));
                } else if (queryParameter.get("group").equalsIgnoreCase("DSC")) {
                    return ResponseEntity.ok(Collections.singletonList(dscTrustListItem));
                } else if (queryParameter.get("group").equalsIgnoreCase("UPLOAD")) {
                    return ResponseEntity.ok(Collections.singletonList(uploadTrustListItem));
                }
            }
            return null;
        });

        when(restClientMock.downloadTrustedIssuers(any())).thenReturn(ResponseEntity.ok(Collections.emptyList()));
        when(restClientMock.downloadTrustedReferences(any())).thenReturn(ResponseEntity.ok(Collections.emptyList()));

        Assertions.assertEquals(0, connector.getTrustedCertificates().size());
        Assertions.assertNotNull(connector.getLastUpdated());
    }

    @Test
    void testDownloadOfTrustedIssuers() throws Exception {

        TrustedIssuerDto trustedIssuerDto = new TrustedIssuerDto();
        trustedIssuerDto.setCountry("EU");
        trustedIssuerDto.setType(TrustedIssuerDto.UrlTypeDto.HTTP);
        trustedIssuerDto.setUrl("hhtps://gateway.test");

        String issuerSignature = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayload(getHashData(trustedIssuerDto))
            .buildAsString(true);
        trustedIssuerDto.setSignature(issuerSignature);

        when(restClientMock.downloadTrustedCertificates(any())).thenReturn(
            ResponseEntity.ok(Collections.emptyList()));

        when(restClientMock.downloadTrustedIssuers(any()))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(trustedIssuerDto)));
        when(restClientMock.downloadTrustedReferences(any())).thenReturn(ResponseEntity.ok(Collections.emptyList()));

        List<TrustedIssuer> trustedIssuers = connector.getTrustedIssuers();
        Assertions.assertEquals(1, trustedIssuers.size());
    }

    @Test
    void testDownloadOfTrustedReferences() {

        TrustedReferenceDto trustedReferenceDto = new TrustedReferenceDto();
        trustedReferenceDto.setCountry("EU");
        trustedReferenceDto.setUuid(UUID.randomUUID().toString());
        trustedReferenceDto.setReferenceVersion("1.0");
        trustedReferenceDto.setName("RefName");
        trustedReferenceDto.setType(TrustedReferenceDto.ReferenceTypeDto.DCC);
        trustedReferenceDto.setService("RefService");

        when(restClientMock.downloadTrustedCertificates(any())).thenReturn(
            ResponseEntity.ok(Collections.emptyList()));

        when(restClientMock.downloadTrustedIssuers(any())).thenReturn(ResponseEntity.ok(Collections.emptyList()));
        when(restClientMock.downloadTrustedReferences(any())).thenReturn(ResponseEntity.ok(Collections.singletonList(trustedReferenceDto)));

        List<TrustedReference> trustedReferences = connector.getTrustedReferences();
        Assertions.assertEquals(1, trustedReferences.size());
    }

    @Test
    void testDownloadOfTrustedReferencesWithEmptyQueryParams() {

        ArgumentCaptor<HashMap<String, String>> captorReferences = ArgumentCaptor.forClass(HashMap.class);

        when(restClientMock.downloadTrustedCertificates(any())).thenReturn(
            ResponseEntity.ok(Collections.emptyList()));
        when(restClientMock.downloadTrustedIssuers(any()))
            .thenReturn(ResponseEntity.ok(Collections.emptyList()));
        when(restClientMock.downloadTrustedReferences(captorReferences.capture()))
            .thenReturn(ResponseEntity.ok(Collections.emptyList()));

        connector.getTrustedReferences();

        Assertions.assertEquals(0, captorReferences.getValue().size());
    }

    @Test
    void testDownloadOfTrustedReferencesWithQueryParams() {

        ArgumentCaptor<HashMap<String, String>> captorReferences = ArgumentCaptor.forClass(HashMap.class);

        when(restClientMock.downloadTrustedCertificates(any())).thenReturn(
            ResponseEntity.ok(Collections.emptyList()));
        when(restClientMock.downloadTrustedIssuers(any()))
            .thenReturn(ResponseEntity.ok(Collections.emptyList()));
        when(restClientMock.downloadTrustedReferences(captorReferences.capture()))
            .thenReturn(ResponseEntity.ok(Collections.emptyList()));


        connector.setQueryParameter(QueryParameter.GROUP, "groupValue");
        connector.setQueryParameter(QueryParameter.DOMAIN, Arrays.asList("domainValue1", "domainValue2", "domainValue3"));
        connector.setQueryParameter(QueryParameter.WITH_FEDERATION, true);
        connector.getTrustedReferences();

        Assertions.assertEquals(3, captorReferences.getValue().size());
        Assertions.assertEquals("groupValue", captorReferences.getValue().get("group"));
        Assertions.assertEquals("domainValue1,domainValue2,domainValue3", captorReferences.getValue().get("domain"));
        Assertions.assertEquals("true", captorReferences.getValue().get("withFederation"));
    }

    @Test
    void testDownloadOfTrustedIssuersWithEmptyQueryParams() {

        ArgumentCaptor<HashMap<String, String>> captorIssuers = ArgumentCaptor.forClass(HashMap.class);

        when(restClientMock.downloadTrustedCertificates(any())).thenReturn(
            ResponseEntity.ok(Collections.emptyList()));
        when(restClientMock.downloadTrustedIssuers(captorIssuers.capture()))
            .thenReturn(ResponseEntity.ok(Collections.emptyList()));
        when(restClientMock.downloadTrustedReferences(any()))
            .thenReturn(ResponseEntity.ok(Collections.emptyList()));

        connector.getTrustedIssuers();

        Assertions.assertEquals(0, captorIssuers.getValue().size());
    }

    @Test
    void testDownloadOfTrustedIssuersWithQueryParams() {

        ArgumentCaptor<HashMap<String, String>> captorIssuers = ArgumentCaptor.forClass(HashMap.class);

        when(restClientMock.downloadTrustedCertificates(any())).thenReturn(
            ResponseEntity.ok(Collections.emptyList()));
        when(restClientMock.downloadTrustedIssuers(captorIssuers.capture()))
            .thenReturn(ResponseEntity.ok(Collections.emptyList()));
        when(restClientMock.downloadTrustedReferences(any()))
            .thenReturn(ResponseEntity.ok(Collections.emptyList()));


        connector.setQueryParameter(QueryParameter.GROUP, "groupValue");
        connector.setQueryParameter(QueryParameter.DOMAIN, Arrays.asList("domainValue1", "domainValue2", "domainValue3"));
        connector.setQueryParameter(QueryParameter.WITH_FEDERATION, true);
        connector.getTrustedReferences();

        Assertions.assertEquals(3, captorIssuers.getValue().size());
        Assertions.assertEquals("groupValue", captorIssuers.getValue().get("group"));
        Assertions.assertEquals("domainValue1,domainValue2,domainValue3", captorIssuers.getValue().get("domain"));
        Assertions.assertEquals("true", captorIssuers.getValue().get("withFederation"));
    }

    /**
     * Method to create dummy request which is required to throw FeignExceptions.
     */
    private Request dummyRequest() {
        return Request.create(Request.HttpMethod.GET, "url", new HashMap<>(), null, new RequestTemplate());
    }

    private String getHashData(TrustedIssuerDto trustedIssuerDto) {
        return trustedIssuerDto.getCountry() + ";"
            + trustedIssuerDto.getUrl() + ";"
            + trustedIssuerDto.getType().name() + ";";
    }

}
