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
import eu.europa.ec.dgc.gateway.connector.dto.CertificateTypeDto;
import eu.europa.ec.dgc.gateway.connector.dto.TrustListItemDto;
import eu.europa.ec.dgc.gateway.connector.model.TrustListItem;
import eu.europa.ec.dgc.signing.SignedCertificateMessageBuilder;
import eu.europa.ec.dgc.testdata.CertificateTestUtils;
import eu.europa.ec.dgc.testdata.DgcTestKeyStore;
import eu.europa.ec.dgc.utils.CertificateUtils;
import feign.FeignException;
import feign.Request;
import feign.RequestTemplate;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.ResponseEntity;

@SpringBootTest
@Slf4j
class DownloadConnectorTest {

    @MockBean
    DgcGatewayConnectorRestClient restClientMock;

    @Autowired
    DgcGatewayDownloadConnector connector;

    @Autowired
    CertificateUtils certificateUtils;

    @Autowired
    DgcTestKeyStore testKeyStore;

    @Test
    void testDownloadOfCertificates() throws Exception {

        KeyPair keyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate csca = CertificateTestUtils.generateCertificate(keyPair, "EU", "CSCA");

        String cscaSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayloadCertificate(certificateUtils.convertCertificate(csca))
            .buildAsString(true);

        TrustListItemDto cscaTrustListItem = new TrustListItemDto();
        cscaTrustListItem.setCountry("EU");
        cscaTrustListItem.setKid("KID_EU");
        cscaTrustListItem.setCertificateType(CertificateTypeDto.CSCA);
        cscaTrustListItem.setTimestamp(ZonedDateTime.now());
        cscaTrustListItem.setSignature(cscaSignature);
        cscaTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(csca));
        cscaTrustListItem.setRawData(Base64.getEncoder().encodeToString(csca.getEncoded()));

        KeyPair keyPairUpload = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate upload = CertificateTestUtils.generateCertificate(keyPairUpload, "EU", "UPLOAD");

        String uploadSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayloadCertificate(certificateUtils.convertCertificate(upload))
            .buildAsString(true);

        TrustListItemDto uploadTrustListItem = new TrustListItemDto();
        uploadTrustListItem.setCountry("EU");
        uploadTrustListItem.setKid("KID_EU_UPLOAD");
        uploadTrustListItem.setCertificateType(CertificateTypeDto.UPLOAD);
        uploadTrustListItem.setTimestamp(ZonedDateTime.now());
        uploadTrustListItem.setSignature(uploadSignature);
        uploadTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(upload));
        uploadTrustListItem.setRawData(Base64.getEncoder().encodeToString(upload.getEncoded()));

        KeyPair keyPairDsc = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate dsc = CertificateTestUtils.generateCertificate(keyPairDsc, "EU", "DSC", csca, keyPair.getPrivate());

        String dscSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(upload), keyPairUpload.getPrivate())
            .withPayloadCertificate(certificateUtils.convertCertificate(dsc))
            .buildAsString(true);

        TrustListItemDto dscTrustListItem = new TrustListItemDto();
        dscTrustListItem.setCountry("EU");
        dscTrustListItem.setKid("KID_EU_DSC");
        dscTrustListItem.setCertificateType(CertificateTypeDto.DSC);
        dscTrustListItem.setTimestamp(ZonedDateTime.now());
        dscTrustListItem.setSignature(dscSignature);
        dscTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(dsc));
        dscTrustListItem.setRawData(Base64.getEncoder().encodeToString(dsc.getEncoded()));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.CSCA))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(cscaTrustListItem)));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.DSC))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(dscTrustListItem)));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.UPLOAD))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(uploadTrustListItem)));


        List<TrustListItem> result = connector.getTrustedCertificates();
        Assertions.assertEquals(1, result.size());

        Assertions.assertEquals(dscTrustListItem.getRawData(), result.get(0).getRawData());
        Assertions.assertEquals(dscTrustListItem.getKid(), result.get(0).getKid());
        Assertions.assertEquals(dscTrustListItem.getTimestamp(), result.get(0).getTimestamp());
        log.info("Trusted Certs: {}", connector.getTrustedCertificates());
        Assertions.assertNotNull(connector.getLastUpdated());
    }

    @Test
    void testThumbprintIntegrityCheck() throws Exception {

        KeyPair keyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate csca = CertificateTestUtils.generateCertificate(keyPair, "EU", "CSCA");

        String cscaSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayloadCertificate(certificateUtils.convertCertificate(csca))
            .buildAsString(true);

        TrustListItemDto cscaTrustListItem = new TrustListItemDto();
        cscaTrustListItem.setCountry("EU");
        cscaTrustListItem.setKid("KID_EU");
        cscaTrustListItem.setCertificateType(CertificateTypeDto.CSCA);
        cscaTrustListItem.setTimestamp(ZonedDateTime.now());
        cscaTrustListItem.setSignature(cscaSignature);
        cscaTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(csca));
        cscaTrustListItem.setRawData(Base64.getEncoder().encodeToString(csca.getEncoded()));

        KeyPair keyPairUpload = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate upload = CertificateTestUtils.generateCertificate(keyPairUpload, "EU", "UPLOAD");

        String uploadSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayloadCertificate(certificateUtils.convertCertificate(upload))
            .buildAsString(true);

        TrustListItemDto uploadTrustListItem = new TrustListItemDto();
        uploadTrustListItem.setCountry("EU");
        uploadTrustListItem.setKid("KID_EU_UPLOAD");
        uploadTrustListItem.setCertificateType(CertificateTypeDto.UPLOAD);
        uploadTrustListItem.setTimestamp(ZonedDateTime.now());
        uploadTrustListItem.setSignature(uploadSignature);
        // set thumbprint from csca cert
        uploadTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(csca));
        uploadTrustListItem.setRawData(Base64.getEncoder().encodeToString(upload.getEncoded()));

        KeyPair keyPairDsc = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate dsc = CertificateTestUtils.generateCertificate(keyPairDsc, "EU", "DSC", csca, keyPair.getPrivate());

        String dscSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(upload), keyPairUpload.getPrivate())
            .withPayloadCertificate(certificateUtils.convertCertificate(dsc))
            .buildAsString(true);

        TrustListItemDto dscTrustListItem = new TrustListItemDto();
        dscTrustListItem.setCountry("EU");
        dscTrustListItem.setKid("KID_EU_DSC");
        dscTrustListItem.setCertificateType(CertificateTypeDto.DSC);
        dscTrustListItem.setTimestamp(ZonedDateTime.now());
        dscTrustListItem.setSignature(dscSignature);
        dscTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(dsc));
        dscTrustListItem.setRawData(Base64.getEncoder().encodeToString(dsc.getEncoded()));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.CSCA))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(cscaTrustListItem)));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.DSC))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(dscTrustListItem)));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.UPLOAD))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(uploadTrustListItem)));


        List<TrustListItem> result = connector.getTrustedCertificates();
        Assertions.assertTrue(result.isEmpty());

        log.info("Trusted Certs: {}", connector.getTrustedCertificates());
        Assertions.assertNotNull(connector.getLastUpdated());
    }


    @Test
    void testThumbprintIntegrityCheckInvalidRawData() throws Exception {

        KeyPair keyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate csca = CertificateTestUtils.generateCertificate(keyPair, "EU", "CSCA");

        String cscaSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayloadCertificate(certificateUtils.convertCertificate(csca))
            .buildAsString(true);

        TrustListItemDto cscaTrustListItem = new TrustListItemDto();
        cscaTrustListItem.setCountry("EU");
        cscaTrustListItem.setKid("KID_EU");
        cscaTrustListItem.setCertificateType(CertificateTypeDto.CSCA);
        cscaTrustListItem.setTimestamp(ZonedDateTime.now());
        cscaTrustListItem.setSignature(cscaSignature);
        cscaTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(csca));
        cscaTrustListItem.setRawData(Base64.getEncoder().encodeToString(csca.getEncoded()));

        KeyPair keyPairUpload = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate upload = CertificateTestUtils.generateCertificate(keyPairUpload, "EU", "UPLOAD");

        String uploadSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayloadCertificate(certificateUtils.convertCertificate(upload))
            .buildAsString(true);

        TrustListItemDto uploadTrustListItem = new TrustListItemDto();
        uploadTrustListItem.setCountry("EU");
        uploadTrustListItem.setKid("KID_EU_UPLOAD");
        uploadTrustListItem.setCertificateType(CertificateTypeDto.UPLOAD);
        uploadTrustListItem.setTimestamp(ZonedDateTime.now());
        uploadTrustListItem.setSignature(uploadSignature);
        uploadTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(upload));
        uploadTrustListItem.setRawData(Base64.getEncoder().encodeToString(new byte[]{}));

        KeyPair keyPairDsc = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate dsc = CertificateTestUtils.generateCertificate(keyPairDsc, "EU", "DSC", csca, keyPair.getPrivate());

        String dscSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(upload), keyPairUpload.getPrivate())
            .withPayloadCertificate(certificateUtils.convertCertificate(dsc))
            .buildAsString(true);

        TrustListItemDto dscTrustListItem = new TrustListItemDto();
        dscTrustListItem.setCountry("EU");
        dscTrustListItem.setKid("KID_EU_DSC");
        dscTrustListItem.setCertificateType(CertificateTypeDto.DSC);
        dscTrustListItem.setTimestamp(ZonedDateTime.now());
        dscTrustListItem.setSignature(dscSignature);
        dscTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(dsc));
        dscTrustListItem.setRawData(Base64.getEncoder().encodeToString(dsc.getEncoded()));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.CSCA))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(cscaTrustListItem)));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.DSC))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(dscTrustListItem)));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.UPLOAD))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(uploadTrustListItem)));


        List<TrustListItem> result = connector.getTrustedCertificates();
        Assertions.assertTrue(result.isEmpty());

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
            .withPayloadCertificate(certificateUtils.convertCertificate(csca))
            .buildAsString(true);

        TrustListItemDto cscaTrustListItem = new TrustListItemDto();
        cscaTrustListItem.setCountry("EU");
        cscaTrustListItem.setKid("KID_EU");
        cscaTrustListItem.setCertificateType(CertificateTypeDto.CSCA);
        cscaTrustListItem.setTimestamp(ZonedDateTime.now());
        cscaTrustListItem.setSignature(cscaSignature);
        cscaTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(csca));
        cscaTrustListItem.setRawData(Base64.getEncoder().encodeToString(csca.getEncoded()));

        KeyPair keyPairUpload = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate upload = CertificateTestUtils.generateCertificate(keyPairUpload, "EU", "UPLOAD");

        String uploadSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayloadCertificate(certificateUtils.convertCertificate(upload))
            .buildAsString(true);

        TrustListItemDto uploadTrustListItem = new TrustListItemDto();
        uploadTrustListItem.setCountry("EU");
        uploadTrustListItem.setKid("KID_EU_UPLOAD");
        uploadTrustListItem.setCertificateType(CertificateTypeDto.UPLOAD);
        uploadTrustListItem.setTimestamp(ZonedDateTime.now());
        uploadTrustListItem.setSignature(uploadSignature);
        uploadTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(upload));
        uploadTrustListItem.setRawData(Base64.getEncoder().encodeToString(upload.getEncoded()));

        KeyPair keyPairDsc = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate dsc = CertificateTestUtils.generateCertificate(keyPairDsc, "EU", "DSC", csca, cscaKayPair.getPrivate());

        String dscSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayloadCertificate(certificateUtils.convertCertificate(dsc))
            .buildAsString(true);

        TrustListItemDto dscTrustListItem = new TrustListItemDto();
        dscTrustListItem.setCountry("EU");
        dscTrustListItem.setKid("KID_EU_DSC");
        dscTrustListItem.setCertificateType(CertificateTypeDto.DSC);
        dscTrustListItem.setTimestamp(ZonedDateTime.now());
        dscTrustListItem.setSignature(dscSignature);
        dscTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(dsc));
        dscTrustListItem.setRawData(Base64.getEncoder().encodeToString(dsc.getEncoded()));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.CSCA))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(cscaTrustListItem)));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.DSC))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(dscTrustListItem)));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.UPLOAD))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(uploadTrustListItem)));

        Assertions.assertEquals(0, connector.getTrustedCertificates().size());
        Assertions.assertNotNull(connector.getLastUpdated());
    }

    @Test
    void testDownloadOfCertificatesShouldFailWrongTrustAnchorSignatureForUpload() throws Exception {

        KeyPair cscaKayPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate csca = CertificateTestUtils.generateCertificate(cscaKayPair, "EU", "CSCA");

        String cscaSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayloadCertificate(certificateUtils.convertCertificate(csca))
            .buildAsString(true);

        TrustListItemDto cscaTrustListItem = new TrustListItemDto();
        cscaTrustListItem.setCountry("EU");
        cscaTrustListItem.setKid("KID_EU");
        cscaTrustListItem.setCertificateType(CertificateTypeDto.CSCA);
        cscaTrustListItem.setTimestamp(ZonedDateTime.now());
        cscaTrustListItem.setSignature(cscaSignature);
        cscaTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(csca));
        cscaTrustListItem.setRawData(Base64.getEncoder().encodeToString(csca.getEncoded()));

        KeyPair fakeTrustAnchorKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate fakeTrustAnchor = CertificateTestUtils.generateCertificate(fakeTrustAnchorKeyPair, "EU", "TA");

        KeyPair keyPairUpload = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate upload = CertificateTestUtils.generateCertificate(keyPairUpload, "EU", "UPLOAD");

        String uploadSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(fakeTrustAnchor), fakeTrustAnchorKeyPair.getPrivate())
            .withPayloadCertificate(certificateUtils.convertCertificate(upload))
            .buildAsString(true);

        TrustListItemDto uploadTrustListItem = new TrustListItemDto();
        uploadTrustListItem.setCountry("EU");
        uploadTrustListItem.setKid("KID_EU_UPLOAD");
        uploadTrustListItem.setCertificateType(CertificateTypeDto.UPLOAD);
        uploadTrustListItem.setTimestamp(ZonedDateTime.now());
        uploadTrustListItem.setSignature(uploadSignature);
        uploadTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(upload));
        uploadTrustListItem.setRawData(Base64.getEncoder().encodeToString(upload.getEncoded()));

        KeyPair keyPairDsc = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate dsc = CertificateTestUtils.generateCertificate(keyPairDsc, "EU", "DSC", csca, cscaKayPair.getPrivate());

        String dscSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayloadCertificate(certificateUtils.convertCertificate(dsc))
            .buildAsString(true);

        TrustListItemDto dscTrustListItem = new TrustListItemDto();
        dscTrustListItem.setCountry("EU");
        dscTrustListItem.setKid("KID_EU_DSC");
        dscTrustListItem.setCertificateType(CertificateTypeDto.DSC);
        dscTrustListItem.setTimestamp(ZonedDateTime.now());
        dscTrustListItem.setSignature(dscSignature);
        dscTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(dsc));
        dscTrustListItem.setRawData(Base64.getEncoder().encodeToString(dsc.getEncoded()));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.CSCA))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(cscaTrustListItem)));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.DSC))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(dscTrustListItem)));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.UPLOAD))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(uploadTrustListItem)));

        Assertions.assertEquals(0, connector.getTrustedCertificates().size());
        Assertions.assertNotNull(connector.getLastUpdated());
    }

    @Test
    void shouldThrowExceptionOnInitWhenNoTrustAnchorIsPresent() {

        X509Certificate trustAnchorBackup = testKeyStore.getTrustAnchor();
        testKeyStore.setTrustAnchor(null);

        Assertions.assertThrows(KeyStoreException.class, connector::init);

        testKeyStore.setTrustAnchor(trustAnchorBackup);
    }

    @Test
    void shouldReturnEmptyListWhenCscaDownloadFails() {
        when(restClientMock.getTrustedCertificates(CertificateTypeDto.CSCA))
            .thenReturn(ResponseEntity.status(500).build());

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.DSC))
            .thenReturn(ResponseEntity.ok(Collections.emptyList()));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.UPLOAD))
            .thenReturn(ResponseEntity.ok(Collections.emptyList()));

        Assertions.assertTrue(connector.getTrustedCertificates().isEmpty());

        doThrow(new FeignException.InternalServerError("", dummyRequest(), null))
            .when(restClientMock).getTrustedCertificates(CertificateTypeDto.CSCA);

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.DSC))
            .thenReturn(ResponseEntity.ok(Collections.emptyList()));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.UPLOAD))
            .thenReturn(ResponseEntity.ok(Collections.emptyList()));

        Assertions.assertTrue(connector.getTrustedCertificates().isEmpty());
    }

    @Test
    void shouldReturnEmptyListWhenUploadCertDownloadFails() {
        when(restClientMock.getTrustedCertificates(CertificateTypeDto.CSCA))
            .thenReturn(ResponseEntity.ok(Collections.emptyList()));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.DSC))
            .thenReturn(ResponseEntity.ok(Collections.emptyList()));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.UPLOAD))
            .thenReturn(ResponseEntity.status(500).build());

        Assertions.assertTrue(connector.getTrustedCertificates().isEmpty());

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.CSCA))
            .thenReturn(ResponseEntity.ok(Collections.emptyList()));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.DSC))
            .thenReturn(ResponseEntity.ok(Collections.emptyList()));

        doThrow(new FeignException.InternalServerError("", dummyRequest(), null))
            .when(restClientMock).getTrustedCertificates(CertificateTypeDto.UPLOAD);

        Assertions.assertTrue(connector.getTrustedCertificates().isEmpty());
    }

    @Test
    void shouldReturnEmptyListWhenDscDownloadFails() {
        when(restClientMock.getTrustedCertificates(CertificateTypeDto.CSCA))
            .thenReturn(ResponseEntity.ok(Collections.emptyList()));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.DSC))
            .thenReturn(ResponseEntity.status(500).build());

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.UPLOAD))
            .thenReturn(ResponseEntity.ok(Collections.emptyList()));

        Assertions.assertTrue(connector.getTrustedCertificates().isEmpty());

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.CSCA))
            .thenReturn(ResponseEntity.ok(Collections.emptyList()));

        doThrow(new FeignException.InternalServerError("", dummyRequest(), null))
            .when(restClientMock).getTrustedCertificates(CertificateTypeDto.DSC);

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.UPLOAD))
            .thenReturn(ResponseEntity.ok(Collections.emptyList()));

        Assertions.assertTrue(connector.getTrustedCertificates().isEmpty());
    }

    @Test
    void testCscaCheckWithInvalidDscRawData() throws Exception {

        KeyPair keyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate csca = CertificateTestUtils.generateCertificate(keyPair, "EU", "CSCA");

        String cscaSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayloadCertificate(certificateUtils.convertCertificate(csca))
            .buildAsString(true);

        TrustListItemDto cscaTrustListItem = new TrustListItemDto();
        cscaTrustListItem.setCountry("EU");
        cscaTrustListItem.setKid("KID_EU");
        cscaTrustListItem.setCertificateType(CertificateTypeDto.CSCA);
        cscaTrustListItem.setTimestamp(ZonedDateTime.now());
        cscaTrustListItem.setSignature(cscaSignature);
        cscaTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(csca));
        cscaTrustListItem.setRawData(Base64.getEncoder().encodeToString(csca.getEncoded()));

        KeyPair keyPairUpload = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate upload = CertificateTestUtils.generateCertificate(keyPairUpload, "EU", "UPLOAD");

        String uploadSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayloadCertificate(certificateUtils.convertCertificate(upload))
            .buildAsString(true);

        TrustListItemDto uploadTrustListItem = new TrustListItemDto();
        uploadTrustListItem.setCountry("EU");
        uploadTrustListItem.setKid("KID_EU_UPLOAD");
        uploadTrustListItem.setCertificateType(CertificateTypeDto.UPLOAD);
        uploadTrustListItem.setTimestamp(ZonedDateTime.now());
        uploadTrustListItem.setSignature(uploadSignature);
        uploadTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(upload));
        uploadTrustListItem.setRawData(Base64.getEncoder().encodeToString(upload.getEncoded()));

        KeyPair keyPairDsc = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate dsc = CertificateTestUtils.generateCertificate(keyPairDsc, "EU", "DSC", csca, keyPair.getPrivate());

        String dscSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(upload), keyPairUpload.getPrivate())
            .withPayloadCertificate(certificateUtils.convertCertificate(dsc))
            .buildAsString(true);

        TrustListItemDto dscTrustListItem = new TrustListItemDto();
        dscTrustListItem.setCountry("EU");
        dscTrustListItem.setKid("KID_EU_DSC");
        dscTrustListItem.setCertificateType(CertificateTypeDto.DSC);
        dscTrustListItem.setTimestamp(ZonedDateTime.now());
        dscTrustListItem.setSignature(dscSignature);
        dscTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(dsc));
        dscTrustListItem.setRawData(Base64.getEncoder().encodeToString(new byte[]{}));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.CSCA))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(cscaTrustListItem)));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.DSC))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(dscTrustListItem)));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.UPLOAD))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(uploadTrustListItem)));


        List<TrustListItem> result = connector.getTrustedCertificates();
        Assertions.assertTrue(result.isEmpty());

        log.info("Trusted Certs: {}", connector.getTrustedCertificates());
        Assertions.assertNotNull(connector.getLastUpdated());
    }

    @Test
    void testTrustAnchorCheckInvalidSignatureFormat() throws Exception {

        KeyPair cscaKayPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate csca = CertificateTestUtils.generateCertificate(cscaKayPair, "EU", "CSCA");

        TrustListItemDto cscaTrustListItem = new TrustListItemDto();
        cscaTrustListItem.setCountry("EU");
        cscaTrustListItem.setKid("KID_EU");
        cscaTrustListItem.setCertificateType(CertificateTypeDto.CSCA);
        cscaTrustListItem.setTimestamp(ZonedDateTime.now());
        cscaTrustListItem.setSignature("BADSIGNATURE");
        cscaTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(csca));
        cscaTrustListItem.setRawData(Base64.getEncoder().encodeToString(csca.getEncoded()));

        KeyPair keyPairUpload = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate upload = CertificateTestUtils.generateCertificate(keyPairUpload, "EU", "UPLOAD");

        String uploadSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayloadCertificate(certificateUtils.convertCertificate(upload))
            .buildAsString(true);

        TrustListItemDto uploadTrustListItem = new TrustListItemDto();
        uploadTrustListItem.setCountry("EU");
        uploadTrustListItem.setKid("KID_EU_UPLOAD");
        uploadTrustListItem.setCertificateType(CertificateTypeDto.UPLOAD);
        uploadTrustListItem.setTimestamp(ZonedDateTime.now());
        uploadTrustListItem.setSignature(uploadSignature);
        uploadTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(upload));
        uploadTrustListItem.setRawData(Base64.getEncoder().encodeToString(upload.getEncoded()));

        KeyPair keyPairDsc = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate dsc = CertificateTestUtils.generateCertificate(keyPairDsc, "EU", "DSC", csca, cscaKayPair.getPrivate());

        String dscSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayloadCertificate(certificateUtils.convertCertificate(dsc))
            .buildAsString(true);

        TrustListItemDto dscTrustListItem = new TrustListItemDto();
        dscTrustListItem.setCountry("EU");
        dscTrustListItem.setKid("KID_EU_DSC");
        dscTrustListItem.setCertificateType(CertificateTypeDto.DSC);
        dscTrustListItem.setTimestamp(ZonedDateTime.now());
        dscTrustListItem.setSignature(dscSignature);
        dscTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(dsc));
        dscTrustListItem.setRawData(Base64.getEncoder().encodeToString(dsc.getEncoded()));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.CSCA))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(cscaTrustListItem)));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.DSC))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(dscTrustListItem)));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.UPLOAD))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(uploadTrustListItem)));

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
            .withPayloadCertificate(certificateUtils.convertCertificate(upload))
            .buildAsString(true);

        TrustListItemDto cscaTrustListItem = new TrustListItemDto();
        cscaTrustListItem.setCountry("EU");
        cscaTrustListItem.setKid("KID_EU");
        cscaTrustListItem.setCertificateType(CertificateTypeDto.CSCA);
        cscaTrustListItem.setTimestamp(ZonedDateTime.now());
        cscaTrustListItem.setSignature(uploadSignature);
        cscaTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(csca));
        cscaTrustListItem.setRawData(Base64.getEncoder().encodeToString(csca.getEncoded()));

        TrustListItemDto uploadTrustListItem = new TrustListItemDto();
        uploadTrustListItem.setCountry("EU");
        uploadTrustListItem.setKid("KID_EU_UPLOAD");
        uploadTrustListItem.setCertificateType(CertificateTypeDto.UPLOAD);
        uploadTrustListItem.setTimestamp(ZonedDateTime.now());
        uploadTrustListItem.setSignature(uploadSignature);
        uploadTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(upload));
        uploadTrustListItem.setRawData(Base64.getEncoder().encodeToString(upload.getEncoded()));

        KeyPair keyPairDsc = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate dsc = CertificateTestUtils.generateCertificate(keyPairDsc, "EU", "DSC", csca, cscaKayPair.getPrivate());

        String dscSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayloadCertificate(certificateUtils.convertCertificate(dsc))
            .buildAsString(true);

        TrustListItemDto dscTrustListItem = new TrustListItemDto();
        dscTrustListItem.setCountry("EU");
        dscTrustListItem.setKid("KID_EU_DSC");
        dscTrustListItem.setCertificateType(CertificateTypeDto.DSC);
        dscTrustListItem.setTimestamp(ZonedDateTime.now());
        dscTrustListItem.setSignature(dscSignature);
        dscTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(dsc));
        dscTrustListItem.setRawData(Base64.getEncoder().encodeToString(dsc.getEncoded()));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.CSCA))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(cscaTrustListItem)));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.DSC))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(dscTrustListItem)));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.UPLOAD))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(uploadTrustListItem)));

        Assertions.assertEquals(0, connector.getTrustedCertificates().size());
        Assertions.assertNotNull(connector.getLastUpdated());
    }


    /**
     * Method to create dummy request which is required to throw FeignExceptions.
     */
    private Request dummyRequest() {
        return Request.create(Request.HttpMethod.GET, "url", new HashMap<>(), null, new RequestTemplate());
    }

}
