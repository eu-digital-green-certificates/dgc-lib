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
import eu.europa.ec.dgc.gateway.connector.dto.TrustListItemDto;
import eu.europa.ec.dgc.signing.SignedCertificateMessageBuilder;
import eu.europa.ec.dgc.testdata.CertificateTestUtils;
import eu.europa.ec.dgc.testdata.DgcTestKeyStore;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Collections;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

@SpringBootTest
@Slf4j
class DownloadConnectorUtilsTest {

    @MockBean
    DgcGatewayConnectorRestClient restClientMock;

    @Autowired
    DgcGatewayConnectorUtils connectorUtils;

    @Autowired
    DgcTestKeyStore testKeyStore;

    @Autowired
    CertificateUtils certificateUtils;

    @Test
    void shouldThrowExceptionOnInitWhenNoTrustAnchorIsPresent() {

        X509Certificate trustAnchorBackup = testKeyStore.getTrustAnchor();
        testKeyStore.setTrustAnchor(null);

        Assertions.assertThrows(KeyStoreException.class, connectorUtils::init);

        testKeyStore.setTrustAnchor(trustAnchorBackup);
    }

    @Test
    void testTrustListItemSignedByCa() throws Exception {

        KeyPair keyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate csca = CertificateTestUtils.generateCertificate(keyPair, "EU", "CSCA");

        KeyPair keyPairDsc = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate dsc = CertificateTestUtils.generateCertificate(keyPairDsc, "EU", "DSC", csca, keyPair.getPrivate());

        KeyPair keyPairUpload = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate upload = CertificateTestUtils.generateCertificate(keyPairUpload, "EU", "UPLOAD");

        String dscSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(upload), keyPairUpload.getPrivate())
            .withPayload(certificateUtils.convertCertificate(dsc))
            .buildAsString(true);

        TrustListItemDto dscTrustListItem = new TrustListItemDto();
        dscTrustListItem.setCountry("EU");
        dscTrustListItem.setKid("KID_EU_DSC");
        dscTrustListItem.setCertificateType(CertificateTypeDto.DSC);
        dscTrustListItem.setTimestamp(ZonedDateTime.now());
        dscTrustListItem.setSignature(dscSignature);
        dscTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(dsc));
        dscTrustListItem.setRawData(Base64.getEncoder().encodeToString(dsc.getEncoded()));

        Assertions.assertTrue(connectorUtils.trustListItemSignedByCa(dscTrustListItem, certificateUtils.convertCertificate(csca)));
    }

    @Test
    void testTrustListItemSignedByCaFailed() throws Exception {

        KeyPair keyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate csca = CertificateTestUtils.generateCertificate(keyPair, "EU", "CSCA");

        KeyPair keyPairUpload = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate upload = CertificateTestUtils.generateCertificate(keyPairUpload, "EU", "UPLOAD");

        // Sign DSC with Upload certificate
        KeyPair keyPairDsc = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate dsc = CertificateTestUtils.generateCertificate(keyPairDsc, "EU", "DSC", upload, keyPairUpload.getPrivate());

        String dscSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(upload), keyPairUpload.getPrivate())
            .withPayload(certificateUtils.convertCertificate(dsc))
            .buildAsString(true);

        TrustListItemDto dscTrustListItem = new TrustListItemDto();
        dscTrustListItem.setCountry("EU");
        dscTrustListItem.setKid("KID_EU_DSC");
        dscTrustListItem.setCertificateType(CertificateTypeDto.DSC);
        dscTrustListItem.setTimestamp(ZonedDateTime.now());
        dscTrustListItem.setSignature(dscSignature);
        dscTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(dsc));
        dscTrustListItem.setRawData(Base64.getEncoder().encodeToString(dsc.getEncoded()));

        Assertions.assertFalse(connectorUtils.trustListItemSignedByCa(dscTrustListItem, certificateUtils.convertCertificate(csca)));
    }

    @Test
    void testTrustListItemSignedByTrustAnchor() throws Exception {

        KeyPair keyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate csca = CertificateTestUtils.generateCertificate(keyPair, "EU", "CSCA");

        String cscaSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayload(certificateUtils.convertCertificate(csca))
            .buildAsString(true);

        TrustListItemDto cscaTrustListItem = new TrustListItemDto();
        cscaTrustListItem.setCountry("EU");
        cscaTrustListItem.setKid("KID_EU");
        cscaTrustListItem.setCertificateType(CertificateTypeDto.CSCA);
        cscaTrustListItem.setTimestamp(ZonedDateTime.now());
        cscaTrustListItem.setSignature(cscaSignature);
        cscaTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(csca));
        cscaTrustListItem.setRawData(Base64.getEncoder().encodeToString(csca.getEncoded()));

        Assertions.assertTrue(
            connectorUtils.checkTrustAnchorSignature(cscaTrustListItem,
                Collections.singletonList(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()))));
    }

    @Test
    void testTrustListItemSignedByTrustAnchorFailed() throws Exception {

        KeyPair keyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate csca = CertificateTestUtils.generateCertificate(keyPair, "EU", "CSCA");

        String cscaSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(csca), keyPair.getPrivate())
            .withPayload(certificateUtils.convertCertificate(csca))
            .buildAsString(true);

        TrustListItemDto cscaTrustListItem = new TrustListItemDto();
        cscaTrustListItem.setCountry("EU");
        cscaTrustListItem.setKid("KID_EU");
        cscaTrustListItem.setCertificateType(CertificateTypeDto.CSCA);
        cscaTrustListItem.setTimestamp(ZonedDateTime.now());
        cscaTrustListItem.setSignature(cscaSignature);
        cscaTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(csca));
        cscaTrustListItem.setRawData(Base64.getEncoder().encodeToString(csca.getEncoded()));

        Assertions.assertFalse(connectorUtils.checkTrustAnchorSignature(cscaTrustListItem,
            Collections.singletonList(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()))));
    }

    @Test
    void testGetCertificateFromTrustListItem() throws Exception {

        KeyPair keyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate csca = CertificateTestUtils.generateCertificate(keyPair, "EU", "CSCA");

        String cscaSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(csca), keyPair.getPrivate())
            .withPayload(certificateUtils.convertCertificate(csca))
            .buildAsString(true);

        TrustListItemDto cscaTrustListItem = new TrustListItemDto();
        cscaTrustListItem.setCountry("EU");
        cscaTrustListItem.setKid("KID_EU");
        cscaTrustListItem.setCertificateType(CertificateTypeDto.CSCA);
        cscaTrustListItem.setTimestamp(ZonedDateTime.now());
        cscaTrustListItem.setSignature(cscaSignature);
        cscaTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(csca));
        cscaTrustListItem.setRawData(Base64.getEncoder().encodeToString(csca.getEncoded()));

        Assertions.assertEquals(certificateUtils.convertCertificate(csca), connectorUtils.getCertificateFromTrustListItem(cscaTrustListItem));
    }

}
