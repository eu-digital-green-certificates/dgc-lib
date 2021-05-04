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
import eu.europa.ec.dgc.signing.SignedCertificateMessageParser;
import eu.europa.ec.dgc.testdata.CertificateTestUtils;
import eu.europa.ec.dgc.testdata.DgcTestKeyStore;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@SpringBootTest
@Slf4j
class UploadConnectorTest {

    @MockBean
    DgcGatewayConnectorRestClient restClientMock;

    @Autowired
    DgcGatewayUploadConnector connector;

    @Autowired
    CertificateUtils certificateUtils;

    @Autowired
    DgcTestKeyStore testKeyStore;


    @Test
    void testDownloadOfCertificates() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate dsc = CertificateTestUtils.generateCertificate(keyPair, "EU", "DSC");

        ArgumentCaptor<String> argumentCaptor = ArgumentCaptor.forClass(String.class);

        when(restClientMock.uploadSignerInformation(argumentCaptor.capture()))
            .thenReturn(ResponseEntity.status(HttpStatus.CREATED).build());

        connector.uploadTrustedCertificate(dsc);

        verify(restClientMock).uploadSignerInformation(any());

        SignedCertificateMessageParser parser = new SignedCertificateMessageParser(argumentCaptor.getValue());

        Assertions.assertEquals(certificateUtils.convertCertificate(dsc), parser.getPayloadCertificate());
        Assertions.assertEquals(certificateUtils.convertCertificate(testKeyStore.getUpload()), parser.getSigningCertificate());
    }

    @Test
    void testDownloadOfCertificatesHolder() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509CertificateHolder dsc = certificateUtils.convertCertificate(
            CertificateTestUtils.generateCertificate(keyPair, "EU", "DSC"));


        ArgumentCaptor<String> argumentCaptor = ArgumentCaptor.forClass(String.class);

        when(restClientMock.uploadSignerInformation(argumentCaptor.capture()))
            .thenReturn(ResponseEntity.status(HttpStatus.CREATED).build());

        connector.uploadTrustedCertificate(dsc);

        verify(restClientMock).uploadSignerInformation(any());

        SignedCertificateMessageParser parser = new SignedCertificateMessageParser(argumentCaptor.getValue());

        Assertions.assertEquals(dsc, parser.getPayloadCertificate());
        Assertions.assertEquals(certificateUtils.convertCertificate(testKeyStore.getUpload()), parser.getSigningCertificate());
    }

    @Test
    void testDeleteCertificates() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate dsc = CertificateTestUtils.generateCertificate(keyPair, "EU", "DSC");

        ArgumentCaptor<String> argumentCaptor = ArgumentCaptor.forClass(String.class);

        when(restClientMock.deleteSignerInformation(argumentCaptor.capture()))
            .thenReturn(ResponseEntity.status(HttpStatus.NO_CONTENT).build());

        connector.deleteTrustedCertificate(dsc);

        verify(restClientMock).deleteSignerInformation(any());

        SignedCertificateMessageParser parser = new SignedCertificateMessageParser(argumentCaptor.getValue());

        Assertions.assertEquals(certificateUtils.convertCertificate(dsc), parser.getPayloadCertificate());
        Assertions.assertEquals(certificateUtils.convertCertificate(testKeyStore.getUpload()), parser.getSigningCertificate());
    }

    @Test
    void testDeleteCertificatesHolder() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509CertificateHolder dsc = certificateUtils.convertCertificate(
            CertificateTestUtils.generateCertificate(keyPair, "EU", "DSC"));

        ArgumentCaptor<String> argumentCaptor = ArgumentCaptor.forClass(String.class);

        when(restClientMock.deleteSignerInformation(argumentCaptor.capture()))
            .thenReturn(ResponseEntity.status(HttpStatus.NO_CONTENT).build());

        connector.deleteTrustedCertificate(dsc);

        verify(restClientMock).deleteSignerInformation(any());

        SignedCertificateMessageParser parser = new SignedCertificateMessageParser(argumentCaptor.getValue());

        Assertions.assertEquals(dsc, parser.getPayloadCertificate());
        Assertions.assertEquals(certificateUtils.convertCertificate(testKeyStore.getUpload()), parser.getSigningCertificate());
    }
}
