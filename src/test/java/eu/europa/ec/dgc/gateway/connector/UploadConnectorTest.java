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
import feign.FeignException;
import feign.Request;
import feign.RequestTemplate;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
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

    @Test
    void initShouldFailWithoutCertificates() {
        X509Certificate uploadCertBackup = testKeyStore.getUpload();
        testKeyStore.setUpload(null);

        Assertions.assertThrows(KeyStoreException.class, connector::init);

        testKeyStore.setUpload(uploadCertBackup);

        PrivateKey uploadPrivateKeyBackup = testKeyStore.getUploadPrivateKey();
        testKeyStore.setUploadPrivateKey(null);

        Assertions.assertThrows(KeyStoreException.class, connector::init);

        testKeyStore.setUploadPrivateKey(uploadPrivateKeyBackup);

        Assertions.assertDoesNotThrow(connector::init);
    }

    @Test
    void shouldThrowAnExceptionWhenCertConversionFailed() throws CertificateEncodingException {
        X509Certificate certificateMock = mock(X509Certificate.class);
        doThrow(new CertificateEncodingException()).when(certificateMock).getEncoded();

        Assertions.assertThrows(DgcGatewayUploadConnector.DgcCertificateUploadException.class,
            () -> connector.uploadTrustedCertificate(certificateMock));
    }

    @Test
    void shouldThrowAnExceptionWhenCertConversionFailedAtDelete() throws CertificateEncodingException {
        X509Certificate certificateMock = mock(X509Certificate.class);
        doThrow(new CertificateEncodingException()).when(certificateMock).getEncoded();

        Assertions.assertThrows(DgcGatewayUploadConnector.DgcCertificateUploadException.class,
            () -> connector.deleteTrustedCertificate(certificateMock));
    }

    @Test
    void shouldThrowAnExceptionWhenUploadRequestFailed() {
        X509CertificateHolder certificateMock = mock(X509CertificateHolder.class);

        String problemReport = "{" +
            "\"code\": \"0x500\"," +
            "\"problem\": \"problem\"," +
            "\"sendValue\": \"val\"," +
            "\"details\": \"details\"" +
            "}";


        doThrow(new FeignException.BadRequest("", dummyRequest(), problemReport.getBytes(StandardCharsets.UTF_8)))
            .when(restClientMock).uploadSignerInformation(any());

        DgcGatewayUploadConnector.DgcCertificateUploadException e =
            Assertions.assertThrows(DgcGatewayUploadConnector.DgcCertificateUploadException.class,
                () -> connector.uploadTrustedCertificate(certificateMock));

        Assertions.assertEquals(DgcGatewayUploadConnector.DgcCertificateUploadException.Reason.UNKNOWN_ERROR, e.getReason());
    }

    @Test
    void shouldThrowAnExceptionWhenUploadRequestFailedWithBadJson() {
        X509CertificateHolder certificateMock = mock(X509CertificateHolder.class);

        String problemReport = "{" +
            "code: \"0x500\"," +
            "problem: \"problem\"," +
            "sendValue: \"val\"," +
            "details: \"details\"" +
            "}";


        doThrow(new FeignException.BadRequest("", dummyRequest(), problemReport.getBytes(StandardCharsets.UTF_8)))
            .when(restClientMock).uploadSignerInformation(any());

        DgcGatewayUploadConnector.DgcCertificateUploadException e =
            Assertions.assertThrows(DgcGatewayUploadConnector.DgcCertificateUploadException.class,
                () -> connector.uploadTrustedCertificate(certificateMock));

        Assertions.assertEquals(DgcGatewayUploadConnector.DgcCertificateUploadException.Reason.UNKNOWN_ERROR, e.getReason());
    }

    @Test
    void shouldThrowAnExceptionWhenUploadRequestGetsInternalServerError() {
        X509CertificateHolder certificateMock = mock(X509CertificateHolder.class);

        doThrow(new FeignException.InternalServerError("", dummyRequest(), null))
            .when(restClientMock).uploadSignerInformation(any());

        DgcGatewayUploadConnector.DgcCertificateUploadException e =
            Assertions.assertThrows(DgcGatewayUploadConnector.DgcCertificateUploadException.class,
                () -> connector.uploadTrustedCertificate(certificateMock));
        Assertions.assertEquals(DgcGatewayUploadConnector.DgcCertificateUploadException.Reason.SERVER_ERROR, e.getReason());
    }

    @Test
    void shouldThrowAnExceptionWhenUploadRequestGetsUnauthorizedError() {
        X509CertificateHolder certificateMock = mock(X509CertificateHolder.class);

        doThrow(new FeignException.Unauthorized("", dummyRequest(), null))
            .when(restClientMock).uploadSignerInformation(any());

        DgcGatewayUploadConnector.DgcCertificateUploadException e =
            Assertions.assertThrows(DgcGatewayUploadConnector.DgcCertificateUploadException.class,
                () -> connector.uploadTrustedCertificate(certificateMock));
        Assertions.assertEquals(DgcGatewayUploadConnector.DgcCertificateUploadException.Reason.INVALID_AUTHORIZATION, e.getReason());
    }

    @Test
    void shouldThrowAnExceptionWhenUploadRequestGetsForbiddenError() {
        X509CertificateHolder certificateMock = mock(X509CertificateHolder.class);

        doThrow(new FeignException.Forbidden("", dummyRequest(), null))
            .when(restClientMock).uploadSignerInformation(any());

        DgcGatewayUploadConnector.DgcCertificateUploadException e =
            Assertions.assertThrows(DgcGatewayUploadConnector.DgcCertificateUploadException.class,
                () -> connector.uploadTrustedCertificate(certificateMock));
        Assertions.assertEquals(DgcGatewayUploadConnector.DgcCertificateUploadException.Reason.INVALID_AUTHORIZATION, e.getReason());
    }

    @Test
    void shouldNotThrowAnExceptionWhenUploadRequestGetsConflictError() {
        X509CertificateHolder certificateMock = mock(X509CertificateHolder.class);

        doThrow(new FeignException.Conflict("", dummyRequest(), null))
            .when(restClientMock).uploadSignerInformation(any());

        Assertions.assertDoesNotThrow(() -> connector.uploadTrustedCertificate(certificateMock));
    }

    @Test
    void shouldThrowAnExceptionWhenDeleteRequestFailed() {
        X509CertificateHolder certificateMock = mock(X509CertificateHolder.class);

        String problemReport = "{" +
            "\"code\": \"0x500\"," +
            "\"problem\": \"problem\"," +
            "\"sendValue\": \"val\"," +
            "\"details\": \"details\"" +
            "}";


        doThrow(new FeignException.BadRequest("", dummyRequest(), problemReport.getBytes(StandardCharsets.UTF_8)))
            .when(restClientMock).deleteSignerInformation(any());

        DgcGatewayUploadConnector.DgcCertificateUploadException e =
            Assertions.assertThrows(DgcGatewayUploadConnector.DgcCertificateUploadException.class,
                () -> connector.deleteTrustedCertificate(certificateMock));

        Assertions.assertEquals(DgcGatewayUploadConnector.DgcCertificateUploadException.Reason.UNKNOWN_ERROR, e.getReason());
    }

    @Test
    void shouldThrowAnExceptionWhenDeleteRequestFailedWithBadJson() {
        X509CertificateHolder certificateMock = mock(X509CertificateHolder.class);

        String problemReport = "{" +
            "code: \"0x500\"," +
            "problem: \"problem\"," +
            "sendValue: \"val\"," +
            "details: \"details\"" +
            "}";


        doThrow(new FeignException.BadRequest("", dummyRequest(), problemReport.getBytes(StandardCharsets.UTF_8)))
            .when(restClientMock).deleteSignerInformation(any());

        DgcGatewayUploadConnector.DgcCertificateUploadException e =
            Assertions.assertThrows(DgcGatewayUploadConnector.DgcCertificateUploadException.class,
                () -> connector.deleteTrustedCertificate(certificateMock));

        Assertions.assertEquals(DgcGatewayUploadConnector.DgcCertificateUploadException.Reason.UNKNOWN_ERROR, e.getReason());
    }

    @Test
    void shouldThrowAnExceptionWhenDeleteRequestGetsInternalServerError() {
        X509CertificateHolder certificateMock = mock(X509CertificateHolder.class);

        doThrow(new FeignException.InternalServerError("", dummyRequest(), null))
            .when(restClientMock).deleteSignerInformation(any());

        DgcGatewayUploadConnector.DgcCertificateUploadException e =
            Assertions.assertThrows(DgcGatewayUploadConnector.DgcCertificateUploadException.class,
                () -> connector.deleteTrustedCertificate(certificateMock));
        Assertions.assertEquals(DgcGatewayUploadConnector.DgcCertificateUploadException.Reason.SERVER_ERROR, e.getReason());
    }

    @Test
    void shouldThrowAnExceptionWhenDeleteRequestGetsUnauthorizedError() {
        X509CertificateHolder certificateMock = mock(X509CertificateHolder.class);

        doThrow(new FeignException.Unauthorized("", dummyRequest(), null))
            .when(restClientMock).deleteSignerInformation(any());

        DgcGatewayUploadConnector.DgcCertificateUploadException e =
            Assertions.assertThrows(DgcGatewayUploadConnector.DgcCertificateUploadException.class,
                () -> connector.deleteTrustedCertificate(certificateMock));
        Assertions.assertEquals(DgcGatewayUploadConnector.DgcCertificateUploadException.Reason.INVALID_AUTHORIZATION, e.getReason());
    }

    @Test
    void shouldThrowAnExceptionWhenDeleteRequestGetsForbiddenError() {
        X509CertificateHolder certificateMock = mock(X509CertificateHolder.class);

        doThrow(new FeignException.Forbidden("", dummyRequest(), null))
            .when(restClientMock).deleteSignerInformation(any());

        DgcGatewayUploadConnector.DgcCertificateUploadException e =
            Assertions.assertThrows(DgcGatewayUploadConnector.DgcCertificateUploadException.class,
                () -> connector.deleteTrustedCertificate(certificateMock));
        Assertions.assertEquals(DgcGatewayUploadConnector.DgcCertificateUploadException.Reason.INVALID_AUTHORIZATION, e.getReason());
    }

    @Test
    void shouldNotThrowAnExceptionWhenDeleteRequestGetsNotFoundError() {
        X509CertificateHolder certificateMock = mock(X509CertificateHolder.class);

        doThrow(new FeignException.NotFound("", dummyRequest(), null))
            .when(restClientMock).deleteSignerInformation(any());

        Assertions.assertDoesNotThrow(() -> connector.deleteTrustedCertificate(certificateMock));
    }

    /**
     * Method to create dummy request which is required to throw FeignExceptions.
     */
    private Request dummyRequest() {
        return Request.create(Request.HttpMethod.GET, "url", new HashMap<>(), null, new RequestTemplate());
    }
}
