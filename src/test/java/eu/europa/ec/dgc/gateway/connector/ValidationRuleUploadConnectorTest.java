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
import eu.europa.ec.dgc.signing.SignedStringMessageParser;
import eu.europa.ec.dgc.testdata.DgcTestKeyStore;
import eu.europa.ec.dgc.utils.CertificateUtils;
import feign.FeignException;
import feign.Request;
import feign.RequestTemplate;
import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@SpringBootTest
@Slf4j
class ValidationRuleUploadConnectorTest {

    @MockBean
    DgcGatewayConnectorRestClient restClientMock;

    @Autowired
    DgcGatewayValidationRuleUploadConnector connector;

    @Autowired
    CertificateUtils certificateUtils;

    @Autowired
    DgcTestKeyStore testKeyStore;


    @Test
    void testUploadOfValidationRules() throws Exception {
        String dummyValidationRule = "dummyValidationRule";

        ArgumentCaptor<String> argumentCaptor = ArgumentCaptor.forClass(String.class);

        when(restClientMock.uploadValidationRule(argumentCaptor.capture()))
            .thenReturn(ResponseEntity.status(HttpStatus.CREATED).build());

        connector.uploadValidationRule(dummyValidationRule);

        verify(restClientMock).uploadValidationRule(any());

        SignedStringMessageParser parser = new SignedStringMessageParser(argumentCaptor.getValue());

        Assertions.assertEquals(dummyValidationRule, parser.getPayload());
        Assertions.assertEquals(certificateUtils.convertCertificate(testKeyStore.getUpload()), parser.getSigningCertificate());
    }

    @Test
    void testDeleteCertificates() throws Exception {
        String dummyValidationRuleId = "IR-EU-0001";

        ArgumentCaptor<String> argumentCaptor = ArgumentCaptor.forClass(String.class);

        when(restClientMock.deleteValidationRule(argumentCaptor.capture()))
            .thenReturn(ResponseEntity.status(HttpStatus.NO_CONTENT).build());

        connector.deleteValidationRules(dummyValidationRuleId);

        verify(restClientMock).deleteValidationRule(any());

        SignedStringMessageParser parser = new SignedStringMessageParser(argumentCaptor.getValue());

        Assertions.assertEquals(dummyValidationRuleId, parser.getPayload());
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
    void shouldThrowAnExceptionWhenUploadRequestFailed() {
        String dummyValidationRule = "dummyValidationRule";

        String problemReport = "{" +
            "\"code\": \"0x500\"," +
            "\"problem\": \"problem\"," +
            "\"sendValue\": \"val\"," +
            "\"details\": \"details\"" +
            "}";


        doThrow(new FeignException.BadRequest("", dummyRequest(), problemReport.getBytes(StandardCharsets.UTF_8), null))
            .when(restClientMock).uploadValidationRule(any());

        DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException e =
            Assertions.assertThrows(DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException.class,
                () -> connector.uploadValidationRule(dummyValidationRule));

        Assertions.assertEquals(DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException.Reason.INVALID_RULE, e.getReason());
    }

    @Test
    void shouldThrowAnExceptionWhenUploadRequestFailedWithBadJson() {
        String dummyValidationRule = "dummyValidationRule";

        String problemReport = "{" +
            "code: \"0x500\"," +
            "problem: \"problem\"," +
            "sendValue: \"val\"," +
            "details: \"details\"" +
            "}";


        doThrow(new FeignException.BadRequest("", dummyRequest(), problemReport.getBytes(StandardCharsets.UTF_8), null))
            .when(restClientMock).uploadValidationRule(any());

        DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException e =
            Assertions.assertThrows(DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException.class,
                () -> connector.uploadValidationRule(dummyValidationRule));

        Assertions.assertEquals(DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException.Reason.UNKNOWN_ERROR, e.getReason());
    }

    @Test
    void shouldThrowAnExceptionWhenUploadRequestGetsInternalServerError() {
        String dummyValidationRule = "dummyValidationRule";

        doThrow(new FeignException.InternalServerError("", dummyRequest(), null, null))
            .when(restClientMock).uploadValidationRule(any());

        DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException e =
            Assertions.assertThrows(DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException.class,
                () -> connector.uploadValidationRule(dummyValidationRule));
        Assertions.assertEquals(DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException.Reason.SERVER_ERROR, e.getReason());
    }

    @Test
    void shouldThrowAnExceptionWhenUploadRequestGetsUnauthorizedError() {
        String dummyValidationRule = "dummyValidationRule";

        doThrow(new FeignException.Unauthorized("", dummyRequest(), null, null))
            .when(restClientMock).uploadValidationRule(any());

        DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException e =
            Assertions.assertThrows(DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException.class,
                () -> connector.uploadValidationRule(dummyValidationRule));
        Assertions.assertEquals(DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException.Reason.INVALID_AUTHORIZATION, e.getReason());
    }

    @Test
    void shouldThrowAnExceptionWhenUploadRequestGetsForbiddenError() {
        String dummyValidationRule = "dummyValidationRule";

        doThrow(new FeignException.Forbidden("", dummyRequest(), null, null))
            .when(restClientMock).uploadValidationRule(any());

        DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException e =
            Assertions.assertThrows(DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException.class,
                () -> connector.uploadValidationRule(dummyValidationRule));
        Assertions.assertEquals(DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException.Reason.INVALID_AUTHORIZATION, e.getReason());
    }

    @Test
    void shouldThrowAnExceptionWhenDeleteRequestFailed() {
        String dummyValidationRule = "dummyValidationRule";

        String problemReport = "{" +
            "\"code\": \"0x500\"," +
            "\"problem\": \"problem\"," +
            "\"sendValue\": \"val\"," +
            "\"details\": \"details\"" +
            "}";


        doThrow(new FeignException.BadRequest("", dummyRequest(), problemReport.getBytes(StandardCharsets.UTF_8), null))
            .when(restClientMock).deleteValidationRule(any());

        DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException e =
            Assertions.assertThrows(DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException.class,
                () -> connector.deleteValidationRules(dummyValidationRule));

        Assertions.assertEquals(DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException.Reason.INVALID_RULE, e.getReason());
    }

    @Test
    void shouldThrowAnExceptionWhenDeleteRequestFailedWithBadJson() {
        String dummyValidationRule = "dummyValidationRule";

        String problemReport = "{" +
            "code: \"0x500\"," +
            "problem: \"problem\"," +
            "sendValue: \"val\"," +
            "details: \"details\"" +
            "}";


        doThrow(new FeignException.BadRequest("", dummyRequest(), problemReport.getBytes(StandardCharsets.UTF_8), null))
            .when(restClientMock).deleteValidationRule(any());

        DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException e =
            Assertions.assertThrows(DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException.class,
                () -> connector.deleteValidationRules(dummyValidationRule));

        Assertions.assertEquals(DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException.Reason.UNKNOWN_ERROR, e.getReason());
    }

    @Test
    void shouldThrowAnExceptionWhenDeleteRequestGetsInternalServerError() {
        String dummyValidationRule = "dummyValidationRule";

        doThrow(new FeignException.InternalServerError("", dummyRequest(), null, null))
            .when(restClientMock).deleteValidationRule(any());

        DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException e =
            Assertions.assertThrows(DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException.class,
                () -> connector.deleteValidationRules(dummyValidationRule));
        Assertions.assertEquals(DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException.Reason.SERVER_ERROR, e.getReason());
    }

    @Test
    void shouldThrowAnExceptionWhenDeleteRequestGetsUnauthorizedError() {
        String dummyValidationRule = "dummyValidationRule";

        doThrow(new FeignException.Unauthorized("", dummyRequest(), null, null))
            .when(restClientMock).deleteValidationRule(any());

        DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException e =
            Assertions.assertThrows(DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException.class,
                () -> connector.deleteValidationRules(dummyValidationRule));
        Assertions.assertEquals(DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException.Reason.INVALID_AUTHORIZATION, e.getReason());
    }

    @Test
    void shouldThrowAnExceptionWhenDeleteRequestGetsForbiddenError() {
        String dummyValidationRule = "dummyValidationRule";

        doThrow(new FeignException.Forbidden("", dummyRequest(), null, null))
            .when(restClientMock).deleteValidationRule(any());

        DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException e =
            Assertions.assertThrows(DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException.class,
                () -> connector.deleteValidationRules(dummyValidationRule));
        Assertions.assertEquals(DgcGatewayValidationRuleUploadConnector.DgcValidationRuleUploadException.Reason.INVALID_AUTHORIZATION, e.getReason());
    }

    @Test
    void shouldNotThrowAnExceptionWhenDeleteRequestGetsNotFoundError() {
        String dummyValidationRule = "dummyValidationRule";

        doThrow(new FeignException.NotFound("", dummyRequest(), null, null))
            .when(restClientMock).deleteValidationRule(any());

        Assertions.assertDoesNotThrow(() -> connector.deleteValidationRules(dummyValidationRule));
    }

    /**
     * Method to create dummy request which is required to throw FeignExceptions.
     */
    private Request dummyRequest() {
        return Request.create(Request.HttpMethod.GET, "url", new HashMap<>(), null, new RequestTemplate());
    }
}
