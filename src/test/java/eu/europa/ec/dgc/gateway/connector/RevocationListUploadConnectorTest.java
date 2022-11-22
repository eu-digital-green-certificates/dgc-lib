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
import com.fasterxml.jackson.databind.util.StdDateFormat;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import eu.europa.ec.dgc.gateway.connector.client.DgcGatewayConnectorRestClient;
import eu.europa.ec.dgc.gateway.connector.dto.RevocationBatchDeleteRequestDto;
import eu.europa.ec.dgc.gateway.connector.dto.RevocationBatchDto;
import eu.europa.ec.dgc.gateway.connector.dto.RevocationHashTypeDto;
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
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
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
class RevocationListUploadConnectorTest {

    @MockBean
    DgcGatewayConnectorRestClient restClientMock;

    @Autowired
    DgcGatewayRevocationListUploadConnector connector;

    @Autowired
    CertificateUtils certificateUtils;

    @Autowired
    DgcTestKeyStore testKeyStore;

    ObjectMapper mapper = new ObjectMapper();

    @Test
    void testUploadOfRevocationList() throws Exception {
        ArgumentCaptor<String> argumentCaptor = ArgumentCaptor.forClass(String.class);

        when(restClientMock.uploadBatch(argumentCaptor.capture()))
            .thenReturn(ResponseEntity.status(HttpStatus.CREATED).build());

        connector.uploadRevocationBatch(getRevocation());

        verify(restClientMock).uploadBatch(any());

        SignedStringMessageParser parser = new SignedStringMessageParser(argumentCaptor.getValue());
        Assertions.assertEquals(getRevocationJSON(), parser.getPayload());
        Assertions.assertEquals(certificateUtils.convertCertificate(testKeyStore.getUpload()),
            parser.getSigningCertificate());
    }

    @Test
    void testDeleteCertificates() throws Exception {
        String dummyRevocationListId = "Revo1234";

        ArgumentCaptor<String> argumentCaptor = ArgumentCaptor.forClass(String.class);

        when(restClientMock.deleteBatch(argumentCaptor.capture()))
            .thenReturn(ResponseEntity.status(HttpStatus.NO_CONTENT).build());

        connector.deleteRevocationBatch(dummyRevocationListId);

        verify(restClientMock).deleteBatch(any());

        SignedStringMessageParser parser = new SignedStringMessageParser(argumentCaptor.getValue());

        Assertions.assertEquals(getDeleteJSON(dummyRevocationListId), parser.getPayload());
        Assertions.assertEquals(certificateUtils.convertCertificate(testKeyStore.getUpload()),
            parser.getSigningCertificate());
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
        String dummyRevocationList = "dummyRevocationList";

        String problemReport = "{" +
            "\"code\": \"0x500\"," +
            "\"problem\": \"problem\"," +
            "\"sendValue\": \"val\"," +
            "\"details\": \"details\"" +
            "}";


        doThrow(new FeignException.BadRequest("", dummyRequest(), problemReport.getBytes(StandardCharsets.UTF_8), null))
            .when(restClientMock).uploadBatch(any());

        DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException e =
            Assertions.assertThrows(DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException.class,
                () -> connector.uploadRevocationBatch(getRevocation()));

        Assertions.assertEquals(
            DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException.Reason.INVALID_BATCH,
            e.getReason());
    }

    @Test
    void shouldThrowAnExceptionWhenUploadRequestFailedWithBadJson() {
        String dummyRevocationList = "dummyRevocationList";

        String problemReport = "{" +
            "code: \"0x500\"," +
            "problem: \"problem\"," +
            "sendValue: \"val\"," +
            "details: \"details\"" +
            "}";


        doThrow(new FeignException.BadRequest("", dummyRequest(), problemReport.getBytes(StandardCharsets.UTF_8), null))
            .when(restClientMock).uploadBatch(any());

        DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException e =
            Assertions.assertThrows(DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException.class,
                () -> connector.uploadRevocationBatch(getRevocation()));

        Assertions.assertEquals(
            DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException.Reason.UNKNOWN_ERROR,
            e.getReason());
    }

    @Test
    void shouldThrowAnExceptionWhenUploadRequestGetsInternalServerError() {
        String dummyRevocationList = "dummyRevocationList";

        doThrow(new FeignException.InternalServerError("", dummyRequest(), null, null))
            .when(restClientMock).uploadBatch(any());

        DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException e =
            Assertions.assertThrows(DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException.class,
                () -> connector.uploadRevocationBatch(getRevocation()));
        Assertions.assertEquals(
            DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException.Reason.SERVER_ERROR, e.getReason());
    }

    @Test
    void shouldThrowAnExceptionWhenUploadRequestGetsUnauthorizedError() {
        String dummyRevocationList = "dummyRevocationList";

        doThrow(new FeignException.Unauthorized("", dummyRequest(), null, null))
            .when(restClientMock).uploadBatch(any());

        DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException e =
            Assertions.assertThrows(DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException.class,
                () -> connector.uploadRevocationBatch(getRevocation()));
        Assertions.assertEquals(
            DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException.Reason.INVALID_AUTHORIZATION,
            e.getReason());
    }

    @Test
    void shouldThrowAnExceptionWhenUploadRequestGetsForbiddenError() {
        String dummyRevocationList = "dummyRevocationList";

        doThrow(new FeignException.Forbidden("", dummyRequest(), null, null))
            .when(restClientMock).uploadBatch(any());

        DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException e =
            Assertions.assertThrows(DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException.class,
                () -> connector.uploadRevocationBatch(getRevocation()));
        Assertions.assertEquals(
            DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException.Reason.INVALID_AUTHORIZATION,
            e.getReason());
    }

    @Test
    void shouldThrowAnExceptionWhenDeleteRequestFailed() {
        String dummyRevocationList = "dummyRevocationList";

        String problemReport = "{" +
            "\"code\": \"0x500\"," +
            "\"problem\": \"problem\"," +
            "\"sendValue\": \"val\"," +
            "\"details\": \"details\"" +
            "}";


        doThrow(new FeignException.BadRequest("", dummyRequest(), problemReport.getBytes(StandardCharsets.UTF_8), null))
            .when(restClientMock).deleteBatch(any());

        DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException e =
            Assertions.assertThrows(DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException.class,
                () -> connector.deleteRevocationBatch(dummyRevocationList));

        Assertions.assertEquals(
            DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException.Reason.INVALID_BATCH,
            e.getReason());
    }

    @Test
    void shouldThrowAnExceptionWhenDeleteRequestFailedWithBadJson() {
        String dummyRevocationList = "dummyRevocationList";

        String problemReport = "{" +
            "code: \"0x500\"," +
            "problem: \"problem\"," +
            "sendValue: \"val\"," +
            "details: \"details\"" +
            "}";


        doThrow(new FeignException.BadRequest("", dummyRequest(), problemReport.getBytes(StandardCharsets.UTF_8), null))
            .when(restClientMock).deleteBatch(any());

        DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException e =
            Assertions.assertThrows(DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException.class,
                () -> connector.deleteRevocationBatch(dummyRevocationList));

        Assertions.assertEquals(
            DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException.Reason.UNKNOWN_ERROR,
            e.getReason());
    }

    @Test
    void shouldThrowAnExceptionWhenDeleteRequestGetsInternalServerError() {
        String dummyRevocationList = "dummyRevocationList";

        doThrow(new FeignException.InternalServerError("", dummyRequest(), null, null))
            .when(restClientMock).deleteBatch(any());

        DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException e =
            Assertions.assertThrows(DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException.class,
                () -> connector.deleteRevocationBatch(dummyRevocationList));
        Assertions.assertEquals(
            DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException.Reason.SERVER_ERROR, e.getReason());
    }

    @Test
    void shouldThrowAnExceptionWhenDeleteRequestGetsUnauthorizedError() {
        String dummyRevocationList = "dummyRevocationList";

        doThrow(new FeignException.Unauthorized("", dummyRequest(), null, null))
            .when(restClientMock).deleteBatch(any());

        DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException e =
            Assertions.assertThrows(DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException.class,
                () -> connector.deleteRevocationBatch(dummyRevocationList));
        Assertions.assertEquals(
            DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException.Reason.INVALID_AUTHORIZATION,
            e.getReason());
    }

    @Test
    void shouldThrowAnExceptionWhenDeleteRequestGetsForbiddenError() {
        String dummyRevocationList = "dummyRevocationList";

        doThrow(new FeignException.Forbidden("", dummyRequest(), null, null))
            .when(restClientMock).deleteBatch(any());

        DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException e =
            Assertions.assertThrows(DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException.class,
                () -> connector.deleteRevocationBatch(dummyRevocationList));
        Assertions.assertEquals(
            DgcGatewayRevocationListUploadConnector.DgcRevocationBatchUploadException.Reason.INVALID_AUTHORIZATION,
            e.getReason());
    }

    @Test
    void shouldNotThrowAnExceptionWhenDeleteRequestGetsNotFoundError() {
        String dummyRevocationList = "dummyRevocationList";

        doThrow(new FeignException.NotFound("", dummyRequest(), null, null))
            .when(restClientMock).deleteBatch(any());

        Assertions.assertDoesNotThrow(() -> connector.deleteRevocationBatch(dummyRevocationList));
    }

    /**
     * Method to create dummy request which is required to throw FeignExceptions.
     */
    private Request dummyRequest() {
        return Request.create(Request.HttpMethod.GET, "url", new HashMap<>(), null, new RequestTemplate());
    }

    private RevocationBatchDto getRevocation() {
        RevocationBatchDto revocation = new RevocationBatchDto();
        revocation.setCountry("SE");
        revocation.setExpires(ZonedDateTime.parse("2022-03-14T10:43:08.828Z"));
        revocation.setKid("123456789012");
        revocation.setHashType(RevocationHashTypeDto.UCI);
        RevocationBatchDto.BatchEntryDto entry = new RevocationBatchDto.BatchEntryDto("123456789123456789123456");
        List<RevocationBatchDto.BatchEntryDto> list = new ArrayList<>();
        list.add(entry);
        revocation.setEntries(list);
        return revocation;
    }

    private String getRevocationJSON() throws JsonProcessingException {
        mapper.registerModule(new JavaTimeModule());
        mapper.setDateFormat(new StdDateFormat().withColonInTimeZone(true));
        return mapper.writeValueAsString(getRevocation());
    }

    private String getDeleteJSON(String batchId) throws JsonProcessingException {
        RevocationBatchDeleteRequestDto deleteRequest = new RevocationBatchDeleteRequestDto();
        deleteRequest.setBatchId(batchId);

        mapper.registerModule(new JavaTimeModule());
        return mapper.writeValueAsString(deleteRequest);
    }
}
