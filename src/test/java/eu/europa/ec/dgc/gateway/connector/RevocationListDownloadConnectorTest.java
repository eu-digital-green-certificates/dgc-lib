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

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.gateway.connector.client.DgcGatewayConnectorRestClient;
import eu.europa.ec.dgc.gateway.connector.dto.RevocationBatchDto;
import eu.europa.ec.dgc.gateway.connector.dto.RevocationBatchListDto;
import eu.europa.ec.dgc.gateway.connector.dto.RevocationHashTypeDto;
import eu.europa.ec.dgc.gateway.connector.exception.RevocationBatchDownloadException;
import eu.europa.ec.dgc.gateway.connector.exception.RevocationBatchParseException;
import eu.europa.ec.dgc.gateway.connector.iterator.DgcGatewayRevocationListDownloadIterator;
import eu.europa.ec.dgc.signing.SignedStringMessageBuilder;
import eu.europa.ec.dgc.testdata.CertificateTestUtils;
import eu.europa.ec.dgc.testdata.DgcTestKeyStore;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@SpringBootTest
@Slf4j
class RevocationListDownloadConnectorTest {

    @MockBean
    DgcGatewayConnectorRestClient restClientMock;

    @Autowired
    DgcGatewayRevocationListDownloadConnector downloadConnector;

    @Autowired
    CertificateUtils certificateUtils;

    @Autowired
    DgcTestKeyStore testKeyStore;

    @Autowired
    ObjectMapper objectMapper;



    @Test
    void getRevocationListDownloadIterator() {
        RevocationBatchListDto.RevocationBatchListItemDto batchItem1 =
            new RevocationBatchListDto.RevocationBatchListItemDto(
                "batchId1",
                "de",
                ZonedDateTime.parse("2021-07-01T00:00:00Z"),
                false
            );

        RevocationBatchListDto.RevocationBatchListItemDto batchItem2 =
            new RevocationBatchListDto.RevocationBatchListItemDto(
                "batchId2",
                "fr",
                ZonedDateTime.parse("2021-08-01T00:00:00Z"),
                false
            );

        RevocationBatchListDto.RevocationBatchListItemDto batchItem3 =
            new RevocationBatchListDto.RevocationBatchListItemDto(
                "batchId3",
                "de",
                ZonedDateTime.parse("2021-08-01T00:00:00Z"),
                false
            );

        RevocationBatchListDto.RevocationBatchListItemDto batchItem4 =
            new RevocationBatchListDto.RevocationBatchListItemDto(
                "batchId4",
                "fr",
                ZonedDateTime.parse("2021-08-10T00:00:00Z"),
                false
            );

        RevocationBatchListDto responseBody1 = new RevocationBatchListDto();
        responseBody1.setMore(true);
        responseBody1.setBatches(new ArrayList<>());
        responseBody1.getBatches().add(batchItem1);
        responseBody1.getBatches().add(batchItem2);

        RevocationBatchListDto responseBody2 = new RevocationBatchListDto();
        responseBody2.setMore(false);
        responseBody2.setBatches(new ArrayList<>());
        responseBody2.getBatches().add(batchItem3);
        responseBody2.getBatches().add(batchItem4);


        when(restClientMock.downloadRevocationList("2021-06-01T00:00:00Z"))
            .thenReturn(ResponseEntity.ok(responseBody1));

        when(restClientMock.downloadRevocationList("2021-08-01T00:00:00Z"))
            .thenReturn(ResponseEntity.ok(responseBody2));

        when(restClientMock.downloadRevocationList("2021-08-10T00:00:00Z"))
            .thenReturn(ResponseEntity.noContent().build());

        DgcGatewayRevocationListDownloadIterator downloadIterator =
            downloadConnector.getRevocationListDownloadIterator();

        assertTrue(downloadIterator.hasNext());
        List<RevocationBatchListDto.RevocationBatchListItemDto> downloadedData = downloadIterator.next();

        assertNotNull(downloadedData);
        assertFalse(downloadedData.isEmpty());
        Assertions.assertEquals(2 , downloadedData.size());
        assertEquals(batchItem1, downloadedData.get(0));
        assertEquals(batchItem2, downloadedData.get(1));

        assertTrue(downloadIterator.hasNext());
        downloadedData = downloadIterator.next();

        assertNotNull(downloadedData);
        assertFalse(downloadedData.isEmpty());
        Assertions.assertEquals(2 , downloadedData.size());
        assertEquals(batchItem3, downloadedData.get(0));
        assertEquals(batchItem4, downloadedData.get(1));

        assertFalse(downloadIterator.hasNext());

    }

    @Test
    void GetRevocationListDownloadIteratorWithStartDate() {
        RevocationBatchListDto.RevocationBatchListItemDto batchItem1 =
            new RevocationBatchListDto.RevocationBatchListItemDto(
                "batchId1",
                "de",
                ZonedDateTime.parse("2021-07-01T00:00:00Z"),
                false
            );

        RevocationBatchListDto.RevocationBatchListItemDto batchItem2 =
            new RevocationBatchListDto.RevocationBatchListItemDto(
                "batchId2",
                "fr",
                ZonedDateTime.parse("2021-08-01T00:00:00Z"),
                false
            );

        RevocationBatchListDto.RevocationBatchListItemDto batchItem3 =
            new RevocationBatchListDto.RevocationBatchListItemDto(
                "batchId3",
                "de",
                ZonedDateTime.parse("2021-08-01T00:00:00Z"),
                false
            );

        RevocationBatchListDto.RevocationBatchListItemDto batchItem4 =
            new RevocationBatchListDto.RevocationBatchListItemDto(
                "batchId4",
                "fr",
                ZonedDateTime.parse("2021-08-10T00:00:00Z"),
                false
            );

        RevocationBatchListDto responseBody1 = new RevocationBatchListDto();
        responseBody1.setMore(true);
        responseBody1.setBatches(new ArrayList<>());
        responseBody1.getBatches().add(batchItem1);
        responseBody1.getBatches().add(batchItem2);

        RevocationBatchListDto responseBody2 = new RevocationBatchListDto();
        responseBody2.setMore(false);
        responseBody2.setBatches(new ArrayList<>());
        responseBody2.getBatches().add(batchItem3);
        responseBody2.getBatches().add(batchItem4);


        when(restClientMock.downloadRevocationList("2021-06-01T00:00:00Z"))
            .thenReturn(ResponseEntity.ok(responseBody1));

        when(restClientMock.downloadRevocationList("2021-08-01T00:00:00Z"))
            .thenReturn(ResponseEntity.ok(responseBody2));

        when(restClientMock.downloadRevocationList("2021-08-10T00:00:00Z"))
            .thenReturn(ResponseEntity.noContent().build());

        DgcGatewayRevocationListDownloadIterator downloadIterator =
            downloadConnector.getRevocationListDownloadIterator(ZonedDateTime.parse("2021-08-01T00:00:00Z"));

        assertTrue(downloadIterator.hasNext());
        List<RevocationBatchListDto.RevocationBatchListItemDto> downloadedData = downloadIterator.next();

        assertNotNull(downloadedData);
        assertFalse(downloadedData.isEmpty());
        Assertions.assertEquals(2 , downloadedData.size());
        assertEquals(batchItem3, downloadedData.get(0));
        assertEquals(batchItem4, downloadedData.get(1));

        assertFalse(downloadIterator.hasNext());
    }

    @Test
    void getRevocationListBatchById() throws Exception {
        KeyPair keyPairUpload = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate upload = CertificateTestUtils.generateCertificate(keyPairUpload, "EU", "UPLOAD");

        RevocationBatchDto batch = new RevocationBatchDto("de", ZonedDateTime.now().plusDays(1),
            "UNKOWN_KID",
            RevocationHashTypeDto.SIGNATURE,
            List.of(new RevocationBatchDto.BatchEntryDto("cafe")));

        String batchId1 = "batchId1";

        String signedBatch = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(upload), keyPairUpload.getPrivate())
            .withPayload(objectMapper.writeValueAsString(batch))
            .buildAsString(false);


        when(restClientMock.downloadBatch(batchId1))
            .thenReturn(ResponseEntity.ok(signedBatch));

        RevocationBatchDto downloadedBatch = downloadConnector.getRevocationListBatchById(batchId1);

        assertNotNull(downloadedBatch);
        assertEquals(downloadedBatch, batch);

    }

    @Test
    void getRevocationListBatchByIdNotFoundBatch() throws Exception {
        String batchId1 = "batchId1";
        when(restClientMock.downloadBatch(batchId1))
            .thenReturn(ResponseEntity.status(HttpStatus.NOT_FOUND.value()).build());

        RevocationBatchDownloadException exception = assertThrows(RevocationBatchDownloadException.class, () -> {
            downloadConnector.getRevocationListBatchById(batchId1);
        });

        Assertions.assertEquals(exception.getStatus(), HttpStatus.NOT_FOUND.value());
    }

    @Test
    void getRevocationListBatchByIdCMSJsonFail() throws Exception {
        KeyPair keyPairUpload = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate upload = CertificateTestUtils.generateCertificate(keyPairUpload, "EU", "UPLOAD");

        String batch = "NoValidJSON";

        String batchId1 = "batchId1";

        String signedBatch = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(upload), keyPairUpload.getPrivate())
            .withPayload(batch)
            .buildAsString(false);


        when(restClientMock.downloadBatch(batchId1))
            .thenReturn(ResponseEntity.ok(signedBatch));

        RevocationBatchParseException exception = assertThrows(RevocationBatchParseException.class, () -> {
            downloadConnector.getRevocationListBatchById(batchId1);
        });
        assertTrue(exception.getMessage().contains("Failed to parse revocation batch JSON"));

    }

    @Test
    void getRevocationListBatchByIdCMSJFail() throws Exception {
        KeyPair keyPairUpload = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate upload = CertificateTestUtils.generateCertificate(keyPairUpload, "EU", "UPLOAD");

        String batch = "NoValidCMS";

        String batchId1 = "batchId1";

        when(restClientMock.downloadBatch(batchId1))
            .thenReturn(ResponseEntity.ok(batch));

        RevocationBatchParseException exception = assertThrows(RevocationBatchParseException.class, () -> {
            downloadConnector.getRevocationListBatchById(batchId1);
        });
        assertTrue(exception.getMessage().contains("CMS check failed for revocation batch"));

    }

    private void assertEquals(RevocationBatchListDto.RevocationBatchListItemDto b1,
                              RevocationBatchListDto.RevocationBatchListItemDto b2) {
        Assertions.assertEquals(b1.getBatchId(), b2.getBatchId());
        Assertions.assertEquals(b1.getCountry(), b2.getCountry());
        Assertions.assertEquals(b1.getDate(), b2.getDate());
        Assertions.assertEquals(b1.getDeleted(), b2.getDeleted());
    }

    private void assertEquals(RevocationBatchDto b1, RevocationBatchDto b2) {
        Assertions.assertEquals(b1.getCountry(), b2.getCountry());
        Assertions.assertTrue(b1.getExpires().isEqual(b2.getExpires()));
        Assertions.assertEquals(b1.getHashType(), b2.getHashType());
        Assertions.assertEquals(b1.getKid(), b2.getKid());
        Assertions.assertEquals(b1.getEntries().size(), b2.getEntries().size());
        for (int i = 0; i < b1.getEntries().size(); i++){
            Assertions.assertEquals(b1.getEntries().get(i).getHash(), b2.getEntries().get(i).getHash());
        }
    }
}
