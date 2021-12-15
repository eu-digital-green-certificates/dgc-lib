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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import eu.europa.ec.dgc.gateway.connector.client.DgcGatewayConnectorRestClient;
import eu.europa.ec.dgc.gateway.connector.dto.CertificateTypeDto;
import eu.europa.ec.dgc.gateway.connector.dto.TrustListItemDto;
import eu.europa.ec.dgc.gateway.connector.dto.ValidationRuleDto;
import eu.europa.ec.dgc.gateway.connector.model.ValidationRule;
import eu.europa.ec.dgc.gateway.connector.model.ValidationRulesByCountry;
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
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.ResponseEntity;

@SpringBootTest
@Slf4j
class ValidationRuleDownloadConnectorTest {

    @MockBean
    DgcGatewayConnectorRestClient restClientMock;

    @Autowired
    DgcGatewayValidationRuleDownloadConnector connector;

    @Autowired
    CertificateUtils certificateUtils;

    @Autowired
    DgcTestKeyStore testKeyStore;

    @Autowired
    ObjectMapper objectMapper;

    ValidationRule validationRule;

    @BeforeEach
    void setup() {
        validationRule = new ValidationRule();
        validationRule.setCountry("EU");
        validationRule.setIdentifier("IR-EU-0001");
        validationRule.setType("Invalidation");
        validationRule.setRegion("BW");
        validationRule.setVersion("1.0.0");
        validationRule.setSchemaVersion("1.0.0");
        validationRule.setEngine("CERTLOGIC");
        validationRule.setEngine("1.0.0");
        validationRule.setCertificateType("Vaccination");
        validationRule.setDescription(List.of(new ValidationRule.DescriptionItem("en", "ab".repeat(10))));
        validationRule.setValidFrom(ZonedDateTime.now().plus(1, ChronoUnit.DAYS));
        validationRule.setValidTo(ZonedDateTime.now().plus(3, ChronoUnit.DAYS));
        validationRule.setAffectedFields(List.of("aa", "bb", "cc"));
        validationRule.setLogic(JsonNodeFactory.instance.objectNode());
    }

    @Test
    void testDownloadOfValidationRules() throws Exception {

        KeyPair keyPairUpload = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate upload = CertificateTestUtils.generateCertificate(keyPairUpload, "EU", "UPLOAD");

        String uploadSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayload(certificateUtils.convertCertificate(upload))
            .buildAsString(true);

        TrustListItemDto uploadTrustListItem = new TrustListItemDto();
        uploadTrustListItem.setCountry("EU");
        uploadTrustListItem.setKid("KID_EU_UPLOAD");
        uploadTrustListItem.setCertificateType(CertificateTypeDto.UPLOAD);
        uploadTrustListItem.setTimestamp(ZonedDateTime.now());
        uploadTrustListItem.setSignature(uploadSignature);
        uploadTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(upload));
        uploadTrustListItem.setRawData(Base64.getEncoder().encodeToString(upload.getEncoded()));

        String ruleSignature = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(upload), keyPairUpload.getPrivate())
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString(false);

        ValidationRuleDto validationRuleDto = new ValidationRuleDto();
        validationRuleDto.setValidTo(validationRule.getValidTo());
        validationRuleDto.setValidFrom(validationRule.getValidFrom());
        validationRuleDto.setVersion(validationRule.getVersion());
        validationRuleDto.setCms(ruleSignature);

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.UPLOAD))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(uploadTrustListItem)));

        when(restClientMock.downloadCountryList())
            .thenReturn(ResponseEntity.ok(Collections.singletonList("EU")));

        Map<String, List<ValidationRuleDto>> response = Map.of(validationRule.getIdentifier(), List.of(validationRuleDto));

        when(restClientMock.downloadValidationRule("EU"))
            .thenReturn(ResponseEntity.ok(response));

        ValidationRulesByCountry result = connector.getValidationRules();
        Assertions.assertEquals(1, result.size());
        assertEquals(validationRule, result.get("EU", validationRule.getIdentifier(), validationRule.getVersion()));
        assertEquals(validationRule, result.getMap().get("EU").getMap().get(validationRule.getIdentifier()).getMap().get(validationRule.getVersion()));
        Assertions.assertEquals(1, result.getMap().get("EU").getMap().size());
        Assertions.assertEquals(1, result.getMap().get("EU").getMap().get(validationRule.getIdentifier()).getMap().size());
        Assertions.assertEquals(1, result.flat().size());
        Assertions.assertEquals(1, result.size());
        assertEquals(validationRule, result.flat().get(0));
        assertEquals(validationRule, result.pure().get("EU").get(validationRule.getIdentifier()).get(validationRule.getVersion()));
        Assertions.assertNotNull(connector.getLastUpdated());
    }

    @Test
    void testThumbprintIntegrityCheck() throws Exception {

        KeyPair keyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate another = CertificateTestUtils.generateCertificate(keyPair, "EU", "Another");

        KeyPair keyPairUpload = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate upload = CertificateTestUtils.generateCertificate(keyPairUpload, "EU", "UPLOAD");

        String uploadSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayload(certificateUtils.convertCertificate(upload))
            .buildAsString(true);

        TrustListItemDto uploadTrustListItem = new TrustListItemDto();
        uploadTrustListItem.setCountry("EU");
        uploadTrustListItem.setKid("KID_EU_UPLOAD");
        uploadTrustListItem.setCertificateType(CertificateTypeDto.UPLOAD);
        uploadTrustListItem.setTimestamp(ZonedDateTime.now());
        uploadTrustListItem.setSignature(uploadSignature);
        // set thumbprint from another cert
        uploadTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(another));
        uploadTrustListItem.setRawData(Base64.getEncoder().encodeToString(upload.getEncoded()));

        String ruleSignature = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(upload), keyPairUpload.getPrivate())
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString(false);

        ValidationRuleDto validationRuleDto = new ValidationRuleDto();
        validationRuleDto.setValidTo(validationRule.getValidTo());
        validationRuleDto.setValidFrom(validationRule.getValidFrom());
        validationRuleDto.setVersion(validationRule.getVersion());
        validationRuleDto.setCms(ruleSignature);

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.UPLOAD))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(uploadTrustListItem)));

        when(restClientMock.downloadCountryList())
            .thenReturn(ResponseEntity.ok(Collections.singletonList("EU")));

        Map<String, List<ValidationRuleDto>> response = Map.of(validationRule.getIdentifier(), List.of(validationRuleDto));

        when(restClientMock.downloadValidationRule("EU"))
            .thenReturn(ResponseEntity.ok(response));

        ValidationRulesByCountry result = connector.getValidationRules();
        Assertions.assertEquals(0, result.size());
        Assertions.assertNotNull(connector.getLastUpdated());
    }


    @Test
    void testThumbprintIntegrityCheckInvalidRawData() throws Exception {

        KeyPair keyPairUpload = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate upload = CertificateTestUtils.generateCertificate(keyPairUpload, "EU", "UPLOAD");

        String uploadSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayload(certificateUtils.convertCertificate(upload))
            .buildAsString(true);

        TrustListItemDto uploadTrustListItem = new TrustListItemDto();
        uploadTrustListItem.setCountry("EU");
        uploadTrustListItem.setKid("KID_EU_UPLOAD");
        uploadTrustListItem.setCertificateType(CertificateTypeDto.UPLOAD);
        uploadTrustListItem.setTimestamp(ZonedDateTime.now());
        uploadTrustListItem.setSignature(uploadSignature);
        uploadTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(upload));
        uploadTrustListItem.setRawData(Base64.getEncoder().encodeToString(new byte[]{}));

        String ruleSignature = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(upload), keyPairUpload.getPrivate())
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString(false);

        ValidationRuleDto validationRuleDto = new ValidationRuleDto();
        validationRuleDto.setValidTo(validationRule.getValidTo());
        validationRuleDto.setValidFrom(validationRule.getValidFrom());
        validationRuleDto.setVersion(validationRule.getVersion());
        validationRuleDto.setCms(ruleSignature);

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.UPLOAD))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(uploadTrustListItem)));

        when(restClientMock.downloadCountryList())
            .thenReturn(ResponseEntity.ok(Collections.singletonList("EU")));

        Map<String, List<ValidationRuleDto>> response = Map.of(validationRule.getIdentifier(), List.of(validationRuleDto));

        when(restClientMock.downloadValidationRule("EU"))
            .thenReturn(ResponseEntity.ok(response));


        ValidationRulesByCountry result = connector.getValidationRules();
        Assertions.assertEquals(0, result.size());
        Assertions.assertNotNull(connector.getLastUpdated());
    }

    @Test
    void testDownloadOfValidationRulesShouldFailWrongTrustAnchorSignatureForUpload() throws Exception {

        KeyPair fakeTrustAnchorKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate fakeTrustAnchor = CertificateTestUtils.generateCertificate(fakeTrustAnchorKeyPair, "EU", "TA");

        KeyPair keyPairUpload = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate upload = CertificateTestUtils.generateCertificate(keyPairUpload, "EU", "UPLOAD");

        String uploadSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(fakeTrustAnchor), fakeTrustAnchorKeyPair.getPrivate())
            .withPayload(certificateUtils.convertCertificate(upload))
            .buildAsString(true);

        TrustListItemDto uploadTrustListItem = new TrustListItemDto();
        uploadTrustListItem.setCountry("EU");
        uploadTrustListItem.setKid("KID_EU_UPLOAD");
        uploadTrustListItem.setCertificateType(CertificateTypeDto.UPLOAD);
        uploadTrustListItem.setTimestamp(ZonedDateTime.now());
        uploadTrustListItem.setSignature(uploadSignature);
        uploadTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(upload));
        uploadTrustListItem.setRawData(Base64.getEncoder().encodeToString(upload.getEncoded()));

        String ruleSignature = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(upload), keyPairUpload.getPrivate())
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString(false);

        ValidationRuleDto validationRuleDto = new ValidationRuleDto();
        validationRuleDto.setValidTo(validationRule.getValidTo());
        validationRuleDto.setValidFrom(validationRule.getValidFrom());
        validationRuleDto.setVersion(validationRule.getVersion());
        validationRuleDto.setCms(ruleSignature);

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.UPLOAD))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(uploadTrustListItem)));

        when(restClientMock.downloadCountryList())
            .thenReturn(ResponseEntity.ok(Collections.singletonList("EU")));

        Map<String, List<ValidationRuleDto>> response = Map.of(validationRule.getIdentifier(), List.of(validationRuleDto));

        when(restClientMock.downloadValidationRule("EU"))
            .thenReturn(ResponseEntity.ok(response));

        Assertions.assertEquals(0, connector.getValidationRules().size());
        Assertions.assertNotNull(connector.getLastUpdated());
    }

    @Test
    void shouldReturnEmptyListWhenUploadCertDownloadFails() throws Exception {
        KeyPair keyPairUpload = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate upload = CertificateTestUtils.generateCertificate(keyPairUpload, "EU", "UPLOAD");

        String ruleSignature = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(upload), keyPairUpload.getPrivate())
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString(false);

        ValidationRuleDto validationRuleDto = new ValidationRuleDto();
        validationRuleDto.setValidTo(validationRule.getValidTo());
        validationRuleDto.setValidFrom(validationRule.getValidFrom());
        validationRuleDto.setVersion(validationRule.getVersion());
        validationRuleDto.setCms(ruleSignature);

        Map<String, List<ValidationRuleDto>> response = Map.of(validationRule.getIdentifier(), List.of(validationRuleDto));

        when(restClientMock.downloadValidationRule("EU"))
            .thenReturn(ResponseEntity.ok(response));

        when(restClientMock.downloadCountryList())
            .thenReturn(ResponseEntity.ok(Collections.singletonList("EU")));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.UPLOAD))
            .thenReturn(ResponseEntity.status(500).build());

        Assertions.assertEquals(0, connector.getValidationRules().size());

        when(restClientMock.downloadCountryList())
            .thenReturn(ResponseEntity.ok(Collections.singletonList("EU")));

        doThrow(new FeignException.InternalServerError("", dummyRequest(), null, null))
            .when(restClientMock).getTrustedCertificates(CertificateTypeDto.UPLOAD);

        Assertions.assertEquals(0, connector.getValidationRules().size());
    }

    @Test
    void shouldReturnEmptyListWhenDscDownloadFails() {
        when(restClientMock.downloadCountryList())
            .thenReturn(ResponseEntity.ok(Collections.singletonList("EU")));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.UPLOAD))
            .thenReturn(ResponseEntity.ok(Collections.emptyList()));

        when(restClientMock.downloadValidationRule("EU"))
            .thenReturn(ResponseEntity.status(500).build());

        Assertions.assertEquals(0, connector.getValidationRules().size());

        when(restClientMock.downloadCountryList())
            .thenReturn(ResponseEntity.ok(Collections.singletonList("EU")));

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.UPLOAD))
            .thenReturn(ResponseEntity.ok(Collections.emptyList()));

        doThrow(new FeignException.InternalServerError("", dummyRequest(), null, null))
            .when(restClientMock).getTrustedCertificates(CertificateTypeDto.DSC);

        Assertions.assertEquals(0, connector.getValidationRules().size());
    }

    @Test
    void testTrustAnchorCheckInvalidSignatureFormat() throws Exception {

        KeyPair keyPairUpload = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate upload = CertificateTestUtils.generateCertificate(keyPairUpload, "EU", "UPLOAD");

        TrustListItemDto uploadTrustListItem = new TrustListItemDto();
        uploadTrustListItem.setCountry("EU");
        uploadTrustListItem.setKid("KID_EU_UPLOAD");
        uploadTrustListItem.setCertificateType(CertificateTypeDto.UPLOAD);
        uploadTrustListItem.setTimestamp(ZonedDateTime.now());
        uploadTrustListItem.setSignature("BADSIGNATURE");
        uploadTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(upload));
        uploadTrustListItem.setRawData(Base64.getEncoder().encodeToString(upload.getEncoded()));

        String ruleSignature = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(upload), keyPairUpload.getPrivate())
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString(false);

        ValidationRuleDto validationRuleDto = new ValidationRuleDto();
        validationRuleDto.setValidTo(validationRule.getValidTo());
        validationRuleDto.setValidFrom(validationRule.getValidFrom());
        validationRuleDto.setVersion(validationRule.getVersion());
        validationRuleDto.setCms(ruleSignature);

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.UPLOAD))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(uploadTrustListItem)));

        when(restClientMock.downloadCountryList())
            .thenReturn(ResponseEntity.ok(Collections.singletonList("EU")));

        Map<String, List<ValidationRuleDto>> response = Map.of(validationRule.getIdentifier(), List.of(validationRuleDto));

        when(restClientMock.downloadValidationRule("EU"))
            .thenReturn(ResponseEntity.ok(response));

        Assertions.assertEquals(0, connector.getValidationRules().size());
        Assertions.assertNotNull(connector.getLastUpdated());
    }

    @Test
    void testTrustAnchorCheckWrongSignature() throws Exception {

        KeyPair anotherKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate anotherCert = CertificateTestUtils.generateCertificate(anotherKeyPair, "EU", "another");

        KeyPair keyPairUpload = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate upload = CertificateTestUtils.generateCertificate(keyPairUpload, "EU", "UPLOAD");

        String wrongSignature = new SignedCertificateMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(testKeyStore.getTrustAnchor()), testKeyStore.getTrustAnchorPrivateKey())
            .withPayload(certificateUtils.convertCertificate(anotherCert))
            .buildAsString(true);

        TrustListItemDto uploadTrustListItem = new TrustListItemDto();
        uploadTrustListItem.setCountry("EU");
        uploadTrustListItem.setKid("KID_EU_UPLOAD");
        uploadTrustListItem.setCertificateType(CertificateTypeDto.UPLOAD);
        uploadTrustListItem.setTimestamp(ZonedDateTime.now());
        uploadTrustListItem.setSignature(wrongSignature);
        uploadTrustListItem.setThumbprint(certificateUtils.getCertThumbprint(upload));
        uploadTrustListItem.setRawData(Base64.getEncoder().encodeToString(upload.getEncoded()));

        String ruleSignature = new SignedStringMessageBuilder()
            .withSigningCertificate(certificateUtils.convertCertificate(upload), keyPairUpload.getPrivate())
            .withPayload(objectMapper.writeValueAsString(validationRule))
            .buildAsString(false);

        ValidationRuleDto validationRuleDto = new ValidationRuleDto();
        validationRuleDto.setValidTo(validationRule.getValidTo());
        validationRuleDto.setValidFrom(validationRule.getValidFrom());
        validationRuleDto.setVersion(validationRule.getVersion());
        validationRuleDto.setCms(ruleSignature);

        when(restClientMock.getTrustedCertificates(CertificateTypeDto.UPLOAD))
            .thenReturn(ResponseEntity.ok(Collections.singletonList(uploadTrustListItem)));

        when(restClientMock.downloadCountryList())
            .thenReturn(ResponseEntity.ok(Collections.singletonList("EU")));

        Map<String, List<ValidationRuleDto>> response = Map.of(validationRule.getIdentifier(), List.of(validationRuleDto));

        when(restClientMock.downloadValidationRule("EU"))
            .thenReturn(ResponseEntity.ok(response));

        Assertions.assertEquals(0, connector.getValidationRules().size());
        Assertions.assertNotNull(connector.getLastUpdated());
    }

    /**
     * Method to create dummy request which is required to throw FeignExceptions.
     */
    private Request dummyRequest() {
        return Request.create(Request.HttpMethod.GET, "url", new HashMap<>(), null, new RequestTemplate());
    }
    
    private void assertEquals(ValidationRule v1, ValidationRule v2) {
        Assertions.assertEquals(v1.getIdentifier(), v2.getIdentifier());
        Assertions.assertEquals(v1.getType(), v2.getType());
        Assertions.assertEquals(v1.getCountry(), v2.getCountry());
        Assertions.assertEquals(v1.getRegion(), v2.getRegion());
        Assertions.assertEquals(v1.getVersion(), v2.getVersion());
        Assertions.assertEquals(v1.getSchemaVersion(), v2.getSchemaVersion());
        Assertions.assertEquals(v1.getEngine(), v2.getEngine());
        Assertions.assertEquals(v1.getEngineVersion(), v2.getEngineVersion());
        Assertions.assertEquals(v1.getCertificateType(), v2.getCertificateType());
        Assertions.assertEquals(v1.getDescription(), v2.getDescription());
        Assertions.assertEquals(v1.getValidFrom().toEpochSecond(), v2.getValidFrom().toEpochSecond());
        Assertions.assertEquals(v1.getValidTo().toEpochSecond(), v2.getValidTo().toEpochSecond());
        Assertions.assertEquals(v1.getAffectedFields(), v2.getAffectedFields());
        Assertions.assertEquals(v1.getLogic(), v2.getLogic());
    }

}
