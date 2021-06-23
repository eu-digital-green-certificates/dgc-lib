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
import eu.europa.ec.dgc.testdata.DgcTestKeyStore;
import eu.europa.ec.dgc.utils.CertificateUtils;
import feign.FeignException;
import feign.Request;
import feign.RequestTemplate;
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
class CountryListDownloadConnectorTest {

    @MockBean
    DgcGatewayConnectorRestClient restClientMock;

    @Autowired
    DgcGatewayCountryListDownloadConnector connector;

    @Test
    void testDownloadOfCountryList() {

        when(restClientMock.downloadCountryList())
            .thenReturn(ResponseEntity.ok(List.of("EU", "DE")));

        List<String> result = connector.getCountryList();
        Assertions.assertEquals(2, result.size());
        Assertions.assertEquals("EU", result.get(0));
        Assertions.assertEquals("DE", result.get(1));
        Assertions.assertNotNull(connector.getLastUpdated());
    }

    @Test
    void shouldReturnEmptyListWhenDownloadFails() {
        when(restClientMock.downloadCountryList())
            .thenReturn(ResponseEntity.status(500).build());

        Assertions.assertEquals(0, connector.getCountryList().size());

        doThrow(new FeignException.InternalServerError("", dummyRequest(), null))
            .when(restClientMock).downloadCountryList();

        Assertions.assertEquals(0, connector.getCountryList().size());
    }

    /**
     * Method to create dummy request which is required to throw FeignExceptions.
     */
    private Request dummyRequest() {
        return Request.create(Request.HttpMethod.GET, "url", new HashMap<>(), null, new RequestTemplate());
    }

}
