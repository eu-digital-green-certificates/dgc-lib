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
import feign.FeignException;
import feign.Request;
import feign.RequestTemplate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
class ValueSetDownloadConnectorTest {

    @MockBean
    DgcGatewayConnectorRestClient restClientMock;

    @Autowired
    DgcGatewayValueSetDownloadConnector connector;

    @Test
    void testDownloadOfValueSets() {

        when(restClientMock.downloadValueSetIds())
            .thenReturn(ResponseEntity.ok(List.of("VS1", "VS2")));

        when(restClientMock.downloadValueSet("VS1"))
            .thenReturn(ResponseEntity.ok("VS1CONTENT"));

        when(restClientMock.downloadValueSet("VS2"))
            .thenReturn(ResponseEntity.ok("VS2CONTENT"));

        Map<String, String> result = connector.getValueSets();
        Assertions.assertEquals(2, result.size());
        Assertions.assertEquals("VS1CONTENT", result.get("VS1"));
        Assertions.assertEquals("VS2CONTENT", result.get("VS2"));
        Assertions.assertNotNull(connector.getLastUpdated());
    }

    @Test
    void shouldReturnEmptyListWhenDownloadOfValueSetIdsFails() {
        when(restClientMock.downloadValueSetIds())
            .thenReturn(ResponseEntity.status(500).build());

        Assertions.assertEquals(0, connector.getValueSets().size());

        doThrow(new FeignException.InternalServerError("", dummyRequest(), null, null))
            .when(restClientMock).downloadValueSetIds();

        Assertions.assertEquals(0, connector.getValueSets().size());
    }

    @Test
    void shouldReturnPartialListWhenDownloadOfOneValueSetFails() {
        when(restClientMock.downloadValueSetIds())
            .thenReturn(ResponseEntity.ok(List.of("VS1", "VS2")));

        when(restClientMock.downloadValueSet("VS1"))
            .thenReturn(ResponseEntity.status(500).build());

        when(restClientMock.downloadValueSet("VS2"))
            .thenReturn(ResponseEntity.ok("VS2CONTENT"));

        Map<String, String> valueSets = connector.getValueSets();
        Assertions.assertEquals(1, valueSets.size());
        Assertions.assertEquals("VS2CONTENT", valueSets.get("VS2"));

        doThrow(new FeignException.InternalServerError("", dummyRequest(), null, null))
            .when(restClientMock).downloadValueSet("VS1");

        valueSets = connector.getValueSets();
        Assertions.assertEquals(1, valueSets.size());
        Assertions.assertEquals("VS2CONTENT", valueSets.get("VS2"));
    }

    /**
     * Method to create dummy request which is required to throw FeignExceptions.
     */
    private Request dummyRequest() {
        return Request.create(Request.HttpMethod.GET, "url", new HashMap<>(), null, new RequestTemplate());
    }

}
