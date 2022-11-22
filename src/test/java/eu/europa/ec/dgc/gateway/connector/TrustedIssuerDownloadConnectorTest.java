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
import eu.europa.ec.dgc.gateway.connector.model.QueryParameter;
import eu.europa.ec.dgc.gateway.connector.model.TrustedIssuer;
import eu.europa.ec.dgc.testdata.TrustedIssuerTestHelper;
import feign.FeignException;
import feign.Request;
import feign.RequestTemplate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.ResponseEntity;

@SpringBootTest
@Slf4j
class TrustedIssuerDownloadConnectorTest {

    @MockBean
    DgcGatewayConnectorRestClient restClientMock;

    @Autowired
    DgcGatewayTrustedIssuerDownloadConnector connector;

    @Autowired
    TrustedIssuerTestHelper trustedIssuerTestHelper;

    @Test
    void testDownloadOfTrustedIssuerList() throws Exception {
        Map<String, String> param = new HashMap<>();

        when(restClientMock.downloadTrustedIssuers(param))
            .thenReturn(ResponseEntity.ok(
                List.of(trustedIssuerTestHelper.createTrustedIssuer("DE"),
                    trustedIssuerTestHelper.createTrustedIssuer("EU"))));

        List<TrustedIssuer> result = connector.getTrustedIssuers();
        Assertions.assertEquals(2, result.size());
        Assertions.assertEquals("DE", result.get(0).getCountry());
        Assertions.assertEquals("EU", result.get(1).getCountry());

    }

    @Test
    void shouldReturnEmptyListWhenDownloadFails() {
        Map<String, String> param = new HashMap<>();

        when(restClientMock.downloadTrustedIssuers(param))
            .thenReturn(ResponseEntity.status(500).build());

        Assertions.assertEquals(0, connector.getTrustedIssuers().size());

        doThrow(new FeignException.InternalServerError("", dummyRequest(), null, null))
            .when(restClientMock).downloadCountryList();

        Assertions.assertEquals(0, connector.getTrustedIssuers().size());
    }

    /**
     * Method to create dummy request which is required to throw FeignExceptions.
     */
    private Request dummyRequest() {
        return Request.create(Request.HttpMethod.GET, "url", new HashMap<>(), null, new RequestTemplate());
    }

    @Test
    void setQueryParameters() throws Exception {
        Map<String, String> param = new HashMap<>();
        param.put("country", "DE");

        when(restClientMock.downloadTrustedIssuers(param))
            .thenReturn(ResponseEntity.ok(
                List.of(trustedIssuerTestHelper.createTrustedIssuer("DE"))));

        connector.setQueryParameter(QueryParameter.COUNTRY_CODE, "DE");
        List<TrustedIssuer> result = connector.getTrustedIssuers();

        Assertions.assertEquals(1, result.size());
        Assertions.assertEquals("DE", result.get(0).getCountry());

    }

    @Test
    void setWrongQueryFormat() {
        assertThrows(IllegalArgumentException.class, () ->
            connector.setQueryParameter(QueryParameter.WITH_FEDERATION, List.of(true, false)));
    }

}
