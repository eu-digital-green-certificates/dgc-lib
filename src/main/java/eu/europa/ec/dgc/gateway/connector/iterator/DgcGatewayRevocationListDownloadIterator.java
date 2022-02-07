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

package eu.europa.ec.dgc.gateway.connector.iterator;

import eu.europa.ec.dgc.gateway.connector.client.DgcGatewayConnectorRestClient;
import eu.europa.ec.dgc.gateway.connector.dto.RevocationBatchListDto;
import eu.europa.ec.dgc.gateway.connector.dto.RevocationBatchListDto.RevocationBatchListItemDto;
import feign.FeignException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;


/**
 * This class provides an Iterator for downloading the revocation List parts from the gateway.
 */

@ConditionalOnProperty("dgc.gateway.connector.enabled")
@Slf4j
public class DgcGatewayRevocationListDownloadIterator implements Iterator<List<RevocationBatchListItemDto>> {

    private final DgcGatewayConnectorRestClient dgcGatewayConnectorRestClient;

    private final DateTimeFormatter dateFormat;

    private ZonedDateTime lastUpdated = null;

    private List<RevocationBatchListItemDto> nextData;

    private boolean hasNext = false;

    /**
     * Creates a new Iterator instance for downloading the revocation list from the dgc gateway.
     * The If-Modified-Since Header is set to the default value and the download should start with the first
     * part of the revocation list.
     *
     * @param dgcGatewayConnectorRestClient The rest client for the connection to the dgc gateway
     */

    public DgcGatewayRevocationListDownloadIterator(DgcGatewayConnectorRestClient dgcGatewayConnectorRestClient) {
        this(dgcGatewayConnectorRestClient, ZonedDateTime.parse("2021-06-01T00:00:00Z"));
    }

    /**
     * Creates a new Iterator instance for downloading the revocation list from the dgc gateway.
     * The If-Modified-Since Header is set to the given value and only newer parts of the revocation list
     * are downloaded.
     *
     * @param dgcGatewayConnectorRestClient The rest client for the connection to the dgc gateway
     * @param ifModifiedSinceDate           The value for the If-Modified-Since date
     */

    public DgcGatewayRevocationListDownloadIterator(DgcGatewayConnectorRestClient dgcGatewayConnectorRestClient,
                                                    ZonedDateTime ifModifiedSinceDate) {
        this.dgcGatewayConnectorRestClient = dgcGatewayConnectorRestClient;
        dateFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX");
        setIfModifiedSinceDate(ifModifiedSinceDate);
    }

    /**
     * Sets the If-Modified-Since date and downloads the next newer part of the revocation list from the dgc gateway.
     *
     * @param dateTime The value for the If-Modified-Since date
     */
    public void setIfModifiedSinceDate(ZonedDateTime dateTime) {
        lastUpdated = dateTime;
        fetchNextRevocationListPart();
    }

    @Override
    public boolean hasNext() {
        return hasNext;
    }

    @Override
    public List<RevocationBatchListItemDto> next() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }
        List<RevocationBatchListItemDto> returnData = nextData;
        fetchNextRevocationListPart();
        return returnData;
    }

    protected String toIsoO8601(ZonedDateTime dateTime) {
        return dateTime.format(dateFormat);
    }

    private void fetchNextRevocationListPart() {
        log.info("Fetching Revocation List from DGCG with If-Modified-Since date: {}", toIsoO8601(lastUpdated));

        ResponseEntity<RevocationBatchListDto> responseEntity;

        hasNext = false;
        nextData = null;

        try {
            responseEntity = dgcGatewayConnectorRestClient.downloadRevocationList(toIsoO8601(lastUpdated));
        } catch (FeignException e) {
            log.error("Download of revocation list failed. DGCG responded with status code: {}",
                e.status());
            return;
        }

        if (responseEntity.getStatusCode() != HttpStatus.OK
            && responseEntity.getStatusCode() != HttpStatus.NO_CONTENT) {

            log.error("DGCG responded with unexpected status code: {}",
                responseEntity.getStatusCode());
            return;
        }

        RevocationBatchListDto downloadedBatchList = responseEntity.getBody();

        if (responseEntity.getStatusCode() == HttpStatus.NO_CONTENT
            || downloadedBatchList == null) {
            log.debug("No Content received for download with If-Modified-Since date: {}", toIsoO8601(lastUpdated));
        } else {

            if (downloadedBatchList.getBatches().isEmpty()) {
                log.debug("No Content received for download with If-Modified-Since date: {}", toIsoO8601(lastUpdated));
            } else {
                nextData = downloadedBatchList.getBatches();
                hasNext = true;
                lastUpdated = nextData.get(nextData.size() - 1).getDate();
            }
        }
    }
}
