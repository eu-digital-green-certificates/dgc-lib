package eu.europa.ec.dgc.gateway.connector;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.gateway.connector.client.DgcGatewayConnectorRestClient;
import eu.europa.ec.dgc.gateway.connector.dto.RevocationBatchDto;
import eu.europa.ec.dgc.gateway.connector.exception.RevocationBatchDownloadException;
import eu.europa.ec.dgc.gateway.connector.exception.RevocationBatchGoneException;
import eu.europa.ec.dgc.gateway.connector.exception.RevocationBatchParseException;
import eu.europa.ec.dgc.gateway.connector.iterator.DgcGatewayRevocationListDownloadIterator;
import eu.europa.ec.dgc.signing.SignedMessageParser;
import eu.europa.ec.dgc.signing.SignedStringMessageParser;
import feign.FeignException;
import java.time.ZonedDateTime;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Scope;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@ConditionalOnProperty("dgc.gateway.connector.enabled")
@Service
@Scope(ConfigurableBeanFactory.SCOPE_SINGLETON)
@RequiredArgsConstructor
@Slf4j
public class DgcGatewayRevocationListDownloadConnector {

    private final DgcGatewayConnectorRestClient dgcGatewayConnectorRestClient;
    private final ObjectMapper objectMapper;

    /**
     * Gets a revocation list iterator, for partly downloading the revocation list.
     * The if-modified-since header is set to the default value to start at the beginning of the list.
     * @return revocation list iterator
     */
    public DgcGatewayRevocationListDownloadIterator getRevocationListDownloadIterator() {
        return new DgcGatewayRevocationListDownloadIterator(dgcGatewayConnectorRestClient);
    }

    /**
     * Gets a revocation list iterator, for partly downloading the revocation list.
     * The if-modified-since header is set to the value of the parameter. Only newer part of the list are downloaded.
     * @param ifModifiedSinceDate The value for the if-modified-since header
     * @return revocation list iterator
     */
    public DgcGatewayRevocationListDownloadIterator getRevocationListDownloadIterator(
        ZonedDateTime ifModifiedSinceDate) {

        return new DgcGatewayRevocationListDownloadIterator(dgcGatewayConnectorRestClient, ifModifiedSinceDate);
    }

    /**
     * Gets the revocation list batch data for a given batchId.
     * @param batchId the id of the batch to download.
     * @return the batch data.
     */
    public RevocationBatchDto getRevocationListBatchById(String batchId) throws RevocationBatchDownloadException,
        RevocationBatchGoneException, RevocationBatchParseException {

        ResponseEntity<String> responseEntity;

        try {
            responseEntity = dgcGatewayConnectorRestClient.downloadBatch(batchId);
        } catch (FeignException e) {
            log.error("Download of revocation list batch failed. DGCG responded with status code: {}", e.status());

            if (e.status() == HttpStatus.GONE.value()) {
                throw new RevocationBatchGoneException(String.format("Batch already gone: {}", batchId),batchId);
            }

            throw new RevocationBatchDownloadException("Batch download failed with exception.", e);
        }

        if (responseEntity.getStatusCode() != HttpStatus.OK) {
            int statusCode = responseEntity.getStatusCode().value();
            log.error("Download of revocation list batch failed. DGCG responded with status code: {}", statusCode);

            throw new RevocationBatchDownloadException(
                String.format("Batch download failed with unexpected response. Response status code: {}", statusCode),
                    statusCode);
        }

        String cms = responseEntity.getBody();

        if (!checkCmsSignature(cms)) {
            log.error("CMS check failed for revocation batch: {}", batchId);
            throw new RevocationBatchParseException(
                String.format("CMS check failed for revocation batch: {}", batchId), batchId);
        }

        return map(cms, batchId);
    }

    private boolean checkCmsSignature(String cms) {
        SignedStringMessageParser parser =
            new SignedStringMessageParser(cms);

        if (parser.getParserState() != SignedMessageParser.ParserState.SUCCESS) {
            log.error("Invalid CMS for Revocation List Batch.");
            return false;
        }

        if (!parser.isSignatureVerified()) {
            log.error("Invalid CMS Signature for Revocation List Batch");
            return false;
        }

        return true;
    }

    private RevocationBatchDto map(String cms, String batchId) {
        SignedStringMessageParser parser =
            new SignedStringMessageParser(cms);

        try {
            objectMapper.configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, true);
            return objectMapper.readValue(parser.getPayload(), RevocationBatchDto.class);
        } catch (JsonProcessingException e) {
            log.error("Failed to parse revocation batch JSON: {}", e.getMessage());

            throw new RevocationBatchParseException(
                String.format("Failed to parse revocation batch JSON: {}", e.getMessage()), batchId);
        }

    }

}
