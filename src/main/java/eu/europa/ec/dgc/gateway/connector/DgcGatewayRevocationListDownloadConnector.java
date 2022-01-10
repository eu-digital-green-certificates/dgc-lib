package eu.europa.ec.dgc.gateway.connector;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import eu.europa.ec.dgc.gateway.connector.client.DgcGatewayConnectorRestClient;
import eu.europa.ec.dgc.gateway.connector.dto.RevocationBatchListDto;
import eu.europa.ec.dgc.gateway.connector.dto.ValidationRuleDto;
import eu.europa.ec.dgc.gateway.connector.iterator.DgcGatewayRevocationListDownloadIterator;
import eu.europa.ec.dgc.gateway.connector.model.ValidationRule;
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
    public String getRevocationListBatchById(String batchId) {

        ResponseEntity<String> responseEntity;

        try {
            responseEntity = dgcGatewayConnectorRestClient.downloadBatch(batchId);
        } catch (FeignException e) {
            log.error("Download of revocation list batch failed. DGCG responded with status code: {}",
                e.status());
            return null;
        }

        if (responseEntity.getStatusCode() != HttpStatus.OK) {

            log.error("Download of revocation list batch failed. DGCG responded with status code: {}",
                responseEntity.getStatusCode());
            return null;
        }

        String cms = responseEntity.getBody();

        if (!checkCmsSignature(cms)) {
            log.error("CMS check failed for revocation batch: {}", batchId);
            return null;
        }

        String rawJson = map(cms);

        return rawJson;
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

    private String map(String cms) {
        SignedStringMessageParser parser =
            new SignedStringMessageParser(cms);
        /*
        try {
            objectMapper.configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, true);
            return objectMapper.readValue(json, clazz);
        } catch (JsonProcessingException e) {
            throw new RevocationBatchServiceException(
                RevocationBatchServiceException.Reason.INVALID_JSON,
                "JSON could not be parsed");
        }
        */
        //        try {
        //            ValidationRule parsedRule = objectMapper.readValue(parser.getPayload(), ValidationRule.class);
        //            parsedRule.setRawJson(parser.getPayload());
        //            return parsedRule;
        //        } catch (JsonProcessingException e) {
        //            log.error("Failed to parse Validation Rule JSON: {}", e.getMessage());
        //            return null;
        //        }
        return parser.getPayload();

    }

}
