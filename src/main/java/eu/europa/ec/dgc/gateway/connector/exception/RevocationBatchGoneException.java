package eu.europa.ec.dgc.gateway.connector.exception;

import lombok.Getter;

@Getter
public class RevocationBatchGoneException extends RuntimeException {

    private final String batchId;

    public RevocationBatchGoneException(String message, String batchId) {
        super(message);
        this.batchId = batchId;
    }

}
