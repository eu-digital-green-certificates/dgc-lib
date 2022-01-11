package eu.europa.ec.dgc.gateway.connector.exception;

import lombok.Getter;

public class RevocationBatchGoneException extends RuntimeException {
    @Getter
    private String batchId;

    public RevocationBatchGoneException(String message, String batchId) {
        super(message);
        this.batchId = batchId;
    }

}
