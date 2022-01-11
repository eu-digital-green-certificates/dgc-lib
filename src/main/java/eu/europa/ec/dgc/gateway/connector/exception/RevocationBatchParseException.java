package eu.europa.ec.dgc.gateway.connector.exception;

import lombok.Getter;

public class RevocationBatchParseException extends RuntimeException {
    @Getter
    private String batchId;

    public RevocationBatchParseException(String message, String batchId) {
        super(message);
        this.batchId = batchId;
    }

}

