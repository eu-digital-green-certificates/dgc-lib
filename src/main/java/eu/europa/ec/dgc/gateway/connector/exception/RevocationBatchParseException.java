package eu.europa.ec.dgc.gateway.connector.exception;

import lombok.Getter;

@Getter
public class RevocationBatchParseException extends RuntimeException {

    private final String batchId;

    public RevocationBatchParseException(String message, String batchId) {
        super(message);
        this.batchId = batchId;
    }

}

