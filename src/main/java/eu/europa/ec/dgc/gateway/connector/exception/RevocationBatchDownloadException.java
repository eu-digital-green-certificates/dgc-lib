package eu.europa.ec.dgc.gateway.connector.exception;

import lombok.Getter;

public class RevocationBatchDownloadException extends RuntimeException {

    @Getter
    private int status = 500;

    public RevocationBatchDownloadException(String message, Throwable inner) {
        super(message, inner);
    }

    public RevocationBatchDownloadException(String message) {
        super(message);
    }

    public RevocationBatchDownloadException(String message, Throwable inner, int status) {
        super(message, inner);
        this.status = status;
    }

    public RevocationBatchDownloadException(String message, int status) {
        super(message);
        this.status = status;
    }
}
