package eu.europa.ec.dgc.gateway.connector.model;

import java.time.ZonedDateTime;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TrustedIssuer {

    private String url;

    private UrlType type;

    private String country;

    private String thumbprint;

    private String sslPublicKey;

    private String keyStorageType;

    private String signature;

    private ZonedDateTime timestamp;

    public enum UrlType {
        HTTP,
        DID
    }
}
