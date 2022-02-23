package eu.europa.ec.dgc.gateway.connector.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TrustedReference {

    private String uuid;

    private String version;

    private String country;

    private ReferenceType type;

    private String service;

    private String thumbprint;

    private String name;

    private String sslPublicKey;

    private String contentType;

    private SignatureType signatureType;

    private String referenceVersion;

    public enum ReferenceType {
        DCC,
        FHIR
    }

    public enum SignatureType {
        CMS,
        JWS,
        NONE
    }
}
