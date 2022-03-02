package eu.europa.ec.dgc.gateway.connector.model;

import java.io.Serializable;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@Getter
public class QueryParameter<T extends Serializable> {

    public static final QueryParameter<String> GROUP =
        new QueryParameter<>("group", true, String.class);

    public static final QueryParameter<String> COUNTRY_CODE =
        new QueryParameter<>("country", true, String.class);

    public static final QueryParameter<String> DOMAIN =
        new QueryParameter<>("domain", true, String.class);

    public static final QueryParameter<String> REFERENCE_TYPE =
        new QueryParameter<>("referenceType", true, String.class);

    public static final QueryParameter<String> SIGNATURE_TYPE =
        new QueryParameter<>("signatureType", true, String.class);

    public static final QueryParameter<Boolean> WITH_FEDERATION =
        new QueryParameter<>("withFederation", false, Boolean.class);

    private final String queryParamName;
    private final Boolean arrayValue;
    private final Class<T> queryParamType;
}
