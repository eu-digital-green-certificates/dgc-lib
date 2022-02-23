package eu.europa.ec.dgc.gateway.connector.mapper;

import eu.europa.ec.dgc.gateway.connector.dto.TrustedIssuerDto;
import eu.europa.ec.dgc.gateway.connector.model.TrustedIssuer;
import java.util.List;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface TrustedIssuerMapper {

    TrustedIssuer map(TrustedIssuerDto trustedIssuerDto);

    List<TrustedIssuer> map(List<TrustedIssuerDto> trustedIssuerDto);
}
