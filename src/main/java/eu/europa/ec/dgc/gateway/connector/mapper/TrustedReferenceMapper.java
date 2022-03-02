package eu.europa.ec.dgc.gateway.connector.mapper;

import eu.europa.ec.dgc.gateway.connector.dto.TrustedReferenceDto;
import eu.europa.ec.dgc.gateway.connector.model.TrustedReference;
import java.util.List;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface TrustedReferenceMapper {

    TrustedReference map(TrustedReferenceDto trustedReferenceDto);

    List<TrustedReference> map(List<TrustedReferenceDto> trustedReferenceDto);
}
