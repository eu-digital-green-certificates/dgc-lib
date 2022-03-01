package eu.europa.ec.dgc.gateway.connector.mapper;

import eu.europa.ec.dgc.gateway.connector.dto.TrustListItemDto;
import eu.europa.ec.dgc.gateway.connector.dto.TrustedCertificateTrustListDto;
import java.util.List;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface TrustedCertificateMapper {

    List<TrustListItemDto> map(List<TrustedCertificateTrustListDto> trustedCertificateTrustListDto);

    @Mapping(source = "group", target = "certificateType")
    @Mapping(source = "certificate", target = "rawData")
    @Mapping(target = "timestamp", ignore = true)
    @Mapping(target = "thumbprint", ignore = true)
    TrustListItemDto map(TrustedCertificateTrustListDto trustedCertificateTrustListDto);

}
