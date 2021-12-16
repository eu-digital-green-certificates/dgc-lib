package eu.europa.ec.dgc.generation;

import java.time.LocalDate;
import java.time.LocalDateTime;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import org.junit.jupiter.api.Test;

class DccVaccinationBuilderTest {
    @Test
    void genTestJson()  {
        DccVaccinationBuilder dccVaccinationBuilder = new DccVaccinationBuilder();
        dccVaccinationBuilder.gn("Artur").fn("Trzewik").gnt("ARTUR").fnt("TRZEWIK").dob(LocalDate.parse("1973-01-01"));
        dccVaccinationBuilder.dgci("URN:UVCI:01:OS:B5921A35D6A0D696421B3E2462178297I")
                .country("DE")
                .certificateIssuer("Dr Who")
                .doseNumber(1)
                .totalSeriesOfDoses(2)
                .dateOfVaccination(LocalDateTime.now())
                .vaccineOrProphylaxis("1119349007")
                .medicalProduct("EU/1/20/1507")
                .marketingAuthorization("ORG-100001699");
        String jsonString = dccVaccinationBuilder.toJsonString();
        assertNotNull(jsonString);
        System.out.println(jsonString);
    }
}
