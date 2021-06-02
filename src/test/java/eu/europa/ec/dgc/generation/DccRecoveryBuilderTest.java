package eu.europa.ec.dgc.generation;

import java.time.LocalDate;
import java.time.LocalDateTime;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DccRecoveryBuilderTest {
    @Test
    void genTestJson()  {
        DccRecoveryBuilder dccRecoveryBuilder = new DccRecoveryBuilder();
        dccRecoveryBuilder.gn("Artur").fn("Trzewik").gnt("ARTUR").fnt("TRZEWIK").dob("1973-01-01");
        dccRecoveryBuilder.dgci("URN:UVCI:01:OS:B5921A35D6A0D696421B3E2462178297I")
                .country("DE")
                .certificateIssuer("Dr Who")
                .firstDayPositiveTest(LocalDate.now())
                .certificateValidFrom(LocalDate.now())
                .certificateValidUnitl(LocalDate.now());
        String jsonString = dccRecoveryBuilder.toJsonString();
        assertNotNull(jsonString);
        System.out.println(jsonString);
    }
}