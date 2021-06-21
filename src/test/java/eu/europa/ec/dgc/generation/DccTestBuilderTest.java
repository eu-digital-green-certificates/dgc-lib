package eu.europa.ec.dgc.generation;

import java.time.LocalDate;
import java.time.LocalDateTime;
import org.junit.jupiter.api.Assertions;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import org.junit.jupiter.api.Test;

class DccTestBuilderTest {
    @Test
    void requiredFieldsFormat() throws Exception {
        DccTestBuilder dccTestBuilder = new DccTestBuilder();
        dccTestBuilder.fn("Tester");
        dccTestBuilder.fnt("TESTER");
        Assertions.assertThrows(IllegalStateException.class, () -> {
            dccTestBuilder.toJsonString();
        });
    }

    @Test
    void patternMatch() {
        DccTestBuilder dccTestBuilder = new DccTestBuilder();
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
            dccTestBuilder.fnt("tester");
        });
    }

    @Test
    void genTestJson()  {
        DccTestBuilder dccTestBuilder = new DccTestBuilder();
        dccTestBuilder.gn("Artur").fn("Trzewik").gnt("ARTUR").fnt("TRZEWIK").dob(LocalDate.parse("1973-01-01"));
        dccTestBuilder.detected(false)
                .dgci("URN:UVCI:01:OS:B5921A35D6A0D696421B3E2462178297I")
                .country("DE")
                .testTypeRapid(true)
                .testingCentre("Hochdahl")
                .testIdentifier("1833")
                .testName("Example name")
                .certificateIssuer("Dr Who")
                .sampleCollection(LocalDateTime.now());
        String jsonString = dccTestBuilder.toJsonString();
        assertNotNull(jsonString);
        System.out.println(jsonString);
    }

}