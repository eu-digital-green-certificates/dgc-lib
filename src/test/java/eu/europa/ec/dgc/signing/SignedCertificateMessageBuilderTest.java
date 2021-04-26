package eu.europa.ec.dgc.signing;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class SignedCertificateMessageBuilderTest {

    @Test
    public void testDefineConstructor() {
        assertNotEquals(new SignedCertificateMessageBuilder(), null);
    }
}
