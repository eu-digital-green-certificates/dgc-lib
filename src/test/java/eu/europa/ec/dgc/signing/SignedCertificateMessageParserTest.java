package eu.europa.ec.dgc.signing;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class SignedCertificateMessageParserTest {

    @Test
    public void testDefineConstructor() {
        assertNotNull(new SignedCertificateMessageParser("Hello World".getBytes()));
    }
}
