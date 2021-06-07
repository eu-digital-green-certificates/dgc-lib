package eu.europa.ec.dgc.generation;

import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

class Base45EncoderTest {

    @Test
    void encodeTest() {
        assertEquals("7WE QE",Base45Encoder.encodeToString("test".getBytes(StandardCharsets.UTF_8)));

        byte[] bytes = new byte[] { 0, 2, -2, 30, -12, 23, -23, -40};
        assertEquals("200T5WR%UEPT",Base45Encoder.encodeToString(bytes));
    }
}