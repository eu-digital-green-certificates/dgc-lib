package eu.europa.ec.dgc.generation;

import java.nio.charset.StandardCharsets;
import java.util.Random;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

class Base45EncoderTest {

    @Test
    void encodeTest() {
        assertEquals("7WE QE",Base45Encoder.encodeToString("test".getBytes(StandardCharsets.UTF_8)));

        byte[] bytes = new byte[] { 0, 2, -2, 30, -12, 23, -23, -40};
        assertEquals("200T5WR%UEPT",Base45Encoder.encodeToString(bytes));
    }

    @Test
    void encodingDecoding() {
        for (int i = 16; i<20; i++) {
            byte[] in = new byte[i];
            Random rnd = new Random();
            rnd.nextBytes(in);

            String encoded = Base45Encoder.encodeToString(in);
            byte[] out = Base45Encoder.decodeFromString(encoded);
            assertArrayEquals(in, out);
        }
    }
}
