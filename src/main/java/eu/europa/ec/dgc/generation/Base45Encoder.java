package eu.europa.ec.dgc.generation;

/**
 * Base45 Encoder.
 */
public class Base45Encoder {
    private static final String ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

    private Base45Encoder() {
    }

    /**
     * Encode a byte array to Base45 String.
     *
     * @param bytes bytes to encode
     * @return encoded string
     */
    public static String encodeToString(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < bytes.length; i += 2) {
            if (bytes.length - i > 1) {
                int x = ((bytes[i] & 0xFF) << 8) + (bytes[i + 1] & 0xFF);
                int e = x / (45 * 45);
                int y = x % (45 * 45);
                int d = y / 45;
                int c = y % 45;
                result.append(ALPHABET.charAt(c)).append(ALPHABET.charAt(d)).append(ALPHABET.charAt(e));
            } else {
                int x = bytes[i] & 0xFF;
                int d = x / 45;
                int c = x % 45;
                result.append(ALPHABET.charAt(c)).append(ALPHABET.charAt(d));
            }
        }
        return result.toString();
    }
}
