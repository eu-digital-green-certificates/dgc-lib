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

    /**
     * Decode base45 string to byte array.
     *
     * @param encodedString string
     * @return bytes
     */
    public static byte[] decodeFromString(String encodedString) {
        int remainderSize = encodedString.length() % 3;
        if (remainderSize == 1) {
            throw new IllegalArgumentException("wrong remainder length: " + remainderSize);
        }
        int wholeChunkCount = encodedString.length() / 3;
        byte[] result = new byte[wholeChunkCount * 2 + (remainderSize == 2 ? 1 : 0)];
        int resultIndex = 0;
        int wholeChunkLength = wholeChunkCount * 3;
        for (int i = 0; i < wholeChunkLength; ) {
            int c0 = ALPHABET.indexOf(encodedString.charAt(i++));
            int c1 = ALPHABET.indexOf(encodedString.charAt(i++));
            int c2 = ALPHABET.indexOf(encodedString.charAt(i++));
            if (c0 < 0 || c1 < 0 || c2 < 0) {
                throw new IllegalArgumentException("unsupported input character near pos: " + i);
            }
            int val = c0 + 45 * c1 + 45 * 45 * c2;
            if (val > 0xFFFF) {
                throw new IllegalArgumentException();
            }
            result[resultIndex++] = (byte) (val / 256);
            result[resultIndex++] = (byte) (val % 256);
        }

        if (remainderSize != 0) {
            int c0 = ALPHABET.indexOf(encodedString.charAt(encodedString.length() - 2));
            int c1 = ALPHABET.indexOf(encodedString.charAt(encodedString.length() - 1));
            result[resultIndex] = (byte) (c0 + 45 * c1);
        }
        return result;
    }
}
