package eu.europa.ec.dgc.generation;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * build final dcc qr code from encode dcc data and signature.
 */
public class DgcCryptedFinalizer {

    /**
     * finalize dcc.
     *
     * @param encodedDccData dcc data
     * @param dek            encoded key
     * @param privateKey     private key
     * @param signature      dcc signature
     * @return qr code of final dcc
     */
    public String finalizeDcc(byte[] encodedDccData, byte[] dek, PrivateKey privateKey, byte[] signature) {
        DgcGenerator dgcGenerator = new DgcGenerator();
        byte[] dgcData = new byte[0];
        try {
            dgcData = decryptDccData(encodedDccData, dek, privateKey);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException
            | IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException
            | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        byte[] dgcCose = dgcGenerator.dgcSetCoseSignature(dgcData, signature);
        return dgcGenerator.coseToQrCode(dgcCose);
    }

    private byte[] decryptDccData(byte[] encodedDccData, byte[] dek, PrivateKey privateKey)
        throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
        IllegalBlockSizeException, BadPaddingException,
        InvalidKeySpecException, InvalidAlgorithmParameterException {
        // decrypt RSA key
        Cipher keyCipher = Cipher.getInstance(DgcCryptedPublisher.KEY_CIPHER);
        keyCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] rsaKey = keyCipher.doFinal(dek);

        byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(DgcCryptedPublisher.DATA_CIPHER);

        SecretKeySpec secretKeySpec = new SecretKeySpec(rsaKey, 0, rsaKey.length, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivspec);
        return cipher.doFinal(encodedDccData);
    }
}
