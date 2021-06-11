package eu.europa.ec.dgc.generation;

import java.security.GeneralSecurityException;
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
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * build final dcc qr code from encode dcc data and signature.
 */
@Service
@Slf4j
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
        } catch (GeneralSecurityException e) {
            log.error("Failed to finalize DCC: {}", e.getMessage());
            throw new IllegalStateException("can not decrypt dcc data");
        }
        byte[] dgcCose = dgcGenerator.dgcSetCoseSignature(dgcData, signature);
        return dgcGenerator.coseToQrCode(dgcCose);
    }

    /**
     * finalize dcc.
     * @param encodedDccData dcc data
     * @param dek encoded key
     * @param privateKey private key
     * @param partialDcc cose with signature and key
     * @return qr code of final dcc
     */
    public String finalizePartialDcc(byte[] encodedDccData, byte[] dek, PrivateKey privateKey, byte[] partialDcc) {
        DgcGenerator dgcGenerator = new DgcGenerator();
        byte[] dgcData = new byte[0];
        try {
            dgcData = decryptDccData(encodedDccData, dek, privateKey);
        } catch (GeneralSecurityException e) {
            log.error("Failed to finalize DCC: {}", e.getMessage());
            throw new IllegalStateException("can not decrypt dcc data");
        }
        byte[] dgcCose = dgcGenerator.dgcSetCosePartial(dgcData, partialDcc);
        return dgcGenerator.coseToQrCode(dgcCose);
    }

    private byte[] decryptDccData(byte[] encodedDccData, byte[] dek, PrivateKey privateKey)
        throws java.security.GeneralSecurityException {
        // decrypt RSA key
        Cipher keyCipher = Cipher.getInstance(DgcCryptedPublisher.KEY_CIPHER);
        keyCipher.init(Cipher.DECRYPT_MODE, privateKey, DgcCryptedPublisher.oaepParameterSpec);
        byte[] rsaKey = keyCipher.doFinal(dek);

        byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(DgcCryptedPublisher.DATA_CIPHER);

        SecretKeySpec secretKeySpec = new SecretKeySpec(rsaKey, 0, rsaKey.length, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivspec);
        return cipher.doFinal(encodedDccData);
    }
}
