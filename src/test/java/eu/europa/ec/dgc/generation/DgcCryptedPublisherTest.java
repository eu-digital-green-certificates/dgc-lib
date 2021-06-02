package eu.europa.ec.dgc.generation;

import eu.europa.ec.dgc.generation.dto.DgcData;
import eu.europa.ec.dgc.generation.dto.DgcInitData;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import javax.crypto.Cipher;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DgcCryptedPublisherTest {

    KeyHelper keyHelper;

    @BeforeEach
    public void setup() throws Exception {
        keyHelper = new KeyHelper();
    }

    @Test
    void getEncodedDGCData() throws Exception {
        DgcSigner dgcSigner = new DgcSigner();
        DgcCryptedPublisher dgcCryptedPublisher = new DgcCryptedPublisher();

        String edgcJson = "{\"ver\":\"1.0.0\",\"nam\":{\"fn\":\"Garcia\",\"fnt\":\"GARCIA\"," +
            "\"gn\":\"Francisco\",\"gnt\":\"FRANCISCO\"},\"dob\":\"1991-01-01\",\"v\":[{\"tg\":\"840539006\"," +
            "\"vp\":\"1119305005\",\"mp\":\"EU/1/20/1507\",\"ma\":\"ORG-100001699\",\"dn\":1,\"sd\":2,\"dt\":" +
            "\"2021-05-14\",\"co\":\"CY\",\"is\":\"Neha\",\"ci\":\"dgci:V1:CY:HIP4OKCIS8CXKQMJSSTOJXAMP:03\"}]}";
        String countryCode = "DE";
        ZonedDateTime now = ZonedDateTime.now();
        ZonedDateTime expiration = now.plus(Duration.of(365, ChronoUnit.DAYS));
        long issuedAt = now.toInstant().getEpochSecond();
        long expirationSec = expiration.toInstant().getEpochSecond();
        byte[] keyId = dgcSigner.keyId(keyHelper.getCert());
        // We assume that it is EC Key
        int algId = -7;

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(3072);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        // Test coding of public key
        // Base64-kodierte RSA-3072 Public Key in x.509 Format (ohne PEM Header/Footer). Immer 564 Zeichen (als Base64-Darstellung).
        String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        assertEquals(564, publicKeyBase64.length());

        DgcInitData dgcInitData = new DgcInitData();
        dgcInitData.setExpriation(expirationSec);
        dgcInitData.setIssuedAt(issuedAt);
        dgcInitData.setIssuerCode(countryCode);
        dgcInitData.setKeyId(keyId);
        dgcInitData.setAlgId(-7);
        DgcData dgcData = dgcCryptedPublisher.createDgc(dgcInitData, edgcJson, keyPair.getPublic());

        // Base64-kodierte und mit dem RSA Public Key verschlüsselter DEK. Der DEK selbst muss 32 Bytes haben (für AES-256).
        // Der verschlüsselte DEK hat 384 Bytes und die base64-kodierte Darstellung entsprechend 512 Zeichen.
        assertEquals(384, dgcData.getDek().length);
        String dekBase64 = Base64.getEncoder().encodeToString(dgcData.getDek());
        assertEquals(512, dekBase64.length());

        byte[] signature = dgcSigner.signHash(dgcData.getHash(), keyHelper.getPrivateKey());

        DgcCryptedFinalizer dgcCryptedFinalizer = new DgcCryptedFinalizer();
        String edgcQRCode = dgcCryptedFinalizer.finalizeDcc(dgcData.getDataEncrypted(), dgcData.getDek(), keyPair.getPrivate(), signature);
        System.out.println(edgcQRCode);
    }

    @Test
    void rsaCrypt() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        byte[] testData = "Test".getBytes(StandardCharsets.UTF_8);

        Cipher cipher = Cipher.getInstance(DgcCryptedPublisher.KEY_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] encrypted = cipher.doFinal(testData);

        Cipher cipherDecrypt = Cipher.getInstance(DgcCryptedPublisher.KEY_CIPHER);
        cipherDecrypt.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decrypted = cipherDecrypt.doFinal(encrypted);

        assertArrayEquals(testData, decrypted);
    }
}