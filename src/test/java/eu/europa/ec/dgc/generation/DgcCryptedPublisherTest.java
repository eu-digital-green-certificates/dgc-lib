/*-
 * ---license-start
 * WHO Digital Documentation Covid Certificate Gateway Service / ddcc-gateway-lib
 * ---
 * Copyright (C) 2022 T-Systems International GmbH and all other contributors
 * ---
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ---license-end
 */

package eu.europa.ec.dgc.generation;

import eu.europa.ec.dgc.generation.dto.DgcData;
import eu.europa.ec.dgc.generation.dto.DgcInitData;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DgcCryptedPublisherTest {
    KeyHelper keyHelper;

    @BeforeEach
    void setup() throws Exception {
        keyHelper = new KeyHelper();
    }

    @Test
    void getEncodedDGCData() throws Exception {
        DgcSigner dgcSigner = new DgcSigner();
        DgcCryptedPublisher dgcCryptedPublisher = new DgcCryptedPublisher();

        String edgcJson = DgcSignerTest.genSampleJson();
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
        dgcInitData.setEncryptCose(true);
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
    void dccWithPartialDCCSigning() throws Exception {
        DgcSigner dgcSigner = new DgcSigner();
        DgcCryptedPublisher dgcCryptedPublisher = new DgcCryptedPublisher();

        String edgcJson = DgcSignerTest.genSampleJson();
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
        // do not set keyId here, because is it unknown for dcc creator
        dgcInitData.setKeyId(null);
        dgcInitData.setAlgId(-7);
        DgcData dgcData = dgcCryptedPublisher.createDgc(dgcInitData, edgcJson, keyPair.getPublic());

        // Base64-kodierte und mit dem RSA Public Key verschlüsselter DEK. Der DEK selbst muss 32 Bytes haben (für AES-256).
        // Der verschlüsselte DEK hat 384 Bytes und die base64-kodierte Darstellung entsprechend 512 Zeichen.
        assertEquals(384, dgcData.getDek().length);
        String dekBase64 = Base64.getEncoder().encodeToString(dgcData.getDek());
        assertEquals(512, dekBase64.length());

        byte[] partialDcc = dgcSigner.signPartialDcc(dgcData.getHash(), keyHelper.getPrivateKey(), keyId);

        DgcCryptedFinalizer dgcCryptedFinalizer = new DgcCryptedFinalizer();
        String edgcQRCode = dgcCryptedFinalizer.finalizePartialDcc(dgcData.getDataEncrypted(), dgcData.getDek(), keyPair.getPrivate(), partialDcc);
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

    @Test
    void testExampleData() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // see CWA DCC Test Certificates v2.1.docx APPENDIX A
        byte[] clearText = Base64.getDecoder().decode("Yfj9EpJCA1mjnLdgCq38cRDpT/eClO8wecILFtC+jwZX5FGIvV8Cq4d0Hw" +
            "vTmR3hlflgo3oqWDG5nAECBXA5S3GrMpiLIL3VkMdSk9DqBA++Ue+25F5RMuNcE2SYmnHR0AoIqMFToPTwaeTlzgdnXK638RogN0" +
            "mHUrNN0bXfKJ5NBHYJ7R6MfPHL8iFZW/RnW3pthra20pjMSviVZJBu2ir1LGxnOpu86jL14PQSe8TdXwbglLop280p33MFiw7CDn" +
            "C0TQQJ59aphsLCqu9gbguD1uYQoSyNu3qeB3n7BNn0evHmhOi5Qjt1TXp6NtlJ4MlMeusiXGXGdlgCLBsVZaOm/QiSGbtcZ8uAH/" +
            "u+Me35CHLwBYoSLBU42diwrpRXGUGDwe0Oh1hKpy8Kd/i/YDj1/H1nQgwdZcjd7Ci5RRnFJ6QjZLqVT8A3SBfUtXP+ig2zRGDevJ" +
            "RXL34mBLM5NEYT9acaF6kST2LKEuEnVARBAEGCcqTWP39fm0TS2KnrYXX06+jLmkFT5sr1hLSBLmXtzrqA21mKpNwOYMMET4+W3/" +
            "5hjFBxZkVGCFwcXEaLNWGRTZBSog==");

        byte[] dek = Hex.decode("7427A22B0A0673B9F293935643DD4209ACEFA1CF944D2B9D9F97DD27474F12A7");

        byte[] encryptedDek = Base64.getDecoder().decode("B++o5TT1onTB3M7mw2CxdAVTWYn961WWRyB4XvAtLotmbmUe1hkPY230" +
            "z90/L+q5BC6DQtIpyZ4oURDKwuC477JrCjws3j6J7g48q1QLxU96oJvjQAAo4rXb0liAVHW8x3Cv72gkbZS9cbzwZXsdb2VbNnHX4" +
            "tGt1TOPtDZMRUbwezwrOJv3K1ZH5lzkUEWcJVa5j5Ev/jkGhBf8b4stKrzxoyp/Ec4jRm48T+Dhiz2WjqUYU0Kh5/oR4mDhJS+f8U" +
            "nc/JBELGeKvBM+qVJEeHYiMvyl2aTkAwlPFYquattlgkKoVsAlWSrRs32XwagAog/Kjze+na0BJqqoYLysf9cpjqYmAA8bqKT1k58" +
            "WT6aviNjMXjdrwjjdloMvChszjszpgFV78XpfL8SEW+JDdQg7lj5yO/rxyC8Q7MLX/45nsxpahoCvqLMoEj99P3ZU8ykKbFA6Caac" +
            "/ccHMVGTyYjMeyKUK2iFa4HercdT/8rjaEj99v81YDRkVICMPlNG");

        byte[] privateKey = Base64.getDecoder().decode("MIIG5QIBAAKCAYEAzrTf6abtRow4Z3zW/9glzOTZpbpanhU5QONkXSDPfi" +
            "dd9HpYtZUAkTYcMz0Z2tOAhS0O+mKjQdg48PxajR5FuheUpCBoJQOhcNJFwNt/FsYvxVLEg/WUE7oujOaRuk4gn6vzabU1pY7fj0C" +
            "468nNtkAl8eSKwGnzQWUAnhUWkpMb30Qe2Fm+kerEjQ8vymG671V2jXmfx0TmE347VYzrwuSonaSRdQkj1G2Kcu91HyoUGHwAD06x" +
            "qfH5T0o5m6fmQhdfy4t0jZef12sR5tISvRg1ojLnGatGTuVzbFZ6YrL5xV2Qxo8DL9NwN49GzwcQX1dYffEFEZjTMrn9A2/kCYT1q" +
            "F9Zh6YQ/4JUqu60m3bW2wqbVAzVB3fH4sMiqm+cUFftYnUS/TuDS7ZvaarN+SgBn60qPjAR3cG5vxx6VSs7tSI93t+8r1fyfpKu3L" +
            "ZGCKGQIM77/pNdvSKu0we5xbQSpvpPrKCrP96eJ5Ooqy1irCPpGv7FVUqsQjW1ghLxAgMBAAECggGAZb/bSKSGv+deDHMDUkUPtmA" +
            "gUtf8qzw/RpWoXb885Bh0w1dGO3vxH4nHL+GvzGu4I9YePVo4irzoqpdN65EvOX9KB9B781xqJ6MZ+ukREiDUewlW+q30ChHnwCvv" +
            "KAo1POPjmfE9SxWdLmLppAdeX4wMIZoiQrzkpRgWyboPtm77lVdu54ilqiYqQlVrbO/WmOE0zkdEQ07DAm1sv5vyoaj050SO5VFud" +
            "a7GK/V7ba/E3JiNXvuZsNIPqtwap2hpqSCxJkw1oL+0RD9HoO2ZKr6UxO3FjAYubiFIftvJyo/J3Zhu+dq4YKB9s5ZnOdATCewU2F" +
            "ahzBw4JIYlQVPnB9INQRdFX7GhtP36pxRIyd8eK5pJcEHBsUag5+40aH6aDqv039tvf+bARqQcbHGVkfWfhGaHmCMY9XrPiAM5DSG" +
            "kgiXjAqZxr5SEGmTXmKaXdEEQHer7Mw/YNFamTrSPH1n0+mR+NqetPQNRbWPHCzPP3iqlIbWHrvXeJ95VWv+RAoHBAN7Iveweqe1k" +
            "D2Aye8zWwNMQ24gAp2t+stvsSrbkOBfdhXxuKYQoEFNNBua9Vr/cv6Uc7djxCagAcA4VBMxeLuGvbLWPcXzmCgIYJf0p/u2FZ7AKI" +
            "UjclV7qbMn5b1yFUrlTcPtikYmdQ/g1ego4qPGWSKUk0A4bfjekUiSDqJBTTn8u1qXOj4N52KZ63XVnHxh1Nw44LBlnhokci+izI9" +
            "7k93be06H5yulQE45sHVhKZEADIIK6CPmtCjG+H6yYzwKBwQDthnr3B8HLO66nH5s1129N/JBCG5C0JM+5kemzGFw0+5K27134+B6" +
            "LMeU8ePlbozbXgFqsx+iZckNU5+5pNmYOdq5Y9DtHKcflxPexbVtCyFPxg2eU1B4dXEwH4FyQQ5bnTx1+x/r3M/kyZMdn57OOIWAl" +
            "8IenL+XjWOGhPa3t5Xer4qp66591ZYPnMdzJgHp+FonF6EkBvylZrd9TX76IPaErJNf5NeAUJd5L6piRfb5yRB47bvk0HcRdHtMeC" +
            "D8CgcEAzbgmkHPcTAaaoCTd5s/jrMMjRNn9vyh2ttfiQjJJjdgTnEwJcCyirpkxJz5tbavFGA23oB0r4oPM9WP5U1IhDmu0AY/cpw" +
            "2w7jAoXDc8XU5T6d3g0GxITiZAoN0BNTkzo0hmyutBIwcirX+MGwYpEzTIDh8JNA21JmJJK8ibjfIvSQgSU3eDVE/efBR2jSPVNft" +
            "/BFVge3D6bX/7vbw2AmwCCzVFzYthEMLN3DT/f/jpy6ZXjf+FrDBaeoZqrzFHAoHBAJdvEMCkQmrHPz+vx+3Yz07CQlrTZjtj6Mff" +
            "/kY/trHU3qIhFCGiVx7ZjdQzMI+7DEDyxVy5C1OhZMoiIH8VvpVkFx4BgDWLrrWQEXceSHvYaqRk6coaPqTrblHrOjiDzxbj+uMUr" +
            "q2ihjMZy4Q0Vea84qbtph7yS7fZt+hsAZLVpKmClrxNstlPAnyI7sHNVstCpU33HWyuqrdRQjvOpBQKbtGp6MQrFBTkW8i85c6Eg8" +
            "IoKboss1cFz2arO2A/UwKBwQCTvvM6sF8+3zw1EJRSecRzmAsxhJ8t0nkSM91ljITFeo8p5HdTeX/vYVgPAF2CCUQDW+kMgw4o5U+N" +
            "d24xm6zL2oYfjGe6lz/I+zM6hU9CPf1EdHxxccars7ilc/NrXAsaBJ7nO1p9peS1YqhoSC/x1aeJrcBDM1SlkoR0UG6l+hBVVLgs" +
            "96yJhG8WjgXJDjB24Nz+L8zuYIB3KUtMTtib4CxYZIvpXYSmzU8RCIa2g16i24dWhlos1QiWOlG28bI=");

        byte[] publicKey = Base64.getDecoder().decode("MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAzrTf6abtRow4Z3" +
            "zW/9glzOTZpbpanhU5QONkXSDPfidd9HpYtZUAkTYcMz0Z2tOAhS0O+mKjQdg48PxajR5FuheUpCBoJQOhcNJFwNt/FsYvxVLEg/W" +
            "UE7oujOaRuk4gn6vzabU1pY7fj0C468nNtkAl8eSKwGnzQWUAnhUWkpMb30Qe2Fm+kerEjQ8vymG671V2jXmfx0TmE347VYzrwuSo" +
            "naSRdQkj1G2Kcu91HyoUGHwAD06xqfH5T0o5m6fmQhdfy4t0jZef12sR5tISvRg1ojLnGatGTuVzbFZ6YrL5xV2Qxo8DL9NwN49Gz" +
            "wcQX1dYffEFEZjTMrn9A2/kCYT1qF9Zh6YQ/4JUqu60m3bW2wqbVAzVB3fH4sMiqm+cUFftYnUS/TuDS7ZvaarN+SgBn60qPjAR3c" +
            "G5vxx6VSs7tSI93t+8r1fyfpKu3LZGCKGQIM77/pNdvSKu0we5xbQSpvpPrKCrP96eJ5Ooqy1irCPpGv7FVUqsQjW1ghLxAgM" +
            "BAAE=");

        byte[] cipherText = Base64.getDecoder().decode(
            "y4N3agJtqoJrziH06swEHIoKi/CQDWF0Z0+/jdFuDif0h5VtQnjUcYzw33nnQE54mBjVyRH79ekdj/B3F9jJc/79f2V9DuPg" +
                "/z0v0d/2Avpg85r8BiuDKDGskF7aZDVZO/wKWUZlj3vtT0aStFJCcgnZuQX83yTdJ22Ogmbn9uVcdv9xfT231aRnUr6y" +
                "f4bON32LcWKxweXgvjp1gNZB/iJFURLKZfF/fZ66gGtcYh/bfT18re2DBNz0ZOpIUyOXuC4tNZA9x0A5hA4CXhaxunHX" +
                "vFCgMCTsXl90JAG0cgfKD54oTp/EAnRcmMsZfAgfXqMLU4iEaWhj80A0nUltnrJx4JAvcrlSvBJa4716nDZaTzHTktzD" +
                "NHl7r8J2wWh2SGFjSfi76s/mK54ZvM0x8B3+ppt/YxrJgAJ2e7SK0qz77dooMoL1G/qf6N2ZlIOSMsoSBrmYgGa5GAQb" +
                "jMsLwoo7fKGYcR12ztp5J7it/w0xvx3jNbeNgxdLuco8gPoNLDxWElXGX1NS3umJ4yVkFKSPE5inUye3BO1pvWlXFmIM" +
                "Fc0u+ZHurGbEMG/dHtVuK5ZKgp6tefd+L3VitTFeuQ==");

        assertEquals(439, clearText.length);
        assertEquals(384, encryptedDek.length);

        // Test data decoding

        Cipher cipher = Cipher.getInstance(DgcCryptedPublisher.DATA_CIPHER);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("AES");
        SecretKeySpec secretKeySpec = new SecretKeySpec(dek, 0, dek.length, "AES");
        SecretKey secretKey = secretKeyFactory.generateSecret(secretKeySpec);
        byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
        assertArrayEquals(clearText, cipher.doFinal(cipherText));

        // Test dek decoding

        X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKeyInst = keyFactory.generatePublic(spec);

        PKCS8EncodedKeySpec specPrivate = new PKCS8EncodedKeySpec(privateKey);
        PrivateKey privateKeyInst = keyFactory.generatePrivate(specPrivate);

        Cipher keyCipher = Cipher.getInstance(DgcCryptedPublisher.KEY_CIPHER);
        keyCipher.init(Cipher.DECRYPT_MODE, privateKeyInst, DgcCryptedPublisher.OAEP_PARAMETER_SPEC);
        assertArrayEquals(dek, keyCipher.doFinal(encryptedDek));

    }
}
