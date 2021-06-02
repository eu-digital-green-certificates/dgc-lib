package eu.europa.ec.dgc.generation;

import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DgcSignerTest {

    KeyHelper keyHelper;

    @BeforeEach
    void setup() throws Exception {
        keyHelper = new KeyHelper();
    }

    @Test
    void genEDGC() {

        DgcGenerator dgcGenerator = new DgcGenerator();
        DgcSigner dgcSigner = new DgcSigner();

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

        byte[] dgcCbor = dgcGenerator.genDgcCbor(edgcJson, countryCode, issuedAt, expirationSec);

        byte[] coseBytes = dgcGenerator.genCoseUnsigned(dgcCbor, keyId, algId);
        byte[] hash = dgcGenerator.computeCoseSignHash(coseBytes);

        byte[] signature = dgcSigner.signHash(hash, keyHelper.getPrivateKey());

        byte[] coseSigned = dgcGenerator.dgcSetCoseSignature(coseBytes, signature);
        String edgcQR = dgcGenerator.coseToQrCode(coseSigned);

        System.out.println(edgcQR);
        Assertions.assertNotNull(edgcQR);
    }
}