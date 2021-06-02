package eu.europa.ec.dgc.generation;

import eu.europa.ec.dgc.testdata.CertificateTestUtils;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.Certificate;

public class KeyHelper {
    private final Certificate cert;
    private final PrivateKey privateKey;

    public Certificate getCert() {
        return cert;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public KeyHelper() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ec");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        cert = CertificateTestUtils.generateCertificate(keyPair, "DE", "DCC Gen Lib Test");
        privateKey = keyPair.getPrivate();
    }
}
