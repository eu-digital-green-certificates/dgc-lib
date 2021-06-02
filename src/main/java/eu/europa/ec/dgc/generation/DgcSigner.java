package eu.europa.ec.dgc.generation;

import com.upokecenter.cbor.CBORObject;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Arrays;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.springframework.stereotype.Service;

/**
 * The signer of cose message. It takes only hash as imput and does not need
 * to know payload of cose data
 */
@Service
public class DgcSigner {

    /**
     * sign hash. (encode hash) to signature.
     *
     * @param hashBytes  computed cose hash
     * @param privateKey can be EC or RSS
     * @return signature
     */
    public byte[] signHash(byte[] hashBytes, PrivateKey privateKey) {
        byte[] signature;
        try {
            if (privateKey instanceof RSAPrivateCrtKey) {
                signature = signRsapss(hashBytes, privateKey);
            } else {
                signature = signEc(hashBytes, privateKey);
            }
        } catch (CryptoException e) {
            throw new IllegalArgumentException("error during signing ", e);
        }
        return signature;
    }

    /**
     * sign hash and build partial cose dcc containing key in unprotected header and signature.
     *
     * This variant can be user together with @link {@link DgcGenerator#dgcSetCosePartial}.
     * @param hashBytes
     * @param privateKey
     * @param keyId
     * @return cose container but only with signature and unprotected header with keyId
     */
    public byte[] signPartialDcc(byte[] hashBytes, PrivateKey privateKey, byte[] keyId) {
        byte[] signature = signHash(hashBytes, privateKey);
        CBORObject protectedHeader = CBORObject.NewMap();
        byte[] protectedHeaderBytes = protectedHeader.EncodeToBytes();

        CBORObject coseObject = CBORObject.NewArray();
        coseObject.Add(protectedHeaderBytes);
        CBORObject unprotectedHeader = CBORObject.NewMap();
        unprotectedHeader.Add(CBORObject.FromObject(4),CBORObject.FromObject(keyId));
        coseObject.Add(unprotectedHeader);
        byte[] contentDummy = new byte[0];
        coseObject.Add(CBORObject.FromObject(contentDummy));
        coseObject.Add(CBORObject.FromObject(signature));
        return CBORObject.FromObjectAndTag(coseObject, 18).EncodeToBytes();
    }

    /**
     * keyId needed for cose header data.
     *
     * @param certificate certificate
     * @return keyId bytes
     */
    public byte[] keyId(Certificate certificate) {
        try {
            byte[] encoderCert = certificate.getEncoded();
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(encoderCert);
            return Arrays.copyOfRange(hash, 0, 8);
        } catch (CertificateEncodingException | NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("can not gen keyid", e);
        }
    }

    private byte[] signRsapss(byte[] hashBytes, PrivateKey privateKey) throws CryptoException {
        Digest contentDigest = new CopyDigest();
        Digest mgfDigest = new SHA256Digest();
        RSAPrivateCrtKey k = (RSAPrivateCrtKey) privateKey;
        RSAPrivateCrtKeyParameters keyparam = new RSAPrivateCrtKeyParameters(k.getModulus(),
            k.getPublicExponent(), k.getPrivateExponent(),
            k.getPrimeP(), k.getPrimeQ(), k.getPrimeExponentP(), k.getPrimeExponentQ(), k.getCrtCoefficient());
        RSABlindedEngine rsaBlindedEngine = new RSABlindedEngine();
        rsaBlindedEngine.init(true, keyparam);
        PSSSigner pssSigner = new PSSSigner(rsaBlindedEngine, contentDigest, mgfDigest, 32, (byte) (-68));
        pssSigner.init(true, keyparam);
        pssSigner.update(hashBytes, 0, hashBytes.length);
        return pssSigner.generateSignature();
    }

    private byte[] signEc(byte[] hash, PrivateKey privateKey) {
        java.security.interfaces.ECPrivateKey privKey = (java.security.interfaces.ECPrivateKey) privateKey;
        ECParameterSpec s = EC5Util.convertSpec(privKey.getParams());
        ECPrivateKeyParameters keyparam = new ECPrivateKeyParameters(
            privKey.getS(),
            new ECDomainParameters(s.getCurve(), s.getG(), s.getN(), s.getH(), s.getSeed()));
        ECDSASigner ecdsaSigner = new ECDSASigner();
        ecdsaSigner.init(true, keyparam);
        BigInteger[] result3BI = ecdsaSigner.generateSignature(hash);
        byte[] rvarArr = result3BI[0].toByteArray();
        byte[] svarArr = result3BI[1].toByteArray();
        // we need to convert it to 2*32 bytes array. This can 33 with leading 0 or shorter so padding is needed
        byte[] sig = new byte[64];
        System.arraycopy(rvarArr, rvarArr.length == 33 ? 1 : 0, sig,
            Math.max(0, 32 - rvarArr.length), Math.min(32, rvarArr.length));
        System.arraycopy(svarArr, svarArr.length == 33 ? 1 : 0, sig,
            32 + Math.max(0, 32 - svarArr.length), Math.min(32, svarArr.length));

        return sig;
    }

}
