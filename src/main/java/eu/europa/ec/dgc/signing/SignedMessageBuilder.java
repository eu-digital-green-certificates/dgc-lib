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

package eu.europa.ec.dgc.signing;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.Security;
import java.util.Base64;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * <p>Abstract class to build Typed CMS Message builder.</p>
 * <p>
 * T -> DataType which needs to be signed with CMS. <br />
 * R -> Implemented Subclass
 * </p>
 */
@Slf4j
@NoArgsConstructor
public abstract class SignedMessageBuilder<T, R extends SignedMessageBuilder<T, R>> {

    private T payload;

    private X509CertificateHolder signingCertificate;

    private PrivateKey signingCertificatePrivateKey;

    /**
     * Method to convert the payload into bytes which can be used for signing.
     *
     * @param payload payload to convert in original data type.
     * @return payload representation as byte array.
     */
    abstract byte[] convertToBytes(T payload) throws IOException;

    /**
     * Method which needs to return the instance of the subclass.
     * This special workaround is needed to enable the builder style.
     */
    abstract R getThis();

    /**
     * Add a signing certificate to MessageBuilder instance.
     *
     * @param certificate X509 Certificate to sign the message with
     * @param privateKey  Private key for given X509 Certificate.
     */
    public R withSigningCertificate(
        X509CertificateHolder certificate, PrivateKey privateKey) {
        signingCertificate = certificate;
        signingCertificatePrivateKey = privateKey;
        return getThis();
    }

    /**
     * Add a payload to MessageBuilder instance.
     *
     * @param payload to be added.
     */
    public R withPayload(T payload) {
        this.payload = payload;
        return getThis();
    }

    /**
     * <p>Builds the CMS signed message.</p>
     * <p>payload and SigningCertificate needs to be set previously.</p>
     *
     * @param detached flag whether only the signature should be returned (detached signature)
     * @return Bytes of signed CMS message.
     */
    public byte[] build(boolean detached) {
        Security.addProvider(new BouncyCastleProvider());

        if (payload == null || signingCertificate == null || signingCertificatePrivateKey == null) {
            throw new RuntimeException("Message Builder is not ready");
        }

        byte[] messageBytes;
        CMSSignedDataGenerator signedDataGenerator = new CMSSignedDataGenerator();

        try {
            DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();

            ASN1ObjectIdentifier publicKeyAlgoOid =
                signingCertificate.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm();

            String signingAlgorithmName;
            if (publicKeyAlgoOid.equals(PKCSObjectIdentifiers.rsaEncryption)) {
                signingAlgorithmName = "SHA256WITHRSA";
            } else if (publicKeyAlgoOid.equals(X9ObjectIdentifiers.id_ecPublicKey)) {
                signingAlgorithmName = "SHA256WITHECDSA";
            } else {
                throw new RuntimeException("Public key must be RSA or EC");
            }

            ContentSigner contentSigner =
                new JcaContentSignerBuilder(signingAlgorithmName).build(signingCertificatePrivateKey);

            SignerInfoGenerator signerInfoGenerator = new JcaSignerInfoGeneratorBuilder(digestCalculatorProvider)
                .build(contentSigner, signingCertificate);

            signedDataGenerator.addSignerInfoGenerator(signerInfoGenerator);

            signedDataGenerator.addCertificate(signingCertificate);

            CMSSignedData signedData = signedDataGenerator.generate(
                new CMSProcessableByteArray(convertToBytes(payload)), !detached);

            messageBytes = signedData.getEncoded();
        } catch (OperatorCreationException | CMSException | IOException e) {
            throw new RuntimeException("Failed to create signed message");
        }

        return messageBytes;
    }

    /**
     * <p>Builds the CMS signed message.</p>
     * <p>payload and SigningCertificate needs to be set previously.</p>
     *
     * @return Bytes of signed CMS message.
     */
    public byte[] build() {
        return build(false);
    }

    /**
     * <p>Builds the CMS signed message.</p>
     * <p>payload and SigningCertificate needs to be set previously.</p>
     *
     * @param detached flag whether only the signature should be returned (detached signature)
     * @return Base64 encoded String of CMS message.
     */
    public String buildAsString(boolean detached) {
        return Base64.getEncoder().encodeToString(build(detached));
    }

    /**
     * <p>Builds the CMS signed message.</p>
     * <p>payload and SigningCertificate needs to be set previously.</p>
     *
     * @return Base64 encoded String of signed CMS message.
     */
    public String buildAsString() {
        return Base64.getEncoder().encodeToString(build(false));
    }
}
