/*-
 * ---license-start
 * EU Digital Green Certificate Gateway Service / dgc-lib
 * ---
 * Copyright (C) 2021 T-Systems International GmbH and all other contributors
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
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Collection;
import lombok.Getter;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

/**
 * Abstract class to create typed CMS Message parsers.
 */
@Slf4j
public abstract class SignedMessageParser<T> {

    private final byte[] raw;
    private final byte[] rawPayload;

    /**
     * The extracted payload.
     */
    @Getter
    private T payload;

    /**
     * The certificate which was used to sign the message.
     */
    @Getter
    private X509CertificateHolder signingCertificate;

    /**
     * <p>The result of parsing the CMS message.</p>
     *
     * <p>Result of <i>SUCCESS</i> does not mean that the signature of the signed message is valid.
     * Pay attention to the value of <i>signatureVerified</i>. Only in conjunction of
     * <i>parserState == ParserState.SUCCESS</i> and <i>signatureVerified == true</i> a valid CMS
     * message was passed to the parser.</p>
     */
    @Getter
    private ParserState parserState = ParserState.IDLE;

    /**
     * <p>Result of the integrity check of the cms message.</p>
     *
     * <p>The result just proofs, that the message was signed with the attached certificate.</p>
     */
    @Getter
    private boolean signatureVerified = false;

    /**
     * <p>Base64 encoded signature of the cms message.
     * Deprecated: Use getDetachedSignature() or getEmbeddedSignature() instead.</p>
     *
     * <p>This string contains only the signature which signs the message.</p>
     */
    @Getter
    @Deprecated
    private String signature;

    /**
     * <p>Base64 encoded detached signature of the cms message.</p>
     *
     * <p>This string contains only the signature which signs the message and not the payload.</p>
     */
    @Getter
    private String detachedSignature;

    /**
     * <p>Base64 encoded embedded signature of the cms message.</p>
     *
     * <p>This string contains both the signature which signs the message and the corresponding payload.</p>
     */
    @Getter
    private String embeddedSignature;

    /**
     * Method to convert the encoded bytes to the actual Class instance.
     *
     * @param bytes to convert.
     * @return instance of T.
     */
    abstract T convertFromBytes(byte[] bytes) throws Exception;

    /**
     * Create a new instance of {@link SignedMessageParser} and starts the parsing process.
     * The result of parsing process will be immediately available.
     *
     * @param cmsMessage base64 encoded CMS message bytes.
     */
    protected SignedMessageParser(@NonNull byte[] cmsMessage) {
        raw = cmsMessage;
        rawPayload = null;
        afterPropertiesSet();
    }

    /**
     * Create a new instance of {@link SignedMessageParser} and starts the parsing process.
     * The result of parsing process will be immediately available.
     *
     * @param cmsSignature base64 encoded detached CMS signature bytes.
     * @param cmsPayload   base64 encoded CMS message payload.
     */
    protected SignedMessageParser(@NonNull byte[] cmsSignature, @NonNull byte[] cmsPayload) {
        raw = cmsSignature;
        rawPayload = cmsPayload;
        afterPropertiesSet();
    }

    /**
     * Create a new instance of {@link SignedMessageParser} and starts the parsing process.
     * The result of parsing process will be immediately available.
     *
     * @param cmsMessage base64 encoded CMS message string.
     */
    protected SignedMessageParser(@NonNull String cmsMessage) {
        raw = cmsMessage.getBytes(StandardCharsets.UTF_8);
        rawPayload = null;
        afterPropertiesSet();
    }

    /**
     * Create a new instance of {@link SignedMessageParser} and starts the parsing process.
     * The result of parsing process will be immediately available.
     *
     * @param cmsSignature base64 encoded detached CMS signature string.
     * @param cmsPayload   base64 encoded CMS message payload string.
     */
    protected SignedMessageParser(@NonNull String cmsSignature, @NonNull String cmsPayload) {
        raw = cmsSignature.getBytes(StandardCharsets.UTF_8);
        rawPayload = cmsPayload.getBytes(StandardCharsets.UTF_8);
        afterPropertiesSet();
    }

    /**
     * Create a new instance of {@link SignedMessageParser} and starts the parsing process.
     * The result of parsing process will be immediately available.
     *
     * @param cmsSignature base64 encoded detached CMS signature bytes.
     * @param cmsPayload   base64 encoded CMS message payload string.
     */
    protected SignedMessageParser(@NonNull byte[] cmsSignature, @NonNull String cmsPayload) {
        raw = cmsSignature;
        rawPayload = cmsPayload.getBytes(StandardCharsets.UTF_8);
        afterPropertiesSet();
    }

    /**
     * Create a new instance of {@link SignedMessageParser} and starts the parsing process.
     * The result of parsing process will be immediately available.
     *
     * @param cmsSignature base64 encoded detached CMS signature string.
     * @param cmsPayload   base64 encoded CMS message payload bytes.
     */
    protected SignedMessageParser(@NonNull String cmsSignature, @NonNull byte[] cmsPayload) {
        raw = cmsSignature.getBytes(StandardCharsets.UTF_8);
        rawPayload = cmsPayload;
        afterPropertiesSet();
    }

    private void afterPropertiesSet() {
        Security.addProvider(new BouncyCastleProvider());

        // Parse Base64
        byte[] cmsBytes;
        byte[] cmsPayloadBytes = null;
        try {
            cmsBytes = Base64.getDecoder().decode(raw);

            if (rawPayload != null) {
                cmsPayloadBytes = Base64.getDecoder().decode(rawPayload);
            }

        } catch (IllegalArgumentException e) {
            parserState = ParserState.FAILURE_INVALID_BASE64;
            return;
        }

        // Parse CMS Message;
        CMSSignedData cmsSignedData;
        try {
            if (rawPayload == null) {
                cmsSignedData = new CMSSignedData(cmsBytes);
            } else {
                CMSProcessableByteArray cmsProcessablePayload = new CMSProcessableByteArray(cmsPayloadBytes);
                cmsSignedData = new CMSSignedData(cmsProcessablePayload, cmsBytes);
            }
        } catch (CMSException e) {
            parserState = ParserState.FAILURE_INVALID_CMS;
            return;
        }

        // Check Payload of CMS Message
        if (cmsSignedData.getSignedContent().getContentType() != CMSObjectIdentifiers.data) {
            parserState = ParserState.FAILURE_INVALID_CMS_BODY;
            return;
        }

        // Extract and convert payload
        try {
            payload = convertFromBytes((byte[]) cmsSignedData.getSignedContent().getContent());
        } catch (Exception e) {
            parserState = ParserState.FAILURE_CMS_BODY_PARSING_FAILED;
            return;
        }

        // Get signer certificate
        Collection<X509CertificateHolder> certificateHolderCollection =
            cmsSignedData.getCertificates().getMatches(null);

        if (certificateHolderCollection.size() != 1) {
            log.error("Signed Message contains more than 1 certificate");
            parserState = ParserState.FAILURE_CMS_SIGNING_CERT_INVALID;
            return;
        }
        signingCertificate = certificateHolderCollection.iterator().next();

        // Try to repack CMS
        try {
            detachedSignature = Base64.getEncoder().encodeToString(repack(cmsSignedData, true).getEncoded());
            embeddedSignature = Base64.getEncoder().encodeToString(repack(cmsSignedData, false).getEncoded());
            signature = detachedSignature; // for compatibility reasons
        } catch (IOException | CMSException e) {
            signature = null;
            log.error("Failed to repack CMS.");
        }

        // Get signer information and verify signature
        if (cmsSignedData.getSignerInfos().size() != 1) {
            log.error("Signed Message contains more than 1 signer information");
            parserState = ParserState.FAILURE_CMS_SIGNER_INFO;
            return;
        }
        SignerInformation signerInformation = cmsSignedData.getSignerInfos().iterator().next();
        try {
            signatureVerified = signerInformation.verify(
                new JcaSimpleSignerInfoVerifierBuilder().build(signingCertificate)
            );
        } catch (CMSException | OperatorCreationException | CertificateException e) {
            log.error("Failed to validate Signature");
        }

        parserState = ParserState.SUCCESS;
    }

    /**
     * Recreates a CMS w/o encapsulated Data.
     *
     * @param input    input CMS Message
     * @param detached whether it should be a detached signature or not
     * @return CMS message.
     * @throws CMSException if repacking fails.
     */
    private CMSSignedData repack(CMSSignedData input, boolean detached) throws CMSException {
        CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
        cmsGenerator.addCertificates(input.getCertificates());
        cmsGenerator.addSigners(input.getSignerInfos());
        cmsGenerator.addAttributeCertificates(input.getAttributeCertificates());
        cmsGenerator.addCRLs(input.getCRLs());

        return cmsGenerator.generate(input.getSignedContent(), !detached);
    }

    public enum ParserState {
        IDLE,
        SUCCESS,
        FAILURE_INVALID_BASE64,
        FAILURE_INVALID_CMS,
        FAILURE_INVALID_CMS_BODY,

        /**
         * Deprecated ParserState Property.
         *
         * @deprecated Replaced by FAILURE_CMS_BODY_PARSING_FAILED
         */
        @Deprecated
        FAILURE_CMS_BODY_NO_CERTIFICATE,

        FAILURE_CMS_BODY_PARSING_FAILED,
        FAILURE_CMS_SIGNER_INFO,
        FAILURE_CMS_SIGNING_CERT_INVALID
    }
}
