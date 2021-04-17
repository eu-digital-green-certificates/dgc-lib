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
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Collection;
import lombok.Getter;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;

@Slf4j
public class SignedCertificateMessageParser {

    private final byte[] raw;

    /**
     * The extracted payload certificate.
     */
    @Getter
    private X509CertificateHolder payloadCertificate;

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
     * <i>parserState == ParserState.SUCCESS</i> and <i>signatureVerified == true</i> a valid certificate CMS
     * message was passed to the parser.</p>
     */
    @Getter
    private ParserState parserState = ParserState.IDLE;

    /**
     * <p>Result of the integrity check of the cms message.</p>
     *
     * <p>The result just proofs, that the message was signed with the attached certificate.
     * The integrity of the signer certificate is not proven</p>
     */
    @Getter
    private boolean signatureVerified = false;

    /**
     * Create a new instance of {@link SignedCertificateMessageParser} and starts the parsing process.
     * The result of parsing process will be immediately available.
     *
     * @param cmsMessage base64 encoded CMS message bytes.
     */
    public SignedCertificateMessageParser(@NonNull byte[] cmsMessage) {
        raw = cmsMessage;
        afterPropertiesSet();
    }

    /**
     * Create a new instance of {@link SignedCertificateMessageParser} and starts the parsing process.
     * The result of parsing process will be immediately available.
     *
     * @param cmsMessage base64 encoded CMS message string.
     */
    public SignedCertificateMessageParser(@NonNull String cmsMessage) {
        raw = cmsMessage.getBytes(StandardCharsets.UTF_8);
        afterPropertiesSet();
    }

    private void afterPropertiesSet() {
        // Parse Base64
        byte[] cmsBytes;
        try {
            cmsBytes = Base64.getDecoder().decode(raw);
        } catch (IllegalArgumentException e) {
            parserState = ParserState.FAILURE_INVALID_BASE64;
            return;
        }

        // Parse CMS Message;
        CMSSignedData cmsSignedData;
        try {
            cmsSignedData = new CMSSignedData(cmsBytes);
        } catch (CMSException e) {
            parserState = ParserState.FAILURE_INVALID_CMS;
            return;
        }

        // Check Payload of CMS Message
        if (cmsSignedData.getSignedContent().getContentType() != CMSObjectIdentifiers.data) {
            parserState = ParserState.FAILURE_INVALID_CMS_BODY;
            return;
        }

        // Extract Certificate from Payload
        try {
            payloadCertificate = new X509CertificateHolder(
                (byte[]) cmsSignedData.getSignedContent().getContent());
        } catch (IOException e) {
            parserState = ParserState.FAILURE_CMS_BODY_NO_CERTIFICATE;
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

    public enum ParserState {
        IDLE,
        SUCCESS,
        FAILURE_INVALID_BASE64,
        FAILURE_INVALID_CMS,
        FAILURE_INVALID_CMS_BODY,
        FAILURE_CMS_BODY_NO_CERTIFICATE,
        FAILURE_CMS_SIGNER_INFO,
        FAILURE_CMS_SIGNING_CERT_INVALID
    }
}
