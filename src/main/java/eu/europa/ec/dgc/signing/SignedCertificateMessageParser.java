/*-
 * ---license-start
 * EU Digital Green Certificate Gateway Service / dgc-lib
 * ---
 * Copyright (C) 2021 - 2022 T-Systems International GmbH and all other contributors
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

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Utility to parse a CMS signed message containing a DER encoded X509 Certificate.
 */
@Slf4j
public class SignedCertificateMessageParser extends SignedMessageParser<X509CertificateHolder> {

    @Override
    X509CertificateHolder convertFromBytes(byte[] bytes) throws Exception {
        return new X509CertificateHolder(bytes);
    }

    /**
     * The extracted payload certificate.
     *
     * @return certificate.
     * @deprecated use .getPayload() instead.
     */
    @Deprecated
    public X509CertificateHolder getPayloadCertificate() {
        return getPayload();
    }

    /**
     * Create a new instance of {@link SignedCertificateMessageParser} and starts the parsing process.
     * The result of parsing process will be immediately available.
     *
     * @param cmsMessage base64 encoded CMS message bytes.
     */
    public SignedCertificateMessageParser(@NonNull byte[] cmsMessage) {
        super(cmsMessage);
    }

    /**
     * Create a new instance of {@link SignedCertificateMessageParser} and starts the parsing process.
     * The result of parsing process will be immediately available.
     *
     * @param cmsSignature base64 encoded detached CMS signature bytes.
     * @param cmsPayload   base64 encoded CMS message payload.
     */
    public SignedCertificateMessageParser(@NonNull byte[] cmsSignature, @NonNull byte[] cmsPayload) {
        super(cmsSignature, cmsPayload);
    }

    /**
     * Create a new instance of {@link SignedCertificateMessageParser} and starts the parsing process.
     * The result of parsing process will be immediately available.
     *
     * @param cmsMessage base64 encoded CMS message string.
     */
    public SignedCertificateMessageParser(@NonNull String cmsMessage) {
        super(cmsMessage);
    }

    /**
     * Create a new instance of {@link SignedCertificateMessageParser} and starts the parsing process.
     * The result of parsing process will be immediately available.
     *
     * @param cmsSignature base64 encoded detached CMS signature string.
     * @param cmsPayload   base64 encoded CMS message payload string.
     */
    public SignedCertificateMessageParser(@NonNull String cmsSignature, @NonNull String cmsPayload) {
        super(cmsSignature, cmsPayload);
    }

    /**
     * Create a new instance of {@link SignedCertificateMessageParser} and starts the parsing process.
     * The result of parsing process will be immediately available.
     *
     * @param cmsSignature base64 encoded detached CMS signature bytes.
     * @param cmsPayload   base64 encoded CMS message payload string.
     */
    public SignedCertificateMessageParser(@NonNull byte[] cmsSignature, @NonNull String cmsPayload) {
        super(cmsSignature, cmsPayload);
    }

    /**
     * Create a new instance of {@link SignedCertificateMessageParser} and starts the parsing process.
     * The result of parsing process will be immediately available.
     *
     * @param cmsSignature base64 encoded detached CMS signature string.
     * @param cmsPayload   base64 encoded CMS message payload bytes.
     */
    public SignedCertificateMessageParser(@NonNull String cmsSignature, @NonNull byte[] cmsPayload) {
        super(cmsSignature, cmsPayload);
    }
}
