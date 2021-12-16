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
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Utility to build a CMS signed message containing a DER encoded X509 certificate.
 */
@Slf4j
@NoArgsConstructor
public class SignedCertificateMessageBuilder
    extends SignedMessageBuilder<X509CertificateHolder, SignedCertificateMessageBuilder> {

    @Override
    byte[] convertToBytes(X509CertificateHolder payload) throws IOException {
        return payload.getEncoded();
    }

    @Override
    SignedCertificateMessageBuilder getThis() {
        return this;
    }

    /**
     * Add a payload certificate to MessageBuilder instance.
     *
     * @param certificate X509 certificate for payload.
     * @deprecated Use .withPayload(X509CertificateHolder) instead
     */
    @Deprecated
    public SignedCertificateMessageBuilder withPayloadCertificate(X509CertificateHolder certificate) {
        return withPayload(certificate);
    }

}
