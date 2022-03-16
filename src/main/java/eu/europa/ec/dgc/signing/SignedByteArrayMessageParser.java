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

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

/**
 * Utility to parse a CMS signed message containing a Byte Array (e.g. a File).
 */
@Slf4j
public class SignedByteArrayMessageParser extends SignedMessageParser<byte[]> {

    @Override
    byte[] convertFromBytes(byte[] bytes) {
        return bytes;
    }

    /**
     * Create a new instance of {@link SignedByteArrayMessageParser} and starts the parsing process.
     * The result of parsing process will be immediately available.
     *
     * @param cmsMessage base64 encoded CMS message bytes.
     */
    public SignedByteArrayMessageParser(@NonNull byte[] cmsMessage) {
        super(cmsMessage);
    }

    /**
     * Create a new instance of {@link SignedByteArrayMessageParser} and starts the parsing process.
     * The result of parsing process will be immediately available.
     *
     * @param cmsSignature base64 encoded detached CMS signature bytes.
     * @param cmsPayload   base64 encoded CMS message payload.
     */
    public SignedByteArrayMessageParser(@NonNull byte[] cmsSignature, @NonNull byte[] cmsPayload) {
        super(cmsSignature, cmsPayload);
    }

    /**
     * Create a new instance of {@link SignedByteArrayMessageParser} and starts the parsing process.
     * The result of parsing process will be immediately available.
     *
     * @param cmsMessage base64 encoded CMS message string.
     */
    public SignedByteArrayMessageParser(@NonNull String cmsMessage) {
        super(cmsMessage);
    }

    /**
     * Create a new instance of {@link SignedByteArrayMessageParser} and starts the parsing process.
     * The result of parsing process will be immediately available.
     *
     * @param cmsSignature base64 encoded detached CMS signature string.
     * @param cmsPayload   base64 encoded CMS message payload string.
     */
    public SignedByteArrayMessageParser(@NonNull String cmsSignature, @NonNull String cmsPayload) {
        super(cmsSignature, cmsPayload);
    }

    /**
     * Create a new instance of {@link SignedByteArrayMessageParser} and starts the parsing process.
     * The result of parsing process will be immediately available.
     *
     * @param cmsSignature base64 encoded detached CMS signature bytes.
     * @param cmsPayload   base64 encoded CMS message payload string.
     */
    public SignedByteArrayMessageParser(@NonNull byte[] cmsSignature, @NonNull String cmsPayload) {
        super(cmsSignature, cmsPayload);
    }

    /**
     * Create a new instance of {@link SignedByteArrayMessageParser} and starts the parsing process.
     * The result of parsing process will be immediately available.
     *
     * @param cmsSignature base64 encoded detached CMS signature string.
     * @param cmsPayload   base64 encoded CMS message payload bytes.
     */
    public SignedByteArrayMessageParser(@NonNull String cmsSignature, @NonNull byte[] cmsPayload) {
        super(cmsSignature, cmsPayload);
    }
}
