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

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Utility to build a CMS signed message containing a Byte Array (e.g. a File).
 */
@Slf4j
@NoArgsConstructor
public class SignedByteArrayMessageBuilder extends SignedMessageBuilder<byte[], SignedByteArrayMessageBuilder> {

    @Override
    byte[] convertToBytes(byte[] payload) {
        return payload;
    }

    @Override
    SignedByteArrayMessageBuilder getThis() {
        return this;
    }

}
