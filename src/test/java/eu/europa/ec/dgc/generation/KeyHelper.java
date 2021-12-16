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
