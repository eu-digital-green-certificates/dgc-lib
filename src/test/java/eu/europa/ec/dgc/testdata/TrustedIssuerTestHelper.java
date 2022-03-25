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

package eu.europa.ec.dgc.testdata;


import eu.europa.ec.dgc.gateway.connector.dto.TrustedIssuerDto;
import eu.europa.ec.dgc.signing.SignedStringMessageBuilder;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TrustedIssuerTestHelper {

    private final DgcTestKeyStore testKeyStore;

    public TrustedIssuerDto createTrustedIssuer(final String country) throws Exception {
        TrustedIssuerDto trustedIssuer = new TrustedIssuerDto();
        trustedIssuer.setUrl("https://trusted.issuer");
        trustedIssuer.setName("tiName");
        trustedIssuer.setCountry(country);
        trustedIssuer.setType(TrustedIssuerDto.UrlTypeDto.HTTP);
        trustedIssuer.setSslPublicKey("pubKey");
        trustedIssuer.setThumbprint("thumbprint");
        trustedIssuer.setKeyStorageType("JWKS");
        final String signature = signString(getHashData(trustedIssuer));
        trustedIssuer.setSignature(signature);

        return trustedIssuer;
    }

    private String getHashData(TrustedIssuerDto entity) {
        return  entity.getCountry() + ";"
                + entity.getName() + ";"
                + entity.getUrl() + ";"
                + entity.getType().name() + ";";
    }

    public String signString(final String hashdata) throws Exception {
        return new SignedStringMessageBuilder()
            .withPayload(hashdata)
            .withSigningCertificate(new X509CertificateHolder(testKeyStore.getTrustAnchor().getEncoded()), testKeyStore.getTrustAnchorPrivateKey())
            .buildAsString();
    }

}
