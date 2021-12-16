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

package eu.europa.ec.dgc.testdata;

import eu.europa.ec.dgc.gateway.connector.config.DgcGatewayConnectorConfigProperties;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import lombok.Getter;
import lombok.Setter;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

@TestConfiguration
public class DgcTestKeyStore {

    private final DgcGatewayConnectorConfigProperties configProperties;

    @Getter
    @Setter
    private X509Certificate trustAnchor;

    @Getter
    @Setter
    private PrivateKey trustAnchorPrivateKey;

    @Getter
    @Setter
    private X509Certificate upload;

    @Getter
    @Setter
    private PrivateKey uploadPrivateKey;

    public DgcTestKeyStore(DgcGatewayConnectorConfigProperties configProperties) throws Exception {
        this.configProperties = configProperties;

        KeyPair keyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        trustAnchorPrivateKey = keyPair.getPrivate();

        trustAnchor = CertificateTestUtils.generateCertificate(keyPair, "EU", "DGCG Test TrustAnchor");

        KeyPair uploadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        uploadPrivateKey = uploadKeyPair.getPrivate();

        upload = CertificateTestUtils.generateCertificate(uploadKeyPair, "EU", "DGCG Test Upload Cert");

    }

    /**
     * Creates a KeyStore instance with keys for DGC.
     *
     * @return KeyStore Instance
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     */
    @Bean
    @Primary
    @Qualifier("trustAnchor")
    public KeyStore testKeyStore() throws IOException, CertificateException, NoSuchAlgorithmException {
        KeyStoreSpi keyStoreSpiMock = mock(KeyStoreSpi.class);
        KeyStore keyStoreMock = new KeyStore(keyStoreSpiMock, null, "test") {
        };
        keyStoreMock.load(null);

        doAnswer((x) -> trustAnchor)
            .when(keyStoreSpiMock).engineGetCertificate(configProperties.getTrustAnchor().getAlias());

        return keyStoreMock;
    }

    /**
     * Creates a KeyStore instance with keys for DGC.
     *
     * @return KeyStore Instance
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     */
    @Bean
    @Primary
    @Qualifier("upload")
    public KeyStore uploadKeyStore() throws IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStoreSpi keyStoreSpiMock = mock(KeyStoreSpi.class);
        KeyStore keyStoreMock = new KeyStore(keyStoreSpiMock, null, "test") {
        };
        keyStoreMock.load(null);

        doAnswer((x) -> upload)
            .when(keyStoreSpiMock).engineGetCertificate(configProperties.getUploadKeyStore().getAlias());

        doAnswer((x) -> uploadPrivateKey)
            .when(keyStoreSpiMock).engineGetKey(configProperties.getUploadKeyStore().getAlias(), configProperties.getUploadKeyStore().getPassword());

        return keyStoreMock;
    }

}
