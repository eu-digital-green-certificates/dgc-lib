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

package eu.europa.ec.dgc.gateway.connector;

import eu.europa.ec.dgc.gateway.connector.mapper.TrustListMapper;
import eu.europa.ec.dgc.gateway.connector.mapper.TrustedIssuerMapper;
import eu.europa.ec.dgc.gateway.connector.mapper.TrustedReferenceMapper;
import eu.europa.ec.dgc.testdata.CertificateTestUtils;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import lombok.extern.slf4j.Slf4j;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.apache.http.ssl.SSLContextBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;

@SpringBootTest(properties = "dgc.gateway.connector.enabled=false")
@Slf4j
public class DownloadConnectorBuilderTest {

    @Autowired
    TrustListMapper trustListMapper;

    @Autowired
    TrustedIssuerMapper trustedIssuerMapper;

    @Autowired
    TrustedReferenceMapper trustedReferenceMapper;

    @Autowired
    ApplicationContext applicationContext;

    CertificateUtils certificateUtils = new CertificateUtils();

    private static X509Certificate serverCertificate, clientCertificate;

    private static KeyPair clientKeyPair;

    private static MockWebServer server;

    @BeforeAll
    static void setupMockWebServer() throws Exception {
        server = new MockWebServer();

        KeyPair serverKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        serverCertificate = CertificateTestUtils.generateCertificate(serverKeyPair, "EU", "DGC-Lib MockWebServer");
        KeyStore serverKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        serverKeyStore.load(null);
        serverKeyStore.setKeyEntry("server", serverKeyPair.getPrivate(), "pw".toCharArray(), new Certificate[]{serverCertificate});

        clientKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        clientCertificate = CertificateTestUtils.generateCertificate(clientKeyPair, "EU", "DGC-Lib Unit Test Client");
        KeyStore clientKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        clientKeyStore.load(null);
        clientKeyStore.setCertificateEntry("1", clientCertificate);

        SSLContext sslContext = SSLContextBuilder.create()
            .loadTrustMaterial(clientKeyStore, null)
            .loadKeyMaterial(serverKeyStore, "pw".toCharArray(), (a, s) -> "server")
            .build();

        server.useHttps(sslContext.getSocketFactory(), false);
        server.requestClientAuth();
        server.start();

        log.info("Mock Server ist listening on: {}", server.url(""));
    }


    @Test
    void testConnectorUsesClientCertificate() throws Exception {
        KeyPair trustAnchorKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        X509Certificate trustAnchorCertificate = CertificateTestUtils.generateCertificate(trustAnchorKeyPair, "EU", "DGC-Lib Unit Test TA");

        server.enqueue(new MockResponse().setBody(""));
        server.enqueue(new MockResponse().setBody(""));
        server.enqueue(new MockResponse().setBody(""));
        server.enqueue(new MockResponse().setBody(""));

        DgcGatewayDownloadConnector connector =
                new DgcGatewayDownloadConnectorBuilder(applicationContext, trustListMapper, trustedIssuerMapper, trustedReferenceMapper)
            .withMtlsAuthCert(certificateUtils.convertCertificate(clientCertificate), clientKeyPair.getPrivate())
            .withTrustedServerCert(certificateUtils.convertCertificate(serverCertificate))
            .withUrl(server.url("/test").toString())
            .withSslHostnameValidation(false)
            .withTrustAnchors(Collections.singletonList(certificateUtils.convertCertificate(trustAnchorCertificate)))
            .build();

        connector.getTrustedCertificates();

        RecordedRequest recordedRequest = server.takeRequest(5, TimeUnit.of(ChronoUnit.SECONDS));

        assert recordedRequest != null;
        Assertions.assertEquals(
            certificateUtils.getCertThumbprint(clientCertificate),
            certificateUtils.getCertThumbprint((X509Certificate) Objects.requireNonNull(recordedRequest.getHandshake()).peerCertificates().get(0)));
    }
}
