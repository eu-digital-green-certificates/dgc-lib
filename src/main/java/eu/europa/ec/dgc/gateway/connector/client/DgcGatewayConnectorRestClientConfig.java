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

package eu.europa.ec.dgc.gateway.connector.client;

import eu.europa.ec.dgc.gateway.connector.config.DgcGatewayConnectorConfigProperties;
import feign.Client;
import feign.httpclient.ApacheHttpClient;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import javax.net.ssl.SSLContext;
import lombok.RequiredArgsConstructor;
import org.apache.http.HttpHost;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicHeader;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.ResourceUtils;

@ConditionalOnProperty("dgc.gateway.connector.tls-key-store.path")
@Configuration
@RequiredArgsConstructor
@EnableFeignClients
public class DgcGatewayConnectorRestClientConfig {

    private final DgcGatewayConnectorConfigProperties properties;

    /**
     * Feign Client for connection to DGC Gateway.
     *
     * @return Instance of HttpClient
     */
    @Bean
    public Client client() throws
        UnrecoverableKeyException, CertificateException,
        IOException, NoSuchAlgorithmException,
        KeyStoreException, KeyManagementException {

        return new ApacheHttpClient(HttpClientBuilder.create()
            .setSSLContext(getSslContext())
            .setDefaultHeaders(Arrays.asList(
                new BasicHeader("Accept-Encoding", "gzip, deflate, br"),
                new BasicHeader("Connection", "keep-alive")
            ))
            .setSSLHostnameVerifier(new DefaultHostnameVerifier())
            .setProxy(getProxy())
            .build());
    }

    private SSLContext getSslContext() throws
        IOException, UnrecoverableKeyException,
        CertificateException, NoSuchAlgorithmException,
        KeyStoreException, KeyManagementException {

        return SSLContextBuilder.create()
            .loadTrustMaterial(
                ResourceUtils.getFile(properties.getTlsTrustStore().getPath()),
                properties.getTlsTrustStore().getPassword())
            .loadKeyMaterial(
                ResourceUtils.getFile(properties.getTlsKeyStore().getPath()),
                properties.getTlsKeyStore().getPassword(),
                properties.getTlsKeyStore().getPassword(),
                (map, socket) -> properties.getTlsKeyStore().getAlias())
            .build();
    }

    private HttpHost getProxy() {
        if (properties.getProxy().isEnabled()) {
            return new HttpHost(properties.getProxy().getHost(), properties.getProxy().getPort());
        } else {
            return null;
        }
    }

}
