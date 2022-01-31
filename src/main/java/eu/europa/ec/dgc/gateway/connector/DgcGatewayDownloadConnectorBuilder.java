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

import eu.europa.ec.dgc.gateway.connector.client.DgcGatewayConnectorRestClient;
import eu.europa.ec.dgc.gateway.connector.config.DgcGatewayConnectorConfigProperties;
import eu.europa.ec.dgc.gateway.connector.mapper.TrustListMapper;
import eu.europa.ec.dgc.gateway.connector.springbootworkaroundforks.DgcFeignClientBuilder;
import eu.europa.ec.dgc.gateway.connector.springbootworkaroundforks.DgcFeignClientFactoryBean;
import eu.europa.ec.dgc.utils.CertificateUtils;
import feign.Client;
import feign.httpclient.ApacheHttpClient;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.UUID;
import javax.net.ssl.SSLContext;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpHost;
import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicHeader;
import org.apache.http.ssl.SSLContextBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpHeaders;

@RequiredArgsConstructor
@Slf4j
public class DgcGatewayDownloadConnectorBuilder {

    /**
     * Inline-Keystore parameters.
     */
    private static final String KEYSTORE_PASSWORD = UUID.randomUUID().toString();
    private static final String KEYSTORE_ALIAS = UUID.randomUUID().toString();

    /**
     * Dependencies.
     */
    private static final CertificateUtils certificateUtils = new CertificateUtils();
    private final ApplicationContext springBootContext;
    private final TrustListMapper trustListMapper;

    /**
     * Builder parameters.
     */
    private String url;
    private KeyStore mtlsTrustStore;
    private KeyStore mtlsKeyStore;
    private X509CertificateHolder trustAnchor;
    private HttpHost proxy;
    private int cacheMagAge = -1;
    private boolean enableSslHostnameValidation = true;
    private HttpClient customApacheHttpClient;

    /**
     * Set the URL of the target DGCG instance.
     * Required.
     *
     * @param url URL of DGCG (e.g. https://example.org)
     */
    public DgcGatewayDownloadConnectorBuilder withUrl(String url) {
        this.url = url;

        return this;
    }

    /**
     * Set the TrustAnchor to validate the received entities.
     * Required.
     *
     * @param cert X509 Certificate which is the TrustAnchor.
     */
    public DgcGatewayDownloadConnectorBuilder withTrustAnchor(X509CertificateHolder cert) {
        this.trustAnchor = cert;
        return this;
    }

    /**
     * Set the Client Auth Certificate (NBTLS).
     * Default: Disable Client Certificate Authentication.
     *
     * @param cert       X509 Certificate
     * @param privateKey Corresponding Private Key
     */
    public DgcGatewayDownloadConnectorBuilder withMtlsAuthCert(X509CertificateHolder cert, PrivateKey privateKey)
        throws DgcGatewayDownloadConnectorBuilderException {

        return withMtlsAuthCert(new X509CertificateHolder[]{cert}, privateKey);
    }

    /**
     * Set the Client Auth Certificate Chain (NBTLS).
     * Default: Disable Client Certificate Authentication.
     *
     * @param chain      X509 Certificate Chain
     * @param privateKey Corresponding Private Key
     */
    public DgcGatewayDownloadConnectorBuilder withMtlsAuthCert(X509CertificateHolder[] chain, PrivateKey privateKey)
        throws DgcGatewayDownloadConnectorBuilderException {
        try {
            if (mtlsKeyStore == null) {
                mtlsKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                mtlsKeyStore.load(null, null);
            }

            Certificate[] convertedChain = new Certificate[chain.length];
            for (int i = 0; i < chain.length; i++) {
                convertedChain[i] = certificateUtils.convertCertificate(chain[i]);
            }

            mtlsKeyStore.setKeyEntry(KEYSTORE_ALIAS, privateKey, KEYSTORE_PASSWORD.toCharArray(), convertedChain);

            return this;
        } catch (CertificateException e) {
            throw new DgcGatewayDownloadConnectorBuilderException(
                DgcGatewayDownloadConnectorBuilderException.Reason.INVALID_CERTIFICATE,
                "Failed to convert certificate",
                e);
        } catch (Exception e) {
            throw new DgcGatewayDownloadConnectorBuilderException(
                DgcGatewayDownloadConnectorBuilderException.Reason.KEYSTORE_FAILURE,
                "Failed to create Keystore from certificate",
                e
            );
        }
    }

    /**
     * Set the trusted Server Certificate of target DGCG.
     * Default: Trust all incomming Certificates.
     *
     * @param cert X509 Certificate
     */
    public DgcGatewayDownloadConnectorBuilder withTrustedServerCert(X509CertificateHolder cert)
        throws DgcGatewayDownloadConnectorBuilderException {
        try {
            if (mtlsTrustStore == null) {
                mtlsTrustStore = KeyStore.getInstance(KeyStore.getDefaultType());
                mtlsTrustStore.load(null, null);
            }

            mtlsTrustStore.setCertificateEntry(
                certificateUtils.getCertThumbprint(cert),
                certificateUtils.convertCertificate(cert));

            return this;
        } catch (CertificateException e) {
            throw new DgcGatewayDownloadConnectorBuilderException(
                DgcGatewayDownloadConnectorBuilderException.Reason.INVALID_CERTIFICATE,
                "Failed to convert certificate",
                e);
        } catch (Exception e) {
            throw new DgcGatewayDownloadConnectorBuilderException(
                DgcGatewayDownloadConnectorBuilderException.Reason.KEYSTORE_FAILURE,
                "Failed to create Keystore from certificate",
                e
            );
        }
    }

    /**
     * Enable internal cache and set the maximum age of entries in seconds.
     * Default: Disabled.
     *
     * @param seconds cache age in seconds.
     */
    public DgcGatewayDownloadConnectorBuilder withMaximumCacheAge(int seconds) {
        this.cacheMagAge = seconds;
        return this;
    }

    /**
     * Disable SSL Hostname Validation.
     * Default: Enabled.
     *
     * @param enable whether SSL Hostname Validation is enabled.
     */
    public DgcGatewayDownloadConnectorBuilder withSslHostnameValidation(boolean enable) {
        this.enableSslHostnameValidation = enable;
        return this;
    }

    /**
     * Define HTTP-Proxy for outbound requests.D
     *
     * @param host Hostname of http Proxy.
     * @param port Post of http Proxy.
     */
    public DgcGatewayDownloadConnectorBuilder withProxy(String host, int port) {
        if (host != null) {
            this.proxy = new HttpHost(host, port);
        } else {
            this.proxy = null;
        }
        return this;
    }

    /**
     * Use a custom Apache HTTP-Client to connect to Gateway.
     *
     * @param httpClient Apache Http Client
     */
    public DgcGatewayDownloadConnectorBuilder withCustomApacheHttpClient(HttpClient httpClient) {
        this.customApacheHttpClient = httpClient;
        return this;
    }

    /**
     * Construct DGCG Download Connector.
     *
     * @return Configured instance of {@link DgcGatewayDownloadConnector}
     */
    public DgcGatewayDownloadConnector build() throws DgcGatewayDownloadConnectorBuilderException {
        Security.addProvider(new BouncyCastleProvider());

        if (url == null) {
            throw new DgcGatewayDownloadConnectorBuilderException(
                DgcGatewayDownloadConnectorBuilderException.Reason.NOT_READY,
                "URL is not set");
        }

        if (this.trustAnchor == null) {
            throw new DgcGatewayDownloadConnectorBuilderException(
                DgcGatewayDownloadConnectorBuilderException.Reason.NOT_READY,
                "TrustAnchor is not set");
        }

        DgcGatewayConnectorConfigProperties properties = new DgcGatewayConnectorConfigProperties();
        properties.setMaxCacheAge(cacheMagAge);

        Client client;
        try {
            client = getClient();
        } catch (Exception e) {
            throw new DgcGatewayDownloadConnectorBuilderException(
                DgcGatewayDownloadConnectorBuilderException.Reason.HTTP_CLIENT_INSTANTIATION_FAILED,
                "Failed to create HTTP Client",
                e);
        }

        DgcGatewayConnectorRestClient restClient = new DgcFeignClientBuilder(springBootContext)
            .forType(DgcGatewayConnectorRestClient.class, new DgcFeignClientFactoryBean(), UUID.randomUUID().toString())
            .customize(builder -> builder.client(client))
            .url(url)
            .build();

        DgcGatewayConnectorUtils connectorUtils =
            new DgcGatewayConnectorUtils(certificateUtils, restClient, null, null);
        connectorUtils.setTrustAnchor(trustAnchor);

        return new DgcGatewayDownloadConnector(connectorUtils, restClient, properties, trustListMapper);
    }

    private Client getClient() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException,
        KeyManagementException {

        if (customApacheHttpClient != null) {
            return new ApacheHttpClient(customApacheHttpClient);
        }

        HttpClientBuilder clientBuilder = HttpClientBuilder.create();

        if (url.startsWith("https://")) {
            clientBuilder.setSSLContext(getSslContext());
            clientBuilder.setSSLHostnameVerifier(
                enableSslHostnameValidation ? new DefaultHostnameVerifier() : new NoopHostnameVerifier());

            if (!enableSslHostnameValidation) {
                log.warn("Connector for {} uses HTTPS but SSL Hostname Validation is disabled.", url);
            }
        }

        return new ApacheHttpClient(clientBuilder
            .setDefaultHeaders(Arrays.asList(
                new BasicHeader(HttpHeaders.ACCEPT_ENCODING, "gzip, deflate, br"),
                new BasicHeader(HttpHeaders.CONNECTION, "keep-alive")
            ))
            .setProxy(proxy)
            .build());
    }

    private SSLContext getSslContext() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException,
        KeyManagementException {

        SSLContextBuilder sslContextBuilder = SSLContextBuilder.create();

        if (mtlsTrustStore == null) {
            log.warn("Connector for {} will not validate server certificate.", url);
            sslContextBuilder.loadTrustMaterial(TrustAllStrategy.INSTANCE);
        } else {
            sslContextBuilder.loadTrustMaterial(mtlsTrustStore, null);
        }

        if (mtlsKeyStore != null) {
            sslContextBuilder.loadKeyMaterial(
                mtlsKeyStore, KEYSTORE_PASSWORD.toCharArray(), (map, socket) -> KEYSTORE_ALIAS);
        }

        return sslContextBuilder.build();
    }

    @RequiredArgsConstructor
    @AllArgsConstructor
    @Getter
    public static class DgcGatewayDownloadConnectorBuilderException extends Exception {
        private final Reason reason;
        private final String message;
        private Throwable innerException;

        enum Reason {
            NOT_READY,
            HTTP_CLIENT_INSTANTIATION_FAILED,
            KEYSTORE_FAILURE,
            INVALID_CERTIFICATE
        }
    }

}
