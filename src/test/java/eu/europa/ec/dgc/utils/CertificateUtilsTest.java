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

package eu.europa.ec.dgc.utils;

import eu.europa.ec.dgc.testdata.CertificateTestUtils;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CertificateUtilsTest {

    CertificateUtils certificateUtils;

    KeyPair keyPair;
    X509Certificate certificate;

    @BeforeEach
    void setupTestData() throws Exception {
        certificateUtils = new CertificateUtils();
        keyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        certificate = CertificateTestUtils.generateCertificate(keyPair, "DE", "PayloadCertificate");
    }

    @Test
    void testDefineConstructor() {
        assertNotNull(new CertificateUtils());
    }

    @Test
    void testGetCertKid() throws Exception {
        byte[] expectedKid = Arrays.copyOfRange(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()), 0, 8);

        String calculatedKid = certificateUtils.getCertKid(certificate);

        Assertions.assertEquals(8, Base64.getDecoder().decode(calculatedKid).length);
        Assertions.assertEquals(Base64.getEncoder().encodeToString(expectedKid), certificateUtils.getCertKid(certificate));
    }

    @Test
    void testGetCertKidHolder() throws Exception {
        byte[] expectedKid = Arrays.copyOfRange(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()), 0, 8);

        X509CertificateHolder holder = new X509CertificateHolder(certificate.getEncoded());

        String calculatedKid = certificateUtils.getCertKid(holder);

        Assertions.assertEquals(8, Base64.getDecoder().decode(calculatedKid).length);
        Assertions.assertEquals(Base64.getEncoder().encodeToString(expectedKid), certificateUtils.getCertKid(holder));
    }

    @Test
    void testGetCertHash() throws Exception {
        byte[] expectedThumbprint = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
        byte[] thumbprint = Hex.decode(certificateUtils.getCertThumbprint(certificate));

        Assertions.assertArrayEquals(expectedThumbprint, thumbprint);
    }

    @Test
    void testGetCertHashHolder() throws Exception {
        X509CertificateHolder holder = new X509CertificateHolder(certificate.getEncoded());

        byte[] expectedThumbprint = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
        byte[] thumbprint = Hex.decode(certificateUtils.getCertThumbprint(holder));

        Assertions.assertArrayEquals(expectedThumbprint, thumbprint);
    }

    @Test
    void testConverter() throws Exception {
        X509CertificateHolder converted = certificateUtils.convertCertificate(certificate);

        Assertions.assertArrayEquals(certificate.getEncoded(), converted.getEncoded());

        X509Certificate reconverted = certificateUtils.convertCertificate(converted);

        Assertions.assertArrayEquals(converted.getEncoded(), reconverted.getEncoded());
    }

    @Test
    void kidShouldReturnNullIfCertIsBroken() throws CertificateEncodingException, IOException {
        X509Certificate certificateMock = mock(X509Certificate.class);
        when(certificateMock.getEncoded()).thenThrow(new CertificateEncodingException());

        Assertions.assertNull(certificateUtils.getCertKid(certificateMock));

        X509CertificateHolder certificateHolderMock = mock(X509CertificateHolder.class);
        when(certificateHolderMock.getEncoded()).thenThrow(new IOException());

        Assertions.assertNull(certificateUtils.getCertKid(certificateHolderMock));
    }

    @Test
    void certThumbprintShouldReturnNullIfCertIsBroken() throws CertificateEncodingException, IOException {
        X509Certificate certificateMock = mock(X509Certificate.class);
        when(certificateMock.getEncoded()).thenThrow(new CertificateEncodingException());

        Assertions.assertNull(certificateUtils.getCertThumbprint(certificateMock));

        X509CertificateHolder certificateHolderMock = mock(X509CertificateHolder.class);
        when(certificateHolderMock.getEncoded()).thenThrow(new IOException());

        Assertions.assertNull(certificateUtils.getCertThumbprint(certificateHolderMock));
    }

    @Test
    void certThumbprintShouldReturnLeadingZero() throws CertificateEncodingException {
        X509Certificate certificateMock = mock(X509Certificate.class);

        // Hash of this String is 0ff414937084de132c1ea9c97eb8f8cf4859ac691d32e0892ebd2edeb35bb848
        when(certificateMock.getEncoded()).thenReturn("fde3383jssk11ß9928018382mxm,sl".getBytes(StandardCharsets.UTF_8));

        Assertions.assertTrue(certificateUtils.getCertThumbprint(certificateMock).startsWith("0"));
    }
}

