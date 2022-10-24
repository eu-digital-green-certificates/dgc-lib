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

import eu.europa.ec.dgc.testdata.CertificateTestUtils;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SignedCertificateMessageBuilderTest {

    KeyPair payloadKeyPair, signingKeyPair;
    X509Certificate payloadCertificate, signingCertificate;

    SignedCertificateMessageBuilder builder;

    @BeforeEach
    void setupTestData() throws Exception {
        payloadKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        payloadCertificate = CertificateTestUtils.generateCertificate(payloadKeyPair, "DE", "PayloadCertificate");

        signingKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        signingCertificate = CertificateTestUtils.generateCertificate(signingKeyPair, "DE", "SigningCertificate");

        builder = new SignedCertificateMessageBuilder()
            .withPayload(new X509CertificateHolder(payloadCertificate.getEncoded()))
            .withSigningCertificate(new X509CertificateHolder(signingCertificate.getEncoded()), signingKeyPair.getPrivate());
    }

    @Test
    void testUnreadyBuilder() {
        builder = new SignedCertificateMessageBuilder();
        Assertions.assertThrows(RuntimeException.class, builder::buildAsString);
    }

    @Test
    void testCatchExceptionDuringBuild() throws IOException {
        X509CertificateHolder certMock = mock(X509CertificateHolder.class);
        when(certMock.getEncoded()).thenThrow(new IOException());

        builder.withPayload(certMock);

        Assertions.assertThrows(RuntimeException.class, builder::build);
    }

    @Test
    void testSignedMessage() throws Exception {
        CMSSignedData cmsSignedData = new CMSSignedData(builder.build());

        Assertions.assertEquals(CMSObjectIdentifiers.data, cmsSignedData.getSignedContent().getContentType());
        Assertions.assertArrayEquals(payloadCertificate.getEncoded(), (byte[]) cmsSignedData.getSignedContent().getContent());

        X509CertificateHolder readPayloadCertificate = new X509CertificateHolder((byte[]) cmsSignedData.getSignedContent().getContent());
        Assertions.assertNotNull(readPayloadCertificate);

        Collection<X509CertificateHolder> certificateHolderCollection = cmsSignedData.getCertificates().getMatches(null);
        Assertions.assertEquals(1, certificateHolderCollection.size());
        X509CertificateHolder readSigningCertificate = certificateHolderCollection.iterator().next();
        Assertions.assertNotNull(readSigningCertificate);

        Assertions.assertEquals(1, cmsSignedData.getSignerInfos().size());
        SignerInformation signerInformation = cmsSignedData.getSignerInfos().iterator().next();

        Assertions.assertTrue(signerInformation.verify(new JcaSimpleSignerInfoVerifierBuilder().build(signingCertificate)));
        Assertions.assertTrue(signerInformation.verify(new JcaSimpleSignerInfoVerifierBuilder().build(readSigningCertificate)));
    }

    @Test
    void testSignedMessageDetached() throws Exception {
        CMSSignedData cmsSignedData = new CMSSignedData(builder.build(true));

        Assertions.assertNull(cmsSignedData.getSignedContent());

        Collection<X509CertificateHolder> certificateHolderCollection = cmsSignedData.getCertificates().getMatches(null);
        Assertions.assertEquals(1, certificateHolderCollection.size());
        X509CertificateHolder readSigningCertificate = certificateHolderCollection.iterator().next();
        Assertions.assertNotNull(readSigningCertificate);

        cmsSignedData = new CMSSignedData(new CMSProcessableByteArray(payloadCertificate.getEncoded()), builder.build(true));

        Assertions.assertEquals(1, cmsSignedData.getSignerInfos().size());
        SignerInformation signerInformation = cmsSignedData.getSignerInfos().iterator().next();

        Assertions.assertTrue(signerInformation.verify(new JcaSimpleSignerInfoVerifierBuilder().build(signingCertificate)));
        Assertions.assertTrue(signerInformation.verify(new JcaSimpleSignerInfoVerifierBuilder().build(readSigningCertificate)));
    }

    @Test
    void testSignedMessageBase64() throws Exception {
        CMSSignedData cmsSignedData = new CMSSignedData(Base64.getDecoder().decode(builder.buildAsString()));

        Assertions.assertEquals(CMSObjectIdentifiers.data, cmsSignedData.getSignedContent().getContentType());
        Assertions.assertArrayEquals(payloadCertificate.getEncoded(), (byte[]) cmsSignedData.getSignedContent().getContent());

        X509CertificateHolder readPayloadCertificate = new X509CertificateHolder((byte[]) cmsSignedData.getSignedContent().getContent());
        Assertions.assertNotNull(readPayloadCertificate);

        Collection<X509CertificateHolder> certificateHolderCollection = cmsSignedData.getCertificates().getMatches(null);
        Assertions.assertEquals(1, certificateHolderCollection.size());
        X509CertificateHolder readSigningCertificate = certificateHolderCollection.iterator().next();
        Assertions.assertNotNull(readSigningCertificate);

        Assertions.assertEquals(1, cmsSignedData.getSignerInfos().size());
        SignerInformation signerInformation = cmsSignedData.getSignerInfos().iterator().next();

        Assertions.assertTrue(signerInformation.verify(new JcaSimpleSignerInfoVerifierBuilder().build(signingCertificate)));
        Assertions.assertTrue(signerInformation.verify(new JcaSimpleSignerInfoVerifierBuilder().build(readSigningCertificate)));
    }

    @Test
    void testSignedMessageDetachedBase64() throws Exception {
        CMSSignedData cmsSignedData = new CMSSignedData(Base64.getDecoder().decode(builder.buildAsString(true)));

        Assertions.assertNull(cmsSignedData.getSignedContent());

        Collection<X509CertificateHolder> certificateHolderCollection = cmsSignedData.getCertificates().getMatches(null);
        Assertions.assertEquals(1, certificateHolderCollection.size());
        X509CertificateHolder readSigningCertificate = certificateHolderCollection.iterator().next();
        Assertions.assertNotNull(readSigningCertificate);

        cmsSignedData = new CMSSignedData(new CMSProcessableByteArray(payloadCertificate.getEncoded()), Base64.getDecoder().decode(builder.buildAsString(true)));

        Assertions.assertEquals(1, cmsSignedData.getSignerInfos().size());
        SignerInformation signerInformation = cmsSignedData.getSignerInfos().iterator().next();

        Assertions.assertTrue(signerInformation.verify(new JcaSimpleSignerInfoVerifierBuilder().build(signingCertificate)));
        Assertions.assertTrue(signerInformation.verify(new JcaSimpleSignerInfoVerifierBuilder().build(readSigningCertificate)));
    }
}
