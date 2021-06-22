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

import eu.europa.ec.dgc.testdata.CertificateTestUtils;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

class SignedStringMessageParserTest {

    KeyPair signingKeyPair;
    X509Certificate signingCertificate;

    SignedStringMessageBuilder builder;
    String payloadString = "{ \"key\": \"HalloWeltABC\" }";

    @BeforeEach
    void setupTestData() throws Exception {
        signingKeyPair = KeyPairGenerator.getInstance("ec").generateKeyPair();
        signingCertificate = CertificateTestUtils.generateCertificate(signingKeyPair, "DE", "SigningCertificate");

        builder = new SignedStringMessageBuilder()
            .withPayload(payloadString)
            .withSigningCertificate(new X509CertificateHolder(signingCertificate.getEncoded()), signingKeyPair.getPrivate());
    }

    @Test
    void parserShouldParseByteArray() throws IOException, CertificateEncodingException {
        SignedStringMessageParser parser = new SignedStringMessageParser(
            Base64.getEncoder().encode(builder.build()));

        Assertions.assertEquals(SignedStringMessageParser.ParserState.SUCCESS, parser.getParserState());
        Assertions.assertEquals(payloadString, parser.getPayload());
        Assertions.assertArrayEquals(signingCertificate.getEncoded(), parser.getSigningCertificate().getEncoded());
        Assertions.assertTrue(parser.isSignatureVerified());
        checkSignatureFromParser(parser.getSignature());
    }

    @Test
    void parserShouldParseByteArrayWithDetachedPayload() throws IOException, CertificateEncodingException {
        byte[] cms = Base64.getEncoder().encode(builder.build(true));

        SignedStringMessageParser parser = new SignedStringMessageParser(
            cms,
            Base64.getEncoder().encode(payloadString.getBytes(StandardCharsets.UTF_8)));

        Assertions.assertEquals(SignedStringMessageParser.ParserState.SUCCESS, parser.getParserState());
        Assertions.assertEquals(payloadString, parser.getPayload());
        Assertions.assertArrayEquals(signingCertificate.getEncoded(), parser.getSigningCertificate().getEncoded());
        Assertions.assertTrue(parser.isSignatureVerified());
        Assertions.assertEquals(new String(cms), parser.getSignature());
    }

    @Test
    void parserShouldParseByteArrayWithDetachedPayloadAsString() throws IOException, CertificateEncodingException {
        byte[] cms = Base64.getEncoder().encode(builder.build(true));

        SignedStringMessageParser parser = new SignedStringMessageParser(
            cms,
            Base64.getEncoder().encodeToString(payloadString.getBytes(StandardCharsets.UTF_8)));

        Assertions.assertEquals(SignedStringMessageParser.ParserState.SUCCESS, parser.getParserState());
        Assertions.assertEquals(payloadString, parser.getPayload());
        Assertions.assertArrayEquals(signingCertificate.getEncoded(), parser.getSigningCertificate().getEncoded());
        Assertions.assertTrue(parser.isSignatureVerified());
        checkSignatureFromParser(parser.getSignature());
    }

    @Test
    void parserShouldParseString() throws IOException, CertificateEncodingException {
        SignedStringMessageParser parser = new SignedStringMessageParser(
            builder.buildAsString());

        Assertions.assertEquals(SignedStringMessageParser.ParserState.SUCCESS, parser.getParserState());
        Assertions.assertEquals(payloadString, parser.getPayload());
        Assertions.assertArrayEquals(signingCertificate.getEncoded(), parser.getSigningCertificate().getEncoded());
        Assertions.assertTrue(parser.isSignatureVerified());
        checkSignatureFromParser(parser.getSignature());
    }

    @Test
    void parserShouldParseStringWithDetachedPayload() throws IOException, CertificateEncodingException {
        SignedStringMessageParser parser = new SignedStringMessageParser(
            builder.buildAsString(true),
            Base64.getEncoder().encode(payloadString.getBytes(StandardCharsets.UTF_8)));

        Assertions.assertEquals(SignedStringMessageParser.ParserState.SUCCESS, parser.getParserState());
        Assertions.assertEquals(payloadString, parser.getPayload());
        Assertions.assertArrayEquals(signingCertificate.getEncoded(), parser.getSigningCertificate().getEncoded());
        Assertions.assertTrue(parser.isSignatureVerified());
        checkSignatureFromParser(parser.getSignature());
    }

    @Test
    void parserShouldDetectBrokenBase64() {
        SignedStringMessageParser parser = new SignedStringMessageParser("randomBadBase64String");

        Assertions.assertEquals(SignedStringMessageParser.ParserState.FAILURE_INVALID_BASE64, parser.getParserState());
        Assertions.assertFalse(parser.isSignatureVerified());
    }

    @Test
    void parserShouldDetectBrokenCms() {
        SignedStringMessageParser parser = new SignedStringMessageParser(Base64.getEncoder().encode("randomString".getBytes(StandardCharsets.UTF_8)));

        Assertions.assertEquals(SignedStringMessageParser.ParserState.FAILURE_INVALID_CMS, parser.getParserState());
        Assertions.assertFalse(parser.isSignatureVerified());
    }

    @Test
    void parserShouldDetectInvalidCmsContentType() throws Exception {
        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();

        X509CertificateHolder signingCertificateHolder = new X509CertificateHolder(signingCertificate.getEncoded());

        CMSSignedDataGenerator signedDataGenerator = new CMSSignedDataGenerator();

        String signingAlgorithmName =
            new DefaultAlgorithmNameFinder().getAlgorithmName(signingCertificateHolder.getSignatureAlgorithm());

        ContentSigner contentSigner =
            new JcaContentSignerBuilder(signingAlgorithmName).build(signingKeyPair.getPrivate());

        SignerInfoGenerator signerInfoGenerator = new JcaSignerInfoGeneratorBuilder(digestCalculatorProvider)
            .build(contentSigner, signingCertificate);

        signedDataGenerator.addSignerInfoGenerator(signerInfoGenerator);

        signedDataGenerator.addCertificate(signingCertificateHolder);


        CMSProcessableByteArray cmsByteArrayMock = spy(new CMSProcessableByteArray(new byte[0]));
        when(cmsByteArrayMock.getContentType()).thenReturn(CMSObjectIdentifiers.encryptedData);

        CMSSignedData signedData = signedDataGenerator.generate(cmsByteArrayMock, true);

        SignedStringMessageParser parser = new SignedStringMessageParser(Base64.getEncoder().encode(signedData.getEncoded()));

        Assertions.assertEquals(SignedStringMessageParser.ParserState.FAILURE_INVALID_CMS_BODY, parser.getParserState());
        Assertions.assertFalse(parser.isSignatureVerified());
    }

    @Test
    void parserShouldDetectInvalidCertificateAmount() throws Exception {
        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();

        X509CertificateHolder signingCertificateHolder = new X509CertificateHolder(signingCertificate.getEncoded());

        CMSSignedDataGenerator signedDataGenerator = new CMSSignedDataGenerator();

        String signingAlgorithmName =
            new DefaultAlgorithmNameFinder().getAlgorithmName(signingCertificateHolder.getSignatureAlgorithm());

        ContentSigner contentSigner =
            new JcaContentSignerBuilder(signingAlgorithmName).build(signingKeyPair.getPrivate());

        SignerInfoGenerator signerInfoGenerator = new JcaSignerInfoGeneratorBuilder(digestCalculatorProvider)
            .build(contentSigner, signingCertificate);

        signedDataGenerator.addSignerInfoGenerator(signerInfoGenerator);

        signedDataGenerator.addCertificate(signingCertificateHolder);
        signedDataGenerator.addCertificate(signingCertificateHolder);

        CMSProcessableByteArray cmsByteArray = new CMSProcessableByteArray(payloadString.getBytes(StandardCharsets.UTF_8));
        CMSSignedData signedData = signedDataGenerator.generate(cmsByteArray, true);

        SignedStringMessageParser parser = new SignedStringMessageParser(Base64.getEncoder().encode(signedData.getEncoded()));

        Assertions.assertEquals(SignedStringMessageParser.ParserState.FAILURE_CMS_SIGNING_CERT_INVALID, parser.getParserState());
        Assertions.assertFalse(parser.isSignatureVerified());
    }

    @Test
    void parserShouldDetectInvalidSignerInfoAmount() throws Exception {
        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();

        X509CertificateHolder signingCertificateHolder = new X509CertificateHolder(signingCertificate.getEncoded());

        CMSSignedDataGenerator signedDataGenerator = new CMSSignedDataGenerator();

        String signingAlgorithmName =
            new DefaultAlgorithmNameFinder().getAlgorithmName(signingCertificateHolder.getSignatureAlgorithm());

        ContentSigner contentSigner =
            new JcaContentSignerBuilder(signingAlgorithmName).build(signingKeyPair.getPrivate());

        SignerInfoGenerator signerInfoGenerator = new JcaSignerInfoGeneratorBuilder(digestCalculatorProvider)
            .build(contentSigner, signingCertificate);

        signedDataGenerator.addSignerInfoGenerator(signerInfoGenerator);
        signedDataGenerator.addSignerInfoGenerator(signerInfoGenerator);

        signedDataGenerator.addCertificate(signingCertificateHolder);

        CMSProcessableByteArray cmsByteArray = new CMSProcessableByteArray(payloadString.getBytes(StandardCharsets.UTF_8));
        CMSSignedData signedData = signedDataGenerator.generate(cmsByteArray, true);

        SignedStringMessageParser parser = new SignedStringMessageParser(Base64.getEncoder().encode(signedData.getEncoded()));

        Assertions.assertEquals(SignedStringMessageParser.ParserState.FAILURE_CMS_SIGNER_INFO, parser.getParserState());
        Assertions.assertFalse(parser.isSignatureVerified());
    }

    private void checkSignatureFromParser(String signature) throws CertificateEncodingException, IOException {
        SignedStringMessageParser parser = new SignedStringMessageParser(
            signature, Base64.getEncoder().encodeToString(payloadString.getBytes(StandardCharsets.UTF_8)));

        Assertions.assertEquals(SignedStringMessageParser.ParserState.SUCCESS, parser.getParserState());
        Assertions.assertEquals(payloadString, parser.getPayload());
        Assertions.assertEquals(new X509CertificateHolder(signingCertificate.getEncoded()), parser.getSigningCertificate());
        Assertions.assertTrue(parser.isSignatureVerified());
        Assertions.assertEquals(signature, parser.getSignature());
    }
}

