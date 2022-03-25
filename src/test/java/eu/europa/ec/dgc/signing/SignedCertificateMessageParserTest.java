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

class SignedCertificateMessageParserTest {

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
    void parserShouldParseByteArray() throws IOException, CertificateEncodingException {
        SignedCertificateMessageParser parser = new SignedCertificateMessageParser(
            Base64.getEncoder().encode(builder.build()));

        Assertions.assertEquals(SignedCertificateMessageParser.ParserState.SUCCESS, parser.getParserState());
        Assertions.assertArrayEquals(payloadCertificate.getEncoded(), parser.getPayload().getEncoded());
        Assertions.assertArrayEquals(signingCertificate.getEncoded(), parser.getSigningCertificate().getEncoded());
        Assertions.assertTrue(parser.isSignatureVerified());
        checkDetachedSignatureFromParser(parser.getSignature());
        checkDetachedSignatureFromParser(parser.getDetachedSignature());
        checkEmbeddedSignatureFromParser(parser.getEmbeddedSignature());
    }

    @Test
    void parserShouldParseByteArrayWithDetachedPayload() throws IOException, CertificateEncodingException {
        byte[] cms = Base64.getEncoder().encode(builder.build(true));

        SignedCertificateMessageParser parser = new SignedCertificateMessageParser(
            cms,
            Base64.getEncoder().encode(payloadCertificate.getEncoded()));

        Assertions.assertEquals(SignedCertificateMessageParser.ParserState.SUCCESS, parser.getParserState());
        Assertions.assertArrayEquals(payloadCertificate.getEncoded(), parser.getPayload().getEncoded());
        Assertions.assertArrayEquals(signingCertificate.getEncoded(), parser.getSigningCertificate().getEncoded());
        Assertions.assertTrue(parser.isSignatureVerified());
        Assertions.assertEquals(new String(cms), parser.getSignature());
    }

    @Test
    void parserShouldParseByteArrayWithDetachedPayloadAsString() throws IOException, CertificateEncodingException {
        byte[] cms = Base64.getEncoder().encode(builder.build(true));

        SignedCertificateMessageParser parser = new SignedCertificateMessageParser(
            cms,
            Base64.getEncoder().encodeToString(payloadCertificate.getEncoded()));

        Assertions.assertEquals(SignedCertificateMessageParser.ParserState.SUCCESS, parser.getParserState());
        Assertions.assertArrayEquals(payloadCertificate.getEncoded(), parser.getPayload().getEncoded());
        Assertions.assertArrayEquals(signingCertificate.getEncoded(), parser.getSigningCertificate().getEncoded());
        Assertions.assertTrue(parser.isSignatureVerified());
        checkDetachedSignatureFromParser(parser.getSignature());
        checkDetachedSignatureFromParser(parser.getDetachedSignature());
        checkEmbeddedSignatureFromParser(parser.getEmbeddedSignature());
    }

    @Test
    void parserShouldParseString() throws IOException, CertificateEncodingException {
        SignedCertificateMessageParser parser = new SignedCertificateMessageParser(
            builder.buildAsString());

        Assertions.assertEquals(SignedCertificateMessageParser.ParserState.SUCCESS, parser.getParserState());
        Assertions.assertArrayEquals(payloadCertificate.getEncoded(), parser.getPayload().getEncoded());
        Assertions.assertArrayEquals(signingCertificate.getEncoded(), parser.getSigningCertificate().getEncoded());
        Assertions.assertTrue(parser.isSignatureVerified());
        checkDetachedSignatureFromParser(parser.getSignature());
        checkDetachedSignatureFromParser(parser.getDetachedSignature());
        checkEmbeddedSignatureFromParser(parser.getEmbeddedSignature());
    }

    @Test
    void parserShouldParseStringWithDetachedPayload() throws IOException, CertificateEncodingException {
        SignedCertificateMessageParser parser = new SignedCertificateMessageParser(
            builder.buildAsString(true),
            Base64.getEncoder().encode(payloadCertificate.getEncoded()));

        Assertions.assertEquals(SignedCertificateMessageParser.ParserState.SUCCESS, parser.getParserState());
        Assertions.assertArrayEquals(payloadCertificate.getEncoded(), parser.getPayload().getEncoded());
        Assertions.assertArrayEquals(signingCertificate.getEncoded(), parser.getSigningCertificate().getEncoded());
        Assertions.assertTrue(parser.isSignatureVerified());
        checkDetachedSignatureFromParser(parser.getSignature());
        checkDetachedSignatureFromParser(parser.getDetachedSignature());
        checkEmbeddedSignatureFromParser(parser.getEmbeddedSignature());
    }

    @Test
    void parserShouldDetectBrokenBase64() {
        SignedCertificateMessageParser parser = new SignedCertificateMessageParser("randomBadBase64String");

        Assertions.assertEquals(SignedCertificateMessageParser.ParserState.FAILURE_INVALID_BASE64, parser.getParserState());
        Assertions.assertFalse(parser.isSignatureVerified());
    }

    @Test
    void parserShouldDetectBrokenCms() {
        SignedCertificateMessageParser parser = new SignedCertificateMessageParser(Base64.getEncoder().encode("randomString".getBytes(StandardCharsets.UTF_8)));

        Assertions.assertEquals(SignedCertificateMessageParser.ParserState.FAILURE_INVALID_CMS, parser.getParserState());
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

        SignedCertificateMessageParser parser = new SignedCertificateMessageParser(Base64.getEncoder().encode(signedData.getEncoded()));

        Assertions.assertEquals(SignedCertificateMessageParser.ParserState.FAILURE_INVALID_CMS_BODY, parser.getParserState());
        Assertions.assertFalse(parser.isSignatureVerified());
    }

    @Test
    void parserShouldDetectInvalidCmsContent() throws Exception {
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


        CMSProcessableByteArray cmsByteArray = new CMSProcessableByteArray(new byte[0]);
        CMSSignedData signedData = signedDataGenerator.generate(cmsByteArray, true);

        SignedCertificateMessageParser parser = new SignedCertificateMessageParser(Base64.getEncoder().encode(signedData.getEncoded()));

        Assertions.assertEquals(SignedCertificateMessageParser.ParserState.FAILURE_CMS_BODY_PARSING_FAILED, parser.getParserState());
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

        CMSProcessableByteArray cmsByteArray = new CMSProcessableByteArray(payloadCertificate.getEncoded());
        CMSSignedData signedData = signedDataGenerator.generate(cmsByteArray, true);

        SignedCertificateMessageParser parser = new SignedCertificateMessageParser(Base64.getEncoder().encode(signedData.getEncoded()));

        Assertions.assertEquals(SignedCertificateMessageParser.ParserState.FAILURE_CMS_SIGNING_CERT_INVALID, parser.getParserState());
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

        CMSProcessableByteArray cmsByteArray = new CMSProcessableByteArray(payloadCertificate.getEncoded());
        CMSSignedData signedData = signedDataGenerator.generate(cmsByteArray, true);

        SignedCertificateMessageParser parser = new SignedCertificateMessageParser(Base64.getEncoder().encode(signedData.getEncoded()));

        Assertions.assertEquals(SignedCertificateMessageParser.ParserState.FAILURE_CMS_SIGNER_INFO, parser.getParserState());
        Assertions.assertFalse(parser.isSignatureVerified());
    }

    private void checkDetachedSignatureFromParser(String signature) throws CertificateEncodingException, IOException {
        SignedCertificateMessageParser parser = new SignedCertificateMessageParser(
            signature, Base64.getEncoder().encodeToString(payloadCertificate.getEncoded()));

        Assertions.assertEquals(SignedCertificateMessageParser.ParserState.SUCCESS, parser.getParserState());
        Assertions.assertEquals(new X509CertificateHolder(payloadCertificate.getEncoded()), parser.getPayload());
        Assertions.assertEquals(new X509CertificateHolder(signingCertificate.getEncoded()), parser.getSigningCertificate());
        Assertions.assertTrue(parser.isSignatureVerified());
        Assertions.assertEquals(signature, parser.getSignature());
    }

    private void checkEmbeddedSignatureFromParser(String signature) throws CertificateEncodingException, IOException {
        SignedCertificateMessageParser parser = new SignedCertificateMessageParser(signature);

        Assertions.assertEquals(SignedStringMessageParser.ParserState.SUCCESS, parser.getParserState());
        Assertions.assertEquals(new X509CertificateHolder(payloadCertificate.getEncoded()), parser.getPayload());
        Assertions.assertEquals(new X509CertificateHolder(signingCertificate.getEncoded()), parser.getSigningCertificate());
        Assertions.assertTrue(parser.isSignatureVerified());
        Assertions.assertEquals(signature, parser.getEmbeddedSignature());
    }
}

