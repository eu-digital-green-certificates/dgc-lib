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

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.springframework.stereotype.Service;

/**
 * Utility Service with helpful commonly used methods related to certificate handling.
 */
@Slf4j
@Service
public class CertificateUtils {

    /**
     * Calculates the SHA-256 thumbprint of X509CertificateHolder.
     *
     * @param x509Certificate the certificate the thumbprint should be calculated for.
     * @return 32-byte SHA-256 hash as hex encoded string
     */
    public String getCertThumbprint(X509Certificate x509Certificate) {
        try {
            return calculateHash(x509Certificate.getEncoded());
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            log.error("Could not calculate thumbprint of certificate.");
            return null;
        }
    }

    /**
     * Calculates the SHA-256 thumbprint of X509CertificateHolder.
     *
     * @param x509CertificateHolder the certificate the thumbprint should be calculated for.
     * @return 32-byte SHA-256 hash as hex encoded string
     */
    public String getCertThumbprint(X509CertificateHolder x509CertificateHolder) {
        try {
            return calculateHash(x509CertificateHolder.getEncoded());
        } catch (IOException | NoSuchAlgorithmException e) {
            log.error("Could not calculate thumbprint of certificate.");
            return null;
        }
    }

    /**
     * Converts a X509Certificate into a X509CertificateHolder.
     *
     * @param inputCertificate the certificate to convert
     * @return converted certificate
     * @throws CertificateEncodingException if converting has failed.
     */
    public X509CertificateHolder convertCertificate(X509Certificate inputCertificate)
        throws CertificateEncodingException, IOException {
        return new X509CertificateHolder(inputCertificate.getEncoded());
    }

    /**
     * Converts a X509CertificateHolder into a X509Certificate.
     *
     * @param inputCertificate the certificate to convert
     * @return converted certificate
     * @throws CertificateException if converting has failed.
     */
    public X509Certificate convertCertificate(X509CertificateHolder inputCertificate)
        throws CertificateException {
        return new JcaX509CertificateConverter().getCertificate(inputCertificate);
    }

    private String calculateHash(byte[] data) throws NoSuchAlgorithmException {
        byte[] certHashBytes = MessageDigest.getInstance("SHA-256").digest(data);
        String hexString = new BigInteger(1, certHashBytes).toString(16);

        if (hexString.length() == 63) {
            hexString = "0" + hexString;
        }

        return hexString;
    }
}
