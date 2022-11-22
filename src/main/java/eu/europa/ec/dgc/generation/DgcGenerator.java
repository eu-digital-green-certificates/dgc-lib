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

package eu.europa.ec.dgc.generation;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterInputStream;
import org.springframework.stereotype.Service;

/**
 * Dgc Generator util.
 * It can generate EDGC cose structure, hash for signing,
 * copy the signature into cose and also generate final QR Code as string.
 */
@Service
public class DgcGenerator {
    /**
     * Generate CBOR EDGC payload for COSE.
     * The json string need to be valid according to specification
     * https://github.com/ehn-digital-green-development/hcert-spec
     * no json structure validation is done here
     *
     * @param edgcJson      edgc payload as json string
     * @param countryCode   for example DE
     * @param issuedAt      unix time in sec
     * @param expirationSec unix time in sec
     * @return CBOR bytes
     */
    public byte[] genDgcCbor(String edgcJson, String countryCode, long issuedAt, long expirationSec) {
        CBORObject map = CBORObject.NewMap();
        if (countryCode == null || countryCode.length() == 0) {
            throw new IllegalArgumentException("dcc issuer is null or empty");
        }
        map.set(CBORObject.FromObject(1), CBORObject.FromObject(countryCode));
        map.set(CBORObject.FromObject(6), CBORObject.FromObject(issuedAt));
        map.set(CBORObject.FromObject(4), CBORObject.FromObject(expirationSec));
        CBORObject hcertVersion = CBORObject.NewMap();
        CBORObject hcert = CBORObject.FromJSONString(edgcJson);
        hcertVersion.set(CBORObject.FromObject(1), hcert);
        map.set(CBORObject.FromObject(-260), hcertVersion);
        return map.EncodeToBytes();
    }

    /**
     * Generate COSE unsigned structure with payload.
     *
     * @param payload it should be CBOR data
     * @param keyId   for protected data or null if not to set
     * @param algId   for protected data for example -7 (means EC) or 0 if not to set
     * @return cose bytes
     */
    public byte[] genCoseUnsigned(byte[] payload, byte[] keyId, int algId) {
        CBORObject protectedHeader = CBORObject.NewMap();
        if (algId != 0) {
            protectedHeader.set(CBORObject.FromObject(1), CBORObject.FromObject(algId));
        }
        if (keyId != null) {
            protectedHeader.set(CBORObject.FromObject(4), CBORObject.FromObject(keyId));
        }
        byte[] protectedHeaderBytes = protectedHeader.EncodeToBytes();

        CBORObject coseObject = CBORObject.NewArray();
        coseObject.Add(protectedHeaderBytes);
        CBORObject unprotectedHeader = CBORObject.NewMap();
        coseObject.Add(unprotectedHeader);
        coseObject.Add(CBORObject.FromObject(payload));
        byte[] sigDummy = new byte[0];
        coseObject.Add(CBORObject.FromObject(sigDummy));
        return CBORObject.FromObjectAndTag(coseObject, 18).EncodeToBytes();
    }

    /**
     * Set Signature in COSE data.
     *
     * @param coseData  bytes
     * @param signature cose signature
     * @return cose bytes with signature
     */
    public byte[] dgcSetCoseSignature(byte[] coseData, byte[] signature) {
        CBORObject cborObject = CBORObject.DecodeFromBytes(coseData);
        if (cborObject.getType() == CBORType.Array && cborObject.getValues().size() == 4) {
            cborObject.set(3, CBORObject.FromObject(signature));
        } else {
            throw new IllegalArgumentException("seems not to be cose");
        }
        return cborObject.EncodeToBytes();
    }

    /**
     * Set signature and unprotected header from partialDcc into unsigned cose dcc.
     *
     * @param cwtData    cwt paylaod data (cbor)
     * @param partialDcc cose with signature and unprotected header
     * @return signed cose dcc
     */
    public byte[] dgcSetCosePartial(byte[] cwtData, byte[] partialDcc) {
        CBORObject partialCose = CBORObject.DecodeFromBytes(partialDcc);
        if (partialCose.getType() != CBORType.Array || partialCose.getValues().size() < 3) {
            throw new IllegalArgumentException("partial dcc is not cbor array");
        }
        partialCose.set(2, CBORObject.FromObject(cwtData));
        return partialCose.EncodeToBytes();
    }

    /**
     * convert cose bytes to qr code data.
     *
     * @param cose signed edgc data
     * @return qr code data
     */
    public String coseToQrCode(byte[] cose) {
        ByteArrayInputStream bis = new ByteArrayInputStream(cose);
        DeflaterInputStream compessedInput = new DeflaterInputStream(bis, new Deflater(9));
        byte[] coseCompressed;
        try {
            coseCompressed = compessedInput.readAllBytes();
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
        String coded = Base45Encoder.encodeToString(coseCompressed);
        return "HC1:" + coded;
    }

    /**
     * comute hash from cose data.
     *
     * @param coseMessage cose message
     * @return hash bytes
     */
    public byte[] computeCoseSignHash(byte[] coseMessage) {
        try {
            CBORObject coseForSign = CBORObject.NewArray();
            CBORObject cborCose = CBORObject.DecodeFromBytes(coseMessage);
            if (cborCose.getType() == CBORType.Array) {
                coseForSign.Add(CBORObject.FromObject("Signature1"));
                coseForSign.Add(cborCose.get(0).GetByteString());
                coseForSign.Add(new byte[0]);
                coseForSign.Add(cborCose.get(2).GetByteString());
            }
            byte[] coseForSignBytes = coseForSign.EncodeToBytes();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(coseForSignBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
