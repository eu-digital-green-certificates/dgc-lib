/*-
 * ---license-start
 * WHO Digital Documentation Covid Certificate Gateway Service / dgc-lib
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

package eu.europa.ec.dgc.generation.dto;

public class DgcInitData {

    private String issuerCode;
    private long issuedAt;
    private long expriation;
    private int algId;
    private byte[] keyId;
    /**
     * if true the whole cose unsigned data are encrypted.
     * if false only the cwt cbor data are encrypted
     */
    private boolean encryptCose = false;

    public String getIssuerCode() {
        return issuerCode;
    }

    public void setIssuerCode(String issuerCode) {
        this.issuerCode = issuerCode;
    }

    public long getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(long issuedAt) {
        this.issuedAt = issuedAt;
    }

    public long getExpriation() {
        return expriation;
    }

    public void setExpriation(long expriation) {
        this.expriation = expriation;
    }

    public int getAlgId() {
        return algId;
    }

    public void setAlgId(int algId) {
        this.algId = algId;
    }

    public byte[] getKeyId() {
        return keyId;
    }

    public void setKeyId(byte[] keyId) {
        this.keyId = keyId;
    }

    public boolean isEncryptCose() {
        return encryptCose;
    }

    public void setEncryptCose(boolean encryptCose) {
        this.encryptCose = encryptCose;
    }
}
