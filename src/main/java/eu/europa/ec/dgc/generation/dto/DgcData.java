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

package eu.europa.ec.dgc.generation.dto;

public class DgcData {

    private byte[] dek;
    /**
     * encrypted dcc cwt (cbor payload) data (cose array item 2).
     */
    private byte[] dataEncrypted;
    private byte[] hash;
    /**
     * unsigned dcc COSE data.
     */
    private byte[] dccData;

    public byte[] getDek() {
        return dek;
    }

    public void setDek(byte[] dek) {
        this.dek = dek;
    }

    public byte[] getDataEncrypted() {
        return dataEncrypted;
    }

    public void setDataEncrypted(byte[] dataEncrypted) {
        this.dataEncrypted = dataEncrypted;
    }

    public byte[] getHash() {
        return hash;
    }

    public void setHash(byte[] hash) {
        this.hash = hash;
    }

    public byte[] getDccData() {
        return dccData;
    }

    public void setDccData(byte[] dccData) {
        this.dccData = dccData;
    }
}
