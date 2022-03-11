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

package eu.europa.ec.dgc.generation;

import java.io.IOException;
import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DgcSignerTest {
    KeyHelper keyHelper;

    @BeforeEach
    void setup() throws Exception {
        keyHelper = new KeyHelper();
    }

    public static String genSampleJson() {
        DccTestBuilder dccTestBuilder = new DccTestBuilder();
        dccTestBuilder.gn("Artur").fn("Trzewik").gnt("ARTUR").fnt("TRZEWIK").dob(LocalDate.parse("1973-01-01"));
        dccTestBuilder.detected(false)
                .dgci("URN:UVCI:01:OS:B5921A35D6A0D696421B3E2462178297I")
                .country("DE")
                .testTypeRapid(true)
                .testingCentre("Hochdahl")
                .certificateIssuer("Dr Who")
                .sampleCollection(LocalDateTime.now());
        return dccTestBuilder.toJsonString();
    }

    @Test
    void genEdgc() throws IOException {

        DgcGenerator dgcGenerator = new DgcGenerator();
        DgcSigner dgcSigner = new DgcSigner();

        String edgcJson = genSampleJson();

        String countryCode = "DE";
        ZonedDateTime now = ZonedDateTime.now();
        ZonedDateTime expiration = now.plus(Duration.of(365, ChronoUnit.DAYS));
        long issuedAt = now.toInstant().getEpochSecond();
        long expirationSec = expiration.toInstant().getEpochSecond();
        byte[] keyId = dgcSigner.keyId(keyHelper.getCert());
        // We assume that it is EC Key
        int algId = -7;

        byte[] dgcCbor = dgcGenerator.genDgcCbor(edgcJson, countryCode, issuedAt, expirationSec);

        byte[] coseBytes = dgcGenerator.genCoseUnsigned(dgcCbor, keyId, algId);
        byte[] hash = dgcGenerator.computeCoseSignHash(coseBytes);

        byte[] signature = dgcSigner.signHash(hash,keyHelper.getPrivateKey());

        byte[] coseSigned = dgcGenerator.dgcSetCoseSignature(coseBytes,signature);
        String edgcQR = dgcGenerator.coseToQrCode(coseSigned);

        System.out.println(edgcQR);
    }
}
