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

package eu.europa.ec.dgc.generation;

import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

class Base45EncoderTest {

    @Test
    void encodeTest() {
        assertEquals("7WE QE",Base45Encoder.encodeToString("test".getBytes(StandardCharsets.UTF_8)));

        byte[] bytes = new byte[] { 0, 2, -2, 30, -12, 23, -23, -40};
        assertEquals("200T5WR%UEPT",Base45Encoder.encodeToString(bytes));
    }
}
