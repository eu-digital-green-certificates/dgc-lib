/*-
 * ---license-start
 * eu-digital-green-certificates / dgc-lib
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

package eu.europa.ec.dgc.gateway.connector.dto;

import java.time.ZonedDateTime;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
public class RevocationBatchListDto {


    private Boolean more;

    private List<RevocationBatchListItemDto> batches;

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class RevocationBatchListItemDto {

        private String batchId;

        private String country;

        private ZonedDateTime date;

        private Boolean deleted;
    }
}