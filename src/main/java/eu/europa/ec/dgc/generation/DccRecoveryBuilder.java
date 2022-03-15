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

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.LocalDate;
import java.util.EnumSet;

public class DccRecoveryBuilder extends DccBuilderBase<DccRecoveryBuilder> {

    private ObjectNode recoveryObject;

    private enum RequiredFields { fr, df, du }

    private EnumSet<RequiredFields> requiredNotSet = EnumSet.allOf(RequiredFields.class);

    /**
     * the constructor.
     */
    public DccRecoveryBuilder() {
        super();

        recoveryObject = jsonNodeFactory.objectNode();
        ArrayNode vaccinationArray = jsonNodeFactory.arrayNode();
        vaccinationArray.add(recoveryObject);
        // disease-agent-targeted COVID-19
        // see https://github.com/ehn-digital-green-development/ehn-dgc-schema/blob/main/valuesets/disease-agent-targeted.json
        recoveryObject.set("tg", jsonNodeFactory.textNode("840539006"));
        dccObject.set("r", vaccinationArray);
    }

    @Override
    public DccRecoveryBuilder getThis() {
        return this;
    }

    @Override
    public ObjectNode getValueHolder() {
        return recoveryObject;
    }

    protected void validate() {
        super.validate();
        if (!requiredNotSet.isEmpty()) {
            throw new IllegalStateException("not all required fields set " + requiredNotSet);
        }
    }

    /**
     * first Day Positive Test.
     * @param fr first Day Positive Test.
     * @return builder
     */
    public DccRecoveryBuilder firstDayPositiveTest(LocalDate fr) {
        recoveryObject.set("fr", jsonNodeFactory.textNode(toIsoDate(fr)));
        requiredNotSet.remove(RequiredFields.fr);
        return this;
    }

    /**
     * certificate valid from.
     * @param df valid from.
     * @return builder
     */
    public DccRecoveryBuilder certificateValidFrom(LocalDate df) {
        recoveryObject.set("df", jsonNodeFactory.textNode(toIsoDate(df)));
        requiredNotSet.remove(RequiredFields.df);
        return this;
    }

    /**
     * certificate valid until.
     * @param du valid until.
     * @return builder
     */
    public DccRecoveryBuilder certificateValidUnitl(LocalDate du) {
        recoveryObject.set("du", jsonNodeFactory.textNode(toIsoDate(du)));
        requiredNotSet.remove(RequiredFields.du);
        return this;
    }

}
