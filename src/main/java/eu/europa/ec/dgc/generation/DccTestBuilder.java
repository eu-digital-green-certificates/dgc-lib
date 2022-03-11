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
import java.time.LocalDateTime;
import java.util.EnumSet;

/**
 * Builder for DCC Test Json.
 */
public class DccTestBuilder extends DccBuilderBase<DccTestBuilder> {
    private ObjectNode testObject;

    private enum RequiredFields { tt, sc, tr, tc }

    private EnumSet<RequiredFields> requiredNotSet = EnumSet.allOf(RequiredFields.class);

    /**
     * the constructor.
     */
    public DccTestBuilder() {
        super();

        testObject = jsonNodeFactory.objectNode();
        ArrayNode testArray = jsonNodeFactory.arrayNode();
        testArray.add(testObject);
        // disease-agent-targeted COVID-19
        // see https://github.com/ehn-digital-green-development/ehn-dgc-schema/blob/main/valuesets/disease-agent-targeted.json
        testObject.set("tg", jsonNodeFactory.textNode("840539006"));
        dccObject.set("t", testArray);
    }

    @Override
    public DccTestBuilder getThis() {
        return this;
    }

    @Override
    public ObjectNode getValueHolder() {
        return testObject;
    }

    /**
     * test result.
     * @param covidDetected covid detected
     * @return builder
     */
    public DccTestBuilder detected(boolean covidDetected) {
        // https://github.com/ehn-digital-green-development/ehn-dgc-schema/blob/main/valuesets/test-result.json
        testObject.set("tr", jsonNodeFactory.textNode(covidDetected ? "260373001" : "260415000"));
        requiredNotSet.remove(RequiredFields.tr);
        return this;
    }

    /**
     * test type.
     * @param isRapidTest true if rapid
     * @return builder
     */
    public DccTestBuilder testTypeRapid(boolean isRapidTest) {
        testObject.set("tt", jsonNodeFactory.textNode(isRapidTest ? "LP217198-3" : "LP6464-4"));
        requiredNotSet.remove(RequiredFields.tt);
        return this;
    }



    /**
     * testing centre.
     * @param tc testing centre
     * @return builder
     */
    public DccTestBuilder testingCentre(String tc) {
        testObject.set("tc", jsonNodeFactory.textNode(tc));
        assertNotNullMax("tc",tc,80);
        requiredNotSet.remove(RequiredFields.tc);
        return this;
    }

    /**
     * NAA Test Name.
     * @param nm "NAA Test Name"
     * @return builder
     */
    public DccTestBuilder testName(String nm) {
        testObject.set("nm", jsonNodeFactory.textNode(nm));
        assertNotNullMax("nm",nm,80);
        return this;
    }

    /**
     * test identifier.
     * Is required if test type is rapid.
     * There is value list for it but is not checked during setting
     * see https://github.com/ehn-dcc-development/ehn-dcc-schema/blob/main/valuesets/test-manf.json
     * @param ma test identifier
     * @return builder
     */
    public DccTestBuilder testIdentifier(String ma) {
        testObject.set("ma", jsonNodeFactory.textNode(ma));
        assertNotNullMax("ma",ma,0);
        return this;
    }


    /**
     * date time of sample collection.
     * @param dateTime sc
     * @return builder
     */
    public DccTestBuilder sampleCollection(LocalDateTime dateTime) {
        testObject.set("sc", jsonNodeFactory.textNode(toIsoO8601(dateTime)));
        requiredNotSet.remove(RequiredFields.sc);
        return this;
    }



    protected void validate() {
        super.validate();
        if (!requiredNotSet.isEmpty()) {
            throw new IllegalStateException("not all required fields set " + requiredNotSet);
        }
    }

}
