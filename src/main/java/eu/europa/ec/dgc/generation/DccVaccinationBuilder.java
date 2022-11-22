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

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.LocalDateTime;
import java.util.EnumSet;

public class DccVaccinationBuilder extends DccBuilderBase<DccVaccinationBuilder> {

    private ObjectNode vaccinationObject;

    private enum RequiredFields { vp, mp, ma, dn, sd, dt }

    private EnumSet<RequiredFields> requiredNotSet = EnumSet.allOf(RequiredFields.class);

    /**
     * the constructor.
     */
    public DccVaccinationBuilder() {
        super();

        vaccinationObject = jsonNodeFactory.objectNode();
        ArrayNode vaccinationArray = jsonNodeFactory.arrayNode();
        vaccinationArray.add(vaccinationObject);
        // disease-agent-targeted COVID-19
        // see https://github.com/ehn-digital-green-development/ehn-dgc-schema/blob/main/valuesets/disease-agent-targeted.json
        vaccinationObject.set("tg", jsonNodeFactory.textNode("840539006"));
        dccObject.set("v", vaccinationArray);
    }

    @Override
    public DccVaccinationBuilder getThis() {
        return this;
    }

    @Override
    public ObjectNode getValueHolder() {
        return vaccinationObject;
    }

    protected void validate() {
        super.validate();
        if (!requiredNotSet.isEmpty()) {
            throw new IllegalStateException("not all required fields set " + requiredNotSet);
        }
    }

    /**
     * vaccine Or Prophylaxis.
     *
     * @param vp vaccineOrProphylaxis
     * @return builder
     */
    public DccVaccinationBuilder vaccineOrProphylaxis(String vp) {
        /* TODO validate the vp or enum */
        vaccinationObject.set("vp", jsonNodeFactory.textNode(vp));
        requiredNotSet.remove(RequiredFields.vp);
        return this;
    }

    /**
     * medical product.
     *
     * @param mp medical product
     * @return builder
     */
    public DccVaccinationBuilder medicalProduct(String mp) {
        /* TODO validate the mp or enum */
        vaccinationObject.set("mp", jsonNodeFactory.textNode(mp));
        requiredNotSet.remove(RequiredFields.mp);
        return this;
    }

    /**
     * marketing Authorization.
     *
     * @param ma marketingAuthorization
     * @return builder
     */
    public DccVaccinationBuilder marketingAuthorization(String ma) {
        /* TODO validate the ma or enum */
        vaccinationObject.set("ma", jsonNodeFactory.textNode(ma));
        requiredNotSet.remove(RequiredFields.ma);
        return this;
    }

    /**
     * dose number.
     *
     * @param dn dose number
     * @return builder
     */
    public DccVaccinationBuilder doseNumber(int dn) {
        if (dn < 1 || dn > 9) {
            throw new IllegalArgumentException("invalid range of dn (1-9)");
        }
        vaccinationObject.set("dn", jsonNodeFactory.numberNode(dn));
        requiredNotSet.remove(RequiredFields.dn);
        return this;
    }

    /**
     * total series of doses.
     *
     * @param sd total series of doses
     * @return builder
     */
    public DccVaccinationBuilder totalSeriesOfDoses(int sd) {
        if (sd < 1 || sd > 9) {
            throw new IllegalArgumentException("invalid range of dn (1-9)");
        }
        vaccinationObject.set("sd", jsonNodeFactory.numberNode(sd));
        requiredNotSet.remove(RequiredFields.sd);
        return this;
    }

    /**
     * date time of vaccination.
     *
     * @param dateTime sc
     * @return builder
     */
    public DccVaccinationBuilder dateOfVaccination(LocalDateTime dateTime) {
        vaccinationObject.set("dt", jsonNodeFactory.textNode(toIsoO8601(dateTime)));
        requiredNotSet.remove(RequiredFields.dt);
        return this;
    }

}
