package eu.europa.ec.dgc.generation;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
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
