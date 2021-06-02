package eu.europa.ec.dgc.generation;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.EnumSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Builder for DCC Test Json.
 */
public class DccTestBuilder {

    private final JsonNodeFactory jsonNodeFactory;
    private final ObjectNode dccObject;
    private final ObjectNode nameObject;
    private final ObjectNode testObject;

    private enum RequiredFields {
        dob, fnt, tt, sc, tr, tc, co, is, ci
    }

    private final EnumSet<RequiredFields> requiredNotSet = EnumSet.allOf(RequiredFields.class);

    private static final Pattern standardNamePattern = Pattern.compile("^[A-Z<]*$");
    private static final Pattern countryPattern = Pattern.compile("[A-Z]{1,10}");

    private final DateTimeFormatter dateFormat;

    /**
     * the constructor.
     */
    public DccTestBuilder() {
        dateFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssZ");

        jsonNodeFactory = JsonNodeFactory.instance;
        dccObject = jsonNodeFactory.objectNode();
        nameObject = jsonNodeFactory.objectNode();
        testObject = jsonNodeFactory.objectNode();
        dccObject.set("version", jsonNodeFactory.textNode("1.0.0"));
        dccObject.set("nam", nameObject);
        ArrayNode testArray = jsonNodeFactory.arrayNode();
        testArray.add(testObject);
        // disease-agent-targeted COVID-19
        // see https://github.com/ehn-digital-green-development/ehn-dgc-schema/blob/main/valuesets/disease-agent-targeted.json
        testObject.set("tg", jsonNodeFactory.textNode("840539006"));
        dccObject.set("t", testArray);
    }

    /**
     * family name field.
     *
     * @param fn family name
     * @return builder
     */
    public DccTestBuilder fn(String fn) {
        assertNotNullMax("fn", fn, 50);
        nameObject.set("fn", jsonNodeFactory.textNode(fn));
        return this;
    }

    /**
     * given name.
     *
     * @param gn given name
     * @return builder
     */
    public DccTestBuilder gn(String gn) {
        assertNotNullMax("gn", gn, 50);
        nameObject.set("gn", jsonNodeFactory.textNode(gn));
        return this;
    }

    /**
     * standardized family name.
     *
     * @param fnt standardized family name
     * @return builder
     */
    public DccTestBuilder fnt(String fnt) {
        assertNotNullMaxPattern("fnt", fnt, 50, standardNamePattern);
        requiredNotSet.remove(RequiredFields.fnt);
        nameObject.set("fnt", jsonNodeFactory.textNode(fnt));
        return this;
    }

    /**
     * standarized given name.
     *
     * @param gnt standardized given name
     * @return builder
     */
    public DccTestBuilder gnt(String gnt) {
        assertNotNullMaxPattern("gnt", gnt, 50, standardNamePattern);
        nameObject.set("gnt", jsonNodeFactory.textNode(gnt));
        return this;
    }

    /**
     * buidl json string.
     *
     * @return json string
     */
    public String toJsonString() {
        if (!requiredNotSet.isEmpty()) {
            throw new IllegalStateException("not all required fields set " + requiredNotSet);
        }
        return dccObject.toString();
    }

    /**
     * certificate identifier.
     *
     * @param dgci certificate identifier
     * @return builder
     */
    public DccTestBuilder dgci(String dgci) {
        assertNotNullMax("ci", dgci, 50);
        testObject.set("ci", jsonNodeFactory.textNode(dgci));
        requiredNotSet.remove(RequiredFields.ci);
        return this;
    }

    /**
     * date of birth in iso format.
     *
     * @param birthday dob
     * @return builder
     */
    public DccTestBuilder dob(String birthday) {
        dccObject.set("dob", jsonNodeFactory.textNode(birthday));
        requiredNotSet.remove(RequiredFields.dob);
        return this;
    }

    /**
     * test result.
     *
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
     *
     * @param isRapidTest true if rapid
     * @return builder
     */
    public DccTestBuilder testTypeRapid(boolean isRapidTest) {
        testObject.set("tt", jsonNodeFactory.textNode(isRapidTest ? "LP217198-3" : "LP6464-4"));
        requiredNotSet.remove(RequiredFields.tt);
        return this;
    }

    /**
     * country of test.
     *
     * @param co co
     * @return builder
     */
    public DccTestBuilder countryOfTest(String co) {
        testObject.set("co", jsonNodeFactory.textNode(co));
        assertNotNullMaxPattern("co", co, 0, countryPattern);
        requiredNotSet.remove(RequiredFields.co);
        return this;
    }

    /**
     * test issuer.
     *
     * @param is issuer
     * @return builder
     */
    public DccTestBuilder certificateIssuer(String is) {
        testObject.set("is", jsonNodeFactory.textNode(is));
        assertNotNullMax("is", is, 50);
        requiredNotSet.remove(RequiredFields.is);
        return this;
    }

    /**
     * testing centre.
     *
     * @param tc testing centre
     * @return builder
     */
    public DccTestBuilder testingCentre(String tc) {
        testObject.set("tc", jsonNodeFactory.textNode(tc));
        assertNotNullMax("tc", tc, 50);
        requiredNotSet.remove(RequiredFields.tc);
        return this;
    }

    /**
     * date time of sample collection.
     *
     * @param dateTime sc
     * @return builder
     */
    public DccTestBuilder sampleCollection(LocalDateTime dateTime) {
        testObject.set("sc", jsonNodeFactory.textNode(toIsoO8601(dateTime)));
        requiredNotSet.remove(RequiredFields.sc);
        return this;
    }

    private String toIsoO8601(LocalDateTime dateTime) {
        return dateTime.atZone(ZoneOffset.UTC).format(dateFormat);
    }

    private void assertNotNullMax(String description, String value, int maxLenght) {
        if (value == null) {
            throw new IllegalArgumentException("field " + description + " must not be null");
        }
        if (maxLenght > 0 && value.length() > maxLenght) {
            throw new IllegalArgumentException("field " + description + " has max length "
                + maxLenght + " but was: " + value.length());
        }
    }

    private void assertNotNullMaxPattern(String description, String value, int maxLenght, Pattern pattern) {
        assertNotNullMax(description, value, maxLenght);
        Matcher matcher = pattern.matcher(value);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("field: " + description + "value: "
                + value + " do not match pattern: " + pattern);
        }
    }

}
