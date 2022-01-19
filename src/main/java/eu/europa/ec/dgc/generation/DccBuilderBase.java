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

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.EnumSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Abstract builder for all certificate types.
 *
 * @param <T> the concrete builder
 */
public abstract class DccBuilderBase<T extends DccBuilderBase<T>> {

    protected JsonNodeFactory jsonNodeFactory;
    protected ObjectNode dccObject;
    protected ObjectNode nameObject;

    private static final Pattern countryPattern = Pattern.compile("[A-Z]{1,10}");
    private static final Pattern standardNamePattern = Pattern.compile("^[A-Z<]*$");

    private final DateTimeFormatter dateFormat;
    private final DateTimeFormatter dayDateFormat;

    private final EnumSet<RequiredFieldsBase> requiredNotSet = EnumSet.allOf(RequiredFieldsBase.class);

    /**
     * constructor.
     */
    public DccBuilderBase() {
        dateFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX");
        dayDateFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd");

        jsonNodeFactory = JsonNodeFactory.instance;
        dccObject = jsonNodeFactory.objectNode();
        nameObject = jsonNodeFactory.objectNode();

        dccObject.set("ver", jsonNodeFactory.textNode("1.0.0"));
        dccObject.set("nam", nameObject);
    }

    public abstract T getThis();

    public abstract ObjectNode getValueHolder();

    /**
     * family name field.
     *
     * @param fn family name
     * @return builder
     */
    public T fn(String fn) {
        assertNotNullMax("fn", fn, 80);
        nameObject.set("fn", jsonNodeFactory.textNode(fn));
        return getThis();
    }

    /**
     * given name.
     *
     * @param gn given name
     * @return builder
     */
    public T gn(String gn) {
        assertNotNullMax("gn", gn, 80);
        nameObject.set("gn", jsonNodeFactory.textNode(gn));
        return getThis();
    }

    /**
     * standardized family name.
     *
     * @param fnt standardized family name
     * @return builder
     */
    public T fnt(String fnt) {
        assertNotNullMaxPattern("fnt", fnt, 80, standardNamePattern);
        requiredNotSet.remove(RequiredFieldsBase.fnt);
        nameObject.set("fnt", jsonNodeFactory.textNode(fnt));
        return getThis();
    }

    /**
     * standarized given name.
     *
     * @param gnt standardized given name
     * @return builder
     */
    public T gnt(String gnt) {
        assertNotNullMaxPattern("gnt", gnt, 80, standardNamePattern);
        nameObject.set("gnt", jsonNodeFactory.textNode(gnt));
        return getThis();
    }

    protected void validate() {
        if (!requiredNotSet.isEmpty()) {
            throw new IllegalStateException("not all required fields set " + requiredNotSet);
        }
    }

    /**
     * buidl json string.
     *
     * @return json string
     */
    public String toJsonString() {
        validate();
        return dccObject.toString();
    }

    /**
     * date of birth in iso format.
     *
     * @param birthday dob
     * @return builder
     */
    public T dob(LocalDate birthday) {
        dccObject.set("dob", jsonNodeFactory.textNode(toIsoDate(birthday)));
        requiredNotSet.remove(RequiredFieldsBase.dob);
        return getThis();
    }

    /**
     * country of test.
     *
     * @param co co
     * @return builder
     */
    public T country(String co) {
        assertNotNullMaxPattern("co", co, 0, countryPattern);
        getValueHolder().set("co", jsonNodeFactory.textNode(co));
        requiredNotSet.remove(RequiredFieldsBase.co);
        return getThis();
    }

    /**
     * test issuer.
     *
     * @param is issuer
     * @return builder
     */
    public T certificateIssuer(String is) {
        assertNotNullMax("is", is, 80);
        getValueHolder().set("is", jsonNodeFactory.textNode(is));
        requiredNotSet.remove(RequiredFieldsBase.is);
        return getThis();
    }

    /**
     * certificate identifier.
     *
     * @param dgci certificate identifier
     * @return builder
     */
    public T dgci(String dgci) {
        assertNotNullMax("ci", dgci, 80);
        getValueHolder().set("ci", jsonNodeFactory.textNode(dgci));
        requiredNotSet.remove(RequiredFieldsBase.ci);
        return getThis();
    }

    protected String toIsoO8601(LocalDateTime dateTime) {
        return dateTime.atZone(ZoneOffset.UTC).format(dateFormat);
    }

    protected String toIsoDate(LocalDate date) {
        return date.format(dayDateFormat);
    }

    protected void assertNotNullMax(String description, String value, int maxLenght) {
        if (value == null) {
            throw new IllegalArgumentException("field " + description + " must not be null");
        }
        if (maxLenght > 0 && value.length() > maxLenght) {
            throw new IllegalArgumentException("field " + description + " has max length "
                + maxLenght + " but was: " + value.length());
        }
    }

    protected void assertNotNullMaxPattern(String description, String value, int maxLength, Pattern pattern) {
        assertNotNullMax(description, value, maxLength);
        Matcher matcher = pattern.matcher(value);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("field: " + description + "value: "
                + value + " do not match pattern: " + pattern);
        }
    }

    private enum RequiredFieldsBase {
        dob,
        fnt,
        co,
        is,
        ci
    }
}
