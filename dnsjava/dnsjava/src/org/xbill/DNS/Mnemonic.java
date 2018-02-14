// Copyright (c) 2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.util.HashMap;
import java.util.Locale;

/**
 * A utility class for converting between numeric codes and mnemonics
 * for those codes.  Mnemonics are case insensitive.
 *
 * @author Brian Wellington
 */

class Mnemonic {

public static enum Wordcase {
	SENSITIVE,
	UPPER,
	LOWER
}

/* Strings are case-sensitive. */
static final Wordcase CASE_SENSITIVE = Wordcase.SENSITIVE;

/* Strings will be stored/searched for in uppercase. */
static final Wordcase CASE_UPPER = Wordcase.UPPER;

/* Strings will be stored/searched for in lowercase. */
static final Wordcase CASE_LOWER = Wordcase.LOWER;

private final HashMap<String, Integer> strings;
private final HashMap<Integer, String> values;
private final String description;
private final Wordcase wordcase;
private String prefix;
private int max;
private boolean numericok;

/**
 * Creates a new Mnemonic table.
 * @param description A short description of the mnemonic to use when
 * @param wordcase Whether to convert strings into uppercase, lowercase,
 * or leave them unchanged.
 * throwing exceptions.
 */
public
Mnemonic(String description, Wordcase wordcase) {
	this.description = description;
	this.wordcase = wordcase;
	strings = new HashMap<String, Integer>();
	values = new HashMap<Integer, String>();
	max = Integer.MAX_VALUE;
}

/** Sets the maximum numeric value */
public void
setMaximum(int max) {
	this.max = max;
}

/**
 * Sets the prefix to use when converting to and from values that don't
 * have mnemonics.
 */
public void
setPrefix(String prefix) {
	this.prefix = sanitize(prefix);
}

/**
 * Sets whether numeric values stored in strings are acceptable.
 */
public void
setNumericAllowed(boolean numeric) {
	this.numericok = numeric;
}

/**
 * Checks that a numeric value is within the range [0..max]
 */
public void
check(int val) {
	if (val < 0 || val > max) {
		throw new IllegalArgumentException(description + " " + val +
						   "is out of range");
	}
}

/* Converts a String to the correct case. */
private String
sanitize(String str) {
	if (wordcase == Wordcase.UPPER)
		str = str.toUpperCase(Locale.ENGLISH);
	else if (wordcase == Wordcase.LOWER)
		str = str.toLowerCase(Locale.ENGLISH);
	return str;
}

private int
parseNumeric(String s) {
	try {
		final int val = Integer.parseInt(s);
		if (val >= 0 && val <= max)
			return val;
	}
	catch (NumberFormatException e) {
	}
	return -1;
}

/**
 * Defines the text representation of a numeric value. Optionally also
 * defines one or more additional text representations of the same numeric
 * value.  These will be used by getValue(), but not getText().
 * @param val The numeric value
 * @param string The text string
 * @param aliases Additional text strings
 */
public void
add(int val, String str, String... aliases) {
	check(val);
	final Integer value = Integer.valueOf(val);
	str = sanitize(str);
	strings.put(str, value);
	values.put(value, str);
	for (String a : aliases) {
		a = sanitize(a);
		strings.put(a, value);
	}
}

/**
 * Copies all mnemonics from one table into another.
 * @param val The numeric value
 * @param string The text string
 * @throws IllegalArgumentException The wordcases of the Mnemonics do not
 * match.
 */
public void
addAll(Mnemonic source) {
	if (wordcase != source.wordcase)
		throw new IllegalArgumentException(source.description +
						   ": wordcases do not match");
	strings.putAll(source.strings);
	values.putAll(source.values);
}

/**
 * Gets the text mnemonic corresponding to a numeric value.
 * @param val The numeric value
 * @return The corresponding text mnemonic.
 */
public String
getText(int val) {
	check(val);
	String str = values.get(Integer.valueOf(val));
	if (str == null) {
		str = Integer.toString(val);
		if (prefix != null)
			str = prefix + str;
	}
	return str;
}

/**
 * Gets the numeric value corresponding to a text mnemonic.
 * @param str The text mnemonic
 * @return The corresponding numeric value, or -1 if there is none
 */
public int
getValue(String str) {
	str = sanitize(str);
	final Integer value = strings.get(str);
	int val;
	if (value != null) {
		val = value.intValue();
	} else {
		if (prefix != null && str.startsWith(prefix)) {
			val = parseNumeric(str.substring(prefix.length()));
		} else {
			val = -1;
		}
		if (val < 0 && numericok) {
			val = parseNumeric(str);
		}
	}
	return val;
}

}
