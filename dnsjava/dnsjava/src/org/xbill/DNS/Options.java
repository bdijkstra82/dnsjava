// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.util.*;

/**
 * Boolean options:<BR>
 * bindttl - Print TTLs in BIND format<BR>
 * multiline - Print records in multiline format<BR>
 * noprintin - Don't print the class of a record if it's IN<BR>
 * verbose - Turn on general debugging statements<BR>
 * verbosemsg - Print all messages sent or received by SimpleResolver<BR>
 * verbosecompression - Print messages related to name compression<BR>
 * verbosesec - Print messages related to signature verification<BR>
 * verbosecache - Print messages related to cache lookups<BR>
 * <BR>
 * Valued options:<BR>
 * tsigfudge=n - Sets the default TSIG fudge value (in seconds)<BR>
 * sig0validity=n - Sets the default SIG(0) validity period (in seconds)<BR>
 *
 * @author Brian Wellington
 */

public final class Options {

	/* internal functions should use this */
	static enum Standard {
		bindttl,
		multiline,
		noprintin,
		verbose,
		verbosemsg,
		verbosecompression,
		verbosesec,
		verbosecache,
		tsigfudge,
		@Deprecated
		sig0validity
	}

private static Map<String, Object> table;

static {
	try {
		refresh();
	}
	catch (SecurityException e) {
	}
}

private
Options() {}

public static void
refresh() {
	final String s = System.getProperty("dnsjava.options");
	if (s != null) {
		final StringTokenizer st = new StringTokenizer(s, ",");
		while (st.hasMoreTokens()) {
			String token = st.nextToken();
			int index = token.indexOf('=');
			if (index == -1)
				set(token);
			else {
				String option = token.substring(0, index);
				String value = token.substring(index + 1);
				set(option, value);
			}
		}
	}
}

/** Clears all defined options */
public static void
clear() {
	table = null;
}

private static String key(Standard option) {
	return option.toString();
}

private static String key(String option) {
	return option.toLowerCase(Locale.ENGLISH);
}

private static void put(String k, Object v) {
	if (table == null)
		table = new HashMap<String, Object>();
	table.put(k, v);
}

/** Sets an option to "true" */
public static void
set(String option) {
	put(key(option), Boolean.TRUE);
}

public static void
set(Standard option) {
	put(key(option), Boolean.TRUE);
}

/** Sets an option to the the supplied value */
public static void
set(String option, String value) {
	put(key(option), value.toLowerCase(Locale.ENGLISH));
}

/** Removes an option */
public static void
unset(String option) {
	if (table != null)
		table.remove(key(option));
}

private static Object getRef(String k) {
	if (table == null)
		return null;
	return table.get(k);
}

private static boolean getBoolean(String k) {
	return getRef(k) != null;
}

/** Checks if an option is defined */
public static boolean
check(String option) {
	return getBoolean(key(option));
}

static boolean
check(Standard option) {
	return getBoolean(key(option));
}

private static String getString(String k) {
	final Object v = getRef(k);
	return v == null ? null : v.toString();
}

/** Returns the value of an option */
public static String
value(String option) {
	return getString(key(option));
}

private static int
getInt(String k) {
	final Object v = getRef(k);
	int val = -1;
	if (v != null) {
		if (v instanceof Number)
			val = ((Number)v).intValue();
		else {
			try {
				val = Integer.parseInt(v.toString());
			}
			catch (NumberFormatException e) {
			}
			if (val > 0)
				put(k, Integer.valueOf(val));
		}
		if (val <= 0)
			val = -1;
	}
	return val;
}

/**
 * Returns the value of an option as an integer, or -1 if not defined.
 */
public static int
intValue(String option) {
	return getInt(key(option));
}

static int
intValue(Standard option) {
	return getInt(key(option));
}

}
