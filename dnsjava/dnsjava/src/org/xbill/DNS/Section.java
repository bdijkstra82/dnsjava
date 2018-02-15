// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * Constants and functions relating to DNS message sections
 *
 * @author Brian Wellington
 */

public enum Section {

	qd("QUESTIONS",			"ZONE"),
	an("ANSWERS",			"PREREQUISITES"),
	au("AUTHORITY RECORDS", "UPDATE RECORDS"),
	ad("ADDITIONAL RECORDS");

	public static final Section
		QUESTION   = qd,
		ANSWER     = an,
		AUTHORITY  = au,
		ADDITIONAL = ad;

	public static final Section
		ZONE   = qd,
		PREREQ = an,
		UPDATE = au;

/** The question (first) section */
public static final int QUESTION_INDEX	= 0;

/** The answer (second) section */
public static final int ANSWER_INDEX	= 1;

/** The authority (third) section */
public static final int AUTHORITY_INDEX	= 2;

/** The additional (fourth) section */
public static final int ADDITIONAL_INDEX = 3;

/* Aliases for dynamic update */
/** The zone (first) section of a dynamic update message */
public static final int ZONE_INDEX		= 0;

/** The prerequisite (second) section of a dynamic update message */
public static final int PREREQ_INDEX	= 1;

/** The update (third) section of a dynamic update message */
public static final int UPDATE_INDEX	= 2;

private final String longString, updString;

private
Section(String longString, String updString) {
	this.longString = longString;
	this.updString = updString;
}
private
Section(String longString) {
	this(longString, longString);
}

/** Converts a numeric Section into a full description String */
public String
longString() {
	return longString;
}

/**
 * Converts a numeric Section into a full description String for an update
 * Message.
 */
public String
updString() {
	return updString;
}

/** Converts a String representation of a Section into its numeric value */
public static Section
value(String s) {
	Section r = null;
	for (Section i : values())
		if (i.name().equalsIgnoreCase(s)) {
			r = i;
			break;
		}
	return r;
}
public static Section valueOf(int s) {
	return values()[s];
}

}
