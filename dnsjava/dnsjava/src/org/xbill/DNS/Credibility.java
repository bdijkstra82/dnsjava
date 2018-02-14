// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * Constants relating to the credibility of cached data, which is based on
 * the data's source.  The constants NORMAL and ANY should be used by most
 * callers.
 * @see Cache
 * @see Section
 *
 * @author Brian Wellington
 */

public enum Credibility {

/** A hint or cache file on disk. */
HINT,

/** Data not required to be credible. */
ANY,

/** The additional section of a response. */
GLUE,

/** Credible data. */
NORMAL,

/** More credible data. */
AUTH,

/** A zone. */
ZONE;


/** The additional section of a response. */
public static final Credibility ADDITIONAL			= ANY;

/** The authority section of a nonauthoritative response. */
public static final Credibility NONAUTH_AUTHORITY	= NORMAL;

/** The answer section of a nonauthoritative response. */
public static final Credibility NONAUTH_ANSWER		= NORMAL;

/** The authority section of an authoritative response. */
public static final Credibility AUTH_AUTHORITY		= AUTH;

/** The answer section of a authoritative response. */
public static final Credibility AUTH_ANSWER			= AUTH;

}
