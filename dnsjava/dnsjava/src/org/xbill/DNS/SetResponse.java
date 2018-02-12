// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.util.*;

/**
 * The Response from a query to Cache.lookupRecords() or Zone.findRecords()
 * @see Cache
 * @see Zone
 *
 * @author Brian Wellington
 */

public class SetResponse {

	private static enum Type {
		/**
		 * The Cache contains no information about the requested name/type
		 */
		UNKNOWN,

		/**
		 * The Zone does not contain the requested name, or the Cache has
		 * determined that the name does not exist.
		 */
		NXDOMAIN,

		/**
		 * The Zone contains the name, but no data of the requested type,
		 * or the Cache has determined that the name exists and has no data
		 * of the requested type.
		 */
		NXRRSET,

		/**
		 * A delegation enclosing the requested name was found.
		 */
		DELEGATION,

		/**
		 * The Cache/Zone found a CNAME when looking for the name.
		 * @see CNAMERecord
		 */
		CNAME,

		/**
		 * The Cache/Zone found a DNAME when looking for the name.
		 * @see DNAMERecord
		 */
		DNAME,

		/**
		 * The Cache/Zone has successfully answered the question for the
		 * requested name/type/class.
		 */
		SUCCESSFUL
	}


static final SetResponse unknown = new SetResponse(Type.UNKNOWN, null);
static final SetResponse nxdomain = new SetResponse(Type.NXDOMAIN, null);
static final SetResponse nxrrset = new SetResponse(Type.NXRRSET, null);

static final SetResponse delegation(RRset rrset) {
	return new SetResponse(Type.DELEGATION, rrset);
}

static final SetResponse cname(RRset rrset) {
	final CNAMERecord r = (CNAMERecord) rrset.first();
	return new SetResponse(Type.CNAME, r);
}

static final SetResponse dname(RRset rrset) {
	final DNAMERecord r = (DNAMERecord) rrset.first();
	return new SetResponse(Type.DNAME, r);
}

static final SetResponse success() {
	Collection<RRset> data = new ArrayList<RRset>();
	return new SetResponse(Type.SUCCESSFUL, data);
}

static final SetResponse success(RRset rrset) {
	Collection<RRset> data = new ArrayList<RRset>();
	data.add(rrset);
	return new SetResponse(Type.SUCCESSFUL, data);
}

static final SetResponse success(Collection<? extends RRset> sets) {
	return new SetResponse(Type.SUCCESSFUL, sets);
}

static final SetResponse success(RRset... sets) {
	Collection<RRset> data = new ArrayList<RRset>();
	for (RRset rrs : sets) {
		data.add(rrs);
	}
	return new SetResponse(Type.SUCCESSFUL, data);
}


private final Type type;
/*
 * DELEGATION: RRset
 * CNAME: 	   CNAMERecord
 * DNAME:      DNAMERecord
 * SUCCESSFUL: List<RRset>
 */
private final Object data;

private SetResponse(Type type, Object data) {
	this.type = type;
	this.data = data;
}

void
addRRset(RRset rrset) {
	@SuppressWarnings("unchecked")
	List<Object> l = (List<Object>) data;
	l.add(rrset);
}

/** Is the answer to the query unknown? */
public boolean
isUnknown() {
	return (type == Type.UNKNOWN);
}

/** Is the answer to the query that the name does not exist? */
public boolean
isNXDOMAIN() {
	return (type == Type.NXDOMAIN);
}

/** Is the answer to the query that the name exists, but the type does not? */
public boolean
isNXRRSET() {
	return (type == Type.NXRRSET);
}

/** Is the result of the lookup that the name is below a delegation? */
public boolean
isDelegation() {
	return (type == Type.DELEGATION);
}

/** Is the result of the lookup a CNAME? */
public boolean
isCNAME() {
	return (type == Type.CNAME);
}

/** Is the result of the lookup a DNAME? */
public boolean
isDNAME() {
	return (type == Type.DNAME);
}

/** Was the query successful? */
public boolean
isSuccessful() {
	return (type == Type.SUCCESSFUL);
}

/** If the query was successful, return the answers */
public RRset []
answers() {
	if (type != Type.SUCCESSFUL)
		return null;
	final List<?> l = (List<?>) data;
	return l.toArray(new RRset[l.size()]);
}

/**
 * If the query encountered a CNAME, return it.
 */
public CNAMERecord
getCNAME() {
	return (CNAMERecord)data;
}

/**
 * If the query encountered a DNAME, return it.
 */
public DNAMERecord
getDNAME() {
	return (DNAMERecord)data;
}

/**
 * If the query hit a delegation point, return the NS set.
 */
public RRset
getNS() {
	return (RRset)data;
}

/** Prints the value of the SetResponse */
@Override
public String
toString() {
	switch (type) {
		case UNKNOWN:		return "unknown";
		case NXDOMAIN:		return "NXDOMAIN";
		case NXRRSET:		return "NXRRSET";
		case DELEGATION:	return "delegation: " + data;
		case CNAME:		return "CNAME: " + data;
		case DNAME:		return "DNAME: " + data;
		case SUCCESSFUL:	return "successful";
		default:		throw new IllegalStateException();
	}
}

}
