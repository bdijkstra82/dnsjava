// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import java.util.Map.Entry;

/**
 * A DNS Zone.  This encapsulates all data related to a Zone, and provides
 * convenient lookup methods.
 *
 * @author Brian Wellington
 */

public class Zone implements Serializable {

private static final long serialVersionUID = -9220510891189510942L;

/** A primary zone */
public static final int PRIMARY = 1;

/** A secondary zone */
public static final int SECONDARY = 2;

private Map<Name, Object> data;//XXX values are RRset or List<RRset>
private Name origin;
private Object originNode;
private int dclass = DClass.IN;
private RRset NS;
private SOARecord SOA;
private boolean hasWild;

class ZoneIterator implements Iterator<RRset> {
	private final Iterator<Entry<Name, Object>> zentries;
	private RRset [] current;
	private int count;
	private boolean wantLastSOA;

	ZoneIterator(boolean axfr) {
		synchronized (Zone.this) {
			zentries = data.entrySet().iterator();
		}
		wantLastSOA = axfr;
		final RRset [] sets = allRRsets(originNode);
		current = new RRset[sets.length];
		for (int i = 0, j = 2; i < sets.length; i++) {
			int type = sets[i].getType();
			if (type == Type.SOA)
				current[0] = sets[i];
			else if (type == Type.NS)
				current[1] = sets[i];
			else
				current[j++] = sets[i];
		}
	}

	public boolean
	hasNext() {
		return (current != null || wantLastSOA);
	}

	public RRset
	next() {
		if (!hasNext()) {
			throw new NoSuchElementException();
		}
		if (current == null) {
			wantLastSOA = false;
			return oneRRset(originNode, Type.SOA);
		}
		final RRset set = current[count++];
		if (count == current.length) {
			current = null;
			while (zentries.hasNext()) {
				Entry<Name, Object> entry = zentries.next();
				if (entry.getKey().equals(origin))
					continue;
				RRset [] sets = allRRsets(entry.getValue());
				if (sets.length == 0)
					continue;
				current = sets;
				count = 0;
				break;
			}
		}
		return set;
	}

	public void
	remove() {
		throw new UnsupportedOperationException();
	}
}

private void
validate() throws IOException {
	originNode = exactName(origin);
	if (originNode == null)
		throw new IOException(origin + ": no data specified");

	final RRset rrset = oneRRset(originNode, Type.SOA);
	if (rrset == null || rrset.size() != 1)
		throw new IOException(origin +
				      ": exactly 1 SOA must be specified");
	final Iterator<Record> it = rrset.rrs();
	SOA = (SOARecord) it.next();

	NS = oneRRset(originNode, Type.NS);
	if (NS == null)
		throw new IOException(origin + ": no NS set specified");
}

private final void
maybeAddRecord(Record record) throws IOException {
	final int rtype = record.getType();
	final Name name = record.getName();

	if (rtype == Type.SOA && !name.equals(origin)) {
		throw new IOException("SOA owner " + name +
				      " does not match zone origin " +
				      origin);
	}
	if (name.subdomain(origin))
		addRecord(record);
}

/**
 * Creates a Zone from the records in the specified master file.
 * @param zone The name of the zone.
 * @param file The master file to read from.
 * @see Master
 */
public
Zone(Name zone, String file) throws IOException {
	data = new TreeMap<Name, Object>();

	if (zone == null)
		throw new IllegalArgumentException("no zone name specified");
	final Master m = new Master(file, zone);
	Record record;

	origin = zone;
	while ((record = m.nextRecord()) != null)
		maybeAddRecord(record);
	validate();
}

/**
 * Creates a Zone from an array of records.
 * @param zone The name of the zone.
 * @param records The records to add to the zone.
 * @see Master
 */
public
Zone(Name zone, Record [] records) throws IOException {
	data = new TreeMap<Name, Object>();

	if (zone == null)
		throw new IllegalArgumentException("no zone name specified");
	origin = zone;
	for (int i = 0; i < records.length; i++)
		maybeAddRecord(records[i]);
	validate();
}

private void
fromXFR(ZoneTransferIn xfrin) throws IOException, ZoneTransferException {
	data = new TreeMap<Name, Object>();

	origin = xfrin.getName();
	xfrin.run();
	if (!xfrin.isAXFR())
		throw new IllegalArgumentException("zones can only be " +
						   "created from AXFRs");
	final List<Record> records = xfrin.getAXFR();
	for (Iterator<Record> it = records.iterator(); it.hasNext(); ) {
		Record record = it.next();
		maybeAddRecord(record);
	}
	validate();
}

/**
 * Creates a Zone by doing the specified zone transfer.
 * @param xfrin The incoming zone transfer to execute.
 * @see ZoneTransferIn
 */
public
Zone(ZoneTransferIn xfrin) throws IOException, ZoneTransferException {
	fromXFR(xfrin);
}

/**
 * Creates a Zone by performing a zone transfer to the specified host.
 * @see ZoneTransferIn
 */
public
Zone(Name zone, int dclass, String remote)
throws IOException, ZoneTransferException
{
	final ZoneTransferIn xfrin = ZoneTransferIn.newAXFR(zone, remote, null);
	xfrin.setDClass(dclass);
	fromXFR(xfrin);
}

/** Returns the Zone's origin */
public Name
getOrigin() {
	return origin;
}

/** Returns the Zone origin's NS records */
public RRset
getNS() {
	return NS;
}

/** Returns the Zone's SOA record */
public SOARecord
getSOA() {
	return SOA;
}

/** Returns the Zone's class */
public int
getDClass() {
	return dclass;
}

private synchronized Object
exactName(Name name) {
	return data.get(name);
}

private synchronized static RRset []
allRRsets(Object types) {
	final RRset[] r;
	if (types instanceof List) {
		final List<?> typelist = (List<?>) types;
		r = typelist.toArray(new RRset[typelist.size()]);
	} else {
		final RRset set = (RRset) types;
		r = new RRset [] {set};
	}
	return r;
}

private synchronized static RRset
oneRRset(Object types, int type) {
	if (type == Type.ANY)
		throw new IllegalArgumentException("oneRRset(ANY)");
	if (types instanceof List) {
		final List<?> list = (List<?>) types;
		for (int i = 0; i < list.size(); i++) {
			RRset set = (RRset) list.get(i);
			if (set.getType() == type)
				return set;
		}
	} else {
		final RRset set = (RRset) types;
		if (set.getType() == type)
			return set;
	}
	return null;
}

private synchronized RRset
findRRset(Name name, int type) {
	final Object types = exactName(name);
	if (types == null)
		return null;
	return oneRRset(types, type);
}

private synchronized void
addRRset(Name name, RRset rrset) {
	if (!hasWild && name.isWild())
		hasWild = true;
	final Object types = data.get(name);
	if (types == null) {
		data.put(name, rrset);
		return;
	}
	final int rtype = rrset.getType();
	if (types instanceof List) {
		@SuppressWarnings("unchecked")
		final List<RRset> list = (List<RRset>) types;
		for (int i = 0; i < list.size(); i++) {
			RRset set = list.get(i);
			if (set.getType() == rtype) {
				list.set(i, rrset);
				return;
			}
		}
		list.add(rrset);
	} else {
		final RRset set = (RRset) types;
		if (set.getType() == rtype)
			data.put(name, rrset);
		else {
			final LinkedList<RRset> list = new LinkedList<RRset>();
			list.add(set);
			list.add(rrset);
			data.put(name, list);
		}
	}
}

private synchronized void
removeRRset(Name name, int type) {
	final Object types = data.get(name);
	if (types == null) {
		return;
	}
	if (types instanceof List) {
		@SuppressWarnings("unchecked")
		final List<RRset> list = (List<RRset>) types;
		for (int i = 0; i < list.size(); i++) {
			RRset set = list.get(i);
			if (set.getType() == type) {
				list.remove(i);
				if (list.size() == 0)
					data.remove(name);
				return;
			}
		}
	} else {
		final RRset set = (RRset) types;
		if (set.getType() != type)
			return;
		data.remove(name);
	}
}

private synchronized SetResponse
lookup(Name name, int type) {
	final int labels;
	final int olabels;
	int tlabels;
	RRset rrset;
	Name tname;
	Object types;
	final SetResponse sr;

	if (!name.subdomain(origin))
		return SetResponse.nxdomain;

	labels = name.labels();
	olabels = origin.labels();

	for (tlabels = olabels; tlabels <= labels; tlabels++) {
		boolean isOrigin = (tlabels == olabels);
		boolean isExact = (tlabels == labels);

		if (isOrigin)
			tname = origin;
		else if (isExact)
			tname = name;
		else
			tname = new Name(name, labels - tlabels);

		types = exactName(tname);
		if (types == null)
			continue;

		/* If this is a delegation, return that. */
		if (!isOrigin) {
			final RRset ns = oneRRset(types, Type.NS);
			if (ns != null)
				return SetResponse.delegation(ns);
		}

		/* If this is an ANY lookup, return everything. */
		if (isExact && type == Type.ANY) {
			sr = SetResponse.success(allRRsets(types));
			return sr;
		}

		/*
		 * If this is the name, look for the actual type or a CNAME.
		 * Otherwise, look for a DNAME.
		 */
		if (isExact) {
			rrset = oneRRset(types, type);
			if (rrset != null) {
				sr = SetResponse.success(rrset);
				return sr;
			}
			rrset = oneRRset(types, Type.CNAME);
			if (rrset != null)
				return SetResponse.cname(rrset);
		} else {
			rrset = oneRRset(types, Type.DNAME);
			if (rrset != null)
				return SetResponse.dname(rrset);
		}

		/* We found the name, but not the type. */
		if (isExact)
			return SetResponse.nxrrset;
	}

	if (hasWild) {
		for (int i = 0; i < labels - olabels; i++) {
			tname = name.wild(i + 1);

			types = exactName(tname);
			if (types == null)
				continue;

			rrset = oneRRset(types, type);
			if (rrset != null) {
				sr = SetResponse.success();
				sr.addRRset(rrset);
				return sr;
			}
		}
	}

	return SetResponse.nxdomain;
}

/**
 * Looks up Records in the Zone.  This follows CNAMEs and wildcards.
 * @param name The name to look up
 * @param type The type to look up
 * @return A SetResponse object
 * @see SetResponse
 */
public SetResponse
findRecords(Name name, int type) {
	return lookup(name, type);
}

/**
 * Looks up Records in the zone, finding exact matches only.
 * @param name The name to look up
 * @param type The type to look up
 * @return The matching RRset
 * @see RRset
 */
public RRset
findExactMatch(Name name, int type) {
	final Object types = exactName(name);
	if (types == null)
		return null;
	return oneRRset(types, type);
}

/**
 * Adds an RRset to the Zone
 * @param rrset The RRset to be added
 * @see RRset
 */
public void
addRRset(RRset rrset) {
	final Name name = rrset.getName();
	addRRset(name, rrset);
}

/**
 * Adds a Record to the Zone
 * @param r The record to be added
 * @see Record
 */
public void
addRecord(Record r) {
	final Name name = r.getName();
	final int rtype = r.getRRsetType();
	synchronized (this) {
		RRset rrset = findRRset(name, rtype);
		if (rrset == null) {
			rrset = new RRset(r);
			addRRset(name, rrset);
		} else {
			rrset.addRR(r);
		}
	}
}

/**
 * Removes a record from the Zone
 * @param r The record to be removed
 * @see Record
 */
public void
removeRecord(Record r) {
	final Name name = r.getName();
	final int rtype = r.getRRsetType();
	synchronized (this) {
		RRset rrset = findRRset(name, rtype);
		if (rrset == null)
			return;
		if (rrset.size() == 1 && rrset.first().equals(r))
			removeRRset(name, rtype);
		else
			rrset.deleteRR(r);
	}
}

/**
 * Returns an Iterator over the RRsets in the zone.
 */
public Iterator<RRset>
iterator() {
	return new ZoneIterator(false);
}

/**
 * Returns an Iterator over the RRsets in the zone that can be used to
 * construct an AXFR response.  This is identical to {@link #iterator} except
 * that the SOA is returned at the end as well as the beginning.
 */
public Iterator<RRset>
AXFR() {
	return new ZoneIterator(true);
}

private static void
nodeToString(StringBuilder sb, Object node) {
	final RRset [] sets = allRRsets(node);
	for (int i = 0; i < sets.length; i++) {
		final RRset rrset = sets[i];
		Iterator<Record> it = rrset.rrs();
		while (it.hasNext())
			sb.append(it.next() + "\n");
		it = rrset.sigs();
		while (it.hasNext())
			sb.append(it.next() + "\n");
	}
}

/**
 * Returns the contents of the Zone in master file format.
 */
public synchronized String
toMasterFile() {
	final Iterator<Entry<Name, Object>> zentries = data.entrySet().iterator();
	final StringBuilder sb = new StringBuilder();
	nodeToString(sb, originNode);
	while (zentries.hasNext()) {
		Entry<Name, Object> entry = zentries.next();
		if (!origin.equals(entry.getKey()))
			nodeToString(sb, entry.getValue());
	}
	return sb.toString();
}

/**
 * Returns the contents of the Zone as a string (in master file format).
 */
@Override
public String
toString() {
	return toMasterFile();
}

}
