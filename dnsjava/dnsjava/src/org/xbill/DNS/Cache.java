// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import java.util.*;


/**
 * A cache of DNS records.  The cache obeys TTLs, so items are purged after
 * their validity period is complete.  Negative answers are cached, to
 * avoid repeated failed DNS queries.  The credibility of each RRset is
 * maintained, so that more credible records replace less credible records,
 * and lookups can specify the minimum credibility of data they are requesting.
 * @see RRset
 * @see Credibility
 *
 * @author Brian Wellington
 */

public class Cache {

private interface Element {
	public boolean expired();
	public int compareCredibility(Credibility cred);
	public int getType();
}

private static long
limitExpire(long ttl, long maxttl) {
	if (maxttl >= 0L && maxttl < ttl)
		ttl = maxttl;
	long expire = (System.currentTimeMillis() / 1000L) + ttl;
	if (expire < 0L)
		expire = Long.MAX_VALUE;
	return expire;
}

private static class CacheRRset extends RRset implements Element {
	private static final long serialVersionUID = 5971755205903597024L;

	final Credibility credibility;
	final long expire;

	public
	CacheRRset(Record rec, Credibility cred, long maxttl) {
		super();
		this.credibility = cred;
		this.expire = limitExpire(rec.getTTL(), maxttl);
		addRR(rec);
	}

	public
	CacheRRset(RRset rrset, Credibility cred, long maxttl) {
		super(rrset);
		this.credibility = cred;
		this.expire = limitExpire(rrset.getTTL(), maxttl);
	}

	public final boolean
	expired() {
		final long now = System.currentTimeMillis() / 1000L;
		return (now >= expire);
	}

	public final int
	compareCredibility(Credibility cred) {
		return credibility.compareTo(cred);
	}

	@Override
	public String
	toString() {
		final StringBuilder sb = new StringBuilder();
		sb.append(super.toString());
		sb.append(" cl = ");
		sb.append(credibility);
		return sb.toString();
	}
}

/* Type value used for NXDOMAIN negative elements */
private static final int Type_NXDOMAIN = 0;

private static class NegativeElement implements Element {
	final int type;
	final Name name;
	final Credibility credibility;
	final long expire;

	public
	NegativeElement(Name name, int type, SOARecord soa, Credibility cred,
			long maxttl)
	{
		this.name = name;
		this.type = type;
		this.credibility = cred;
		final long cttl = (soa != null) ? soa.getMinimum() : 0L;
		this.expire = limitExpire(cttl, maxttl);
	}

	public int
	getType() {
		return type;
	}

	public final boolean
	expired() {
		final long now = System.currentTimeMillis() / 1000L;
		return (now >= expire);
	}

	public final int
	compareCredibility(Credibility cred) {
		return credibility.compareTo(cred);
	}

	@Override
	public String
	toString() {
		final StringBuilder sb = new StringBuilder();
		if (type == Type_NXDOMAIN)
			sb.append("NXDOMAIN ").append(name);
		else
			sb.append("NXRRSET ").append(name).append(' ').append(Type.string(type));
		sb.append(" cl = ");
		sb.append(credibility.ordinal());
		return sb.toString();
	}
}

//XXX value is either Element or List<Element>
private static class CacheMap extends LinkedHashMap<Name, Object> {
	private int maxsize = -1;

	CacheMap(int maxsize) {
		super(16, 0.75f, true);
		this.maxsize = maxsize;
	}

	int
	getMaxSize() {
		return maxsize;
	}

	void
	setMaxSize(int maxsize) {
		/*
		 * Note that this doesn't shrink the size of the map if
		 * the maximum size is lowered, but it should shrink as
		 * entries expire.
		 */
		this.maxsize = maxsize;
	}

	@Override
	protected boolean removeEldestEntry(Map.Entry<Name, Object> eldest) {
		return maxsize >= 0 && size() > maxsize;
	}
}

private final CacheMap data;
private int maxncache = -1;
private int maxcache = -1;
private final int dclass;

private static final int defaultMaxEntries = 50000;

/**
 * Creates an empty Cache
 *
 * @param dclass The DNS class of this cache
 * @see DClass
 */
public
Cache(int dclass) {
	this.dclass = dclass;
	data = new CacheMap(defaultMaxEntries);
}

/**
 * Creates an empty Cache for class IN.
 * @see DClass
 */
public
Cache() {
	this(DClass.IN);
}

/**
 * Creates a Cache which initially contains all records in the specified file.
 */
public
Cache(String file) throws IOException {
	data = new CacheMap(defaultMaxEntries);
	dclass = 0;	//XXX
	final Master m = new Master(file);
	Record record;
	while ((record = m.nextRecord()) != null)
		addRecord(record, Credibility.HINT, m);
}

private synchronized Object
exactName(Name name) {
	return data.get(name);
}

private synchronized void
removeName(Name name) {
	data.remove(name);
}

private synchronized static Element []
allElements(Object types) {
	final Element[] r;
	if (types instanceof List) {
		final List<?> typelist = (List<?>) types;
		final int size = typelist.size();
		r = typelist.toArray(new Element[size]);
	} else {
		final Element set = (Element) types;
		r = new Element[] {set};
	}
	return r;
}

private synchronized Element
oneElement(Name name, Object types, int type, Credibility minCred) {
	Element found = null;

	if (type == Type.ANY)
		throw new IllegalArgumentException("oneElement(ANY)");
	if (types instanceof List) {
		@SuppressWarnings("unchecked")
		final List<Element> list = (List<Element>) types;
		for (Element set : list) {
			if (set.getType() == type) {
				found = set;
				break;
			}
		}
	} else {
		final Element set = (Element) types;
		if (set.getType() == type)
			found = set;
	}
	if (found != null) {
		if (found.expired()) {
			removeElement(name, type);
			found = null;
		} else if (found.compareCredibility(minCred) < 0)
			found = null;
	}
	return found;
}

private synchronized Element
findElement(Name name, int type, Credibility minCred) {
	final Object types = exactName(name);
	if (types == null)
		return null;
	return oneElement(name, types, type, minCred);
}

private synchronized void
addElement(Name name, Element element) {
	final Object types = data.get(name);
	if (types == null) {
		data.put(name, element);
		return;
	}
	int type = element.getType();
	if (types instanceof List) {
		@SuppressWarnings("unchecked")
		final List<Element> list = (List<Element>) types;
		for (int i = 0; i < list.size(); i++) {
			Element elt = list.get(i);
			if (elt.getType() == type) {
				list.set(i, element);
				return;
			}
		}
		list.add(element);
	} else {
		final Element elt = (Element) types;
		if (elt.getType() == type)
			data.put(name, element);
		else {
			final LinkedList<Element> list = new LinkedList<Element>();
			list.add(elt);
			list.add(element);
			data.put(name, list);
		}
	}
}

private synchronized void
removeElement(Name name, int type) {
	final Object types = data.get(name);
	if (types != null) {
		if (types instanceof List) {
			@SuppressWarnings("unchecked")
			final List<Element> list = (List<Element>) types;
			for (int i = 0; i < list.size(); i++) {
				Element elt = list.get(i);
				if (elt.getType() == type) {
					list.remove(i);
					if (list.isEmpty())
						data.remove(name);
					break;
				}
			}
		} else {
			final Element elt = (Element) types;
			if (elt.getType() == type)
				data.remove(name);
		}
	}
}

/** Empties the Cache. */
public synchronized void
clearCache() {
	data.clear();
}

/**
 * Adds a record to the Cache.
 * @param r The record to be added
 * @param cred The credibility of the record
 * @param o The source of the record (this could be a Message, for example)
 * @see Record
 */
public synchronized void
addRecord(Record r, Credibility cred, Object o) {
	final Name name = r.getName();
	final int type = r.getRRsetType();
	if (!Type.isRR(type))
		return;
	final Element element = findElement(name, type, cred);
	if (element == null) {
		final CacheRRset crrset = new CacheRRset(r, cred, maxcache);
		addRRset(crrset, cred);
	} else if (element.compareCredibility(cred) == 0) {
		if (element instanceof CacheRRset) {
			final CacheRRset crrset = (CacheRRset) element;
			crrset.addRR(r);
		}
	}
}

/**
 * Adds an RRset to the Cache.
 * @param rrset The RRset to be added
 * @param cred The credibility of these records
 * @see RRset
 */
public synchronized void
addRRset(RRset rrset, Credibility cred) {
	final long ttl = rrset.getTTL();
	final Name name = rrset.getName();
	final int type = rrset.getType();
	Element element = findElement(name, type, Credibility.HINT);
	if (ttl == 0) {
		if (element != null && element.compareCredibility(cred) <= 0)
			removeElement(name, type);
	} else {
		if (element != null && element.compareCredibility(cred) <= 0)
			element = null;
		if (element == null) {
			CacheRRset crrset;
			if (rrset instanceof CacheRRset)
				crrset = (CacheRRset) rrset;
			else
				crrset = new CacheRRset(rrset, cred, maxcache);
			addElement(name, crrset);
		}
	}
}

/**
 * Adds a negative entry to the Cache.
 * @param name The name of the negative entry
 * @param type The type of the negative entry
 * @param soa The SOA record to add to the negative cache entry, or null.
 * The negative cache ttl is derived from the SOA.
 * @param cred The credibility of the negative entry
 */
public synchronized void
addNegative(Name name, int type, SOARecord soa, Credibility cred) {
	final long ttl = (soa != null) ? soa.getTTL() : 0L;
	Element element = findElement(name, type, Credibility.HINT);
	if (ttl == 0L) {
		if (element != null && element.compareCredibility(cred) <= 0)
			removeElement(name, type);
	} else {
		if (element != null && element.compareCredibility(cred) <= 0)
			element = null;
		if (element == null)
			addElement(name, new NegativeElement(name, type,
							     soa, cred,
							     maxncache));
	}
}

/**
 * Finds all matching sets or something that causes the lookup to stop.
 */
protected synchronized SetResponse
lookup(Name name, int type, Credibility minCred) {
	final int labels;
	int tlabels;
	Element element;
	Name tname;
	Object types;
	SetResponse sr = SetResponse.unknown;

	labels = name.labels();

	for (tlabels = labels; tlabels >= 1; tlabels--) {
		boolean isRoot = (tlabels == 1);
		boolean isExact = (tlabels == labels);

		if (isRoot)
			tname = Name.root;
		else if (isExact)
			tname = name;
		else
			tname = new Name(name, labels - tlabels);

		types = data.get(tname);
		if (types == null)
			continue;

		/*
		 * If this is the name, look for the actual type or a CNAME
		 * (unless it's an ANY query, where we return everything).
		 * Otherwise, look for a DNAME.
		 */
		if (isExact && type == Type.ANY) {
			Element [] elements = allElements(types);
			int added = 0;
			for (Element elem : elements) {
				if (elem.expired()) {
					removeElement(tname, elem.getType());
				} else if (elem instanceof CacheRRset &&
						elem.compareCredibility(minCred) >= 0) {
					sr.addRRset((CacheRRset)elem);
					added++;
				}
			}
			/* There were positive entries */
			if (added > 0)
				sr = SetResponse.success();
		} else if (isExact) {
			element = oneElement(tname, types, type, minCred);
			if (element != null &&
			    element instanceof CacheRRset)
			{
				sr = SetResponse.success((CacheRRset) element);
			} else if (element != null) {
				sr = SetResponse.nxrrset;
			} else {
				element = oneElement(tname, types, Type.CNAME, minCred);
				if (element != null &&
				    element instanceof CacheRRset)
				{
					sr = SetResponse.cname((CacheRRset) element);
				}
			}

		} else {
			element = oneElement(tname, types, Type.DNAME, minCred);
			if (element != null &&
			    element instanceof CacheRRset)
			{
				sr = SetResponse.dname((CacheRRset) element);
			}
		}

		if (sr == SetResponse.unknown) {
			/* Look for an NS */
			element = oneElement(tname, types, Type.NS, minCred);
			if (element != null && element instanceof CacheRRset)
				sr = SetResponse.delegation((CacheRRset) element);
		}

		if (sr == SetResponse.unknown) {
			/* Check for the special NXDOMAIN element. */
			if (isExact) {
				element = oneElement(tname, types, Type_NXDOMAIN, minCred);
				if (element != null)
					sr = SetResponse.nxdomain;
			}
		}

	}
	return sr;
}

/**
 * Looks up Records in the Cache.  This follows CNAMEs and handles negatively
 * cached data.
 * @param name The name to look up
 * @param type The type to look up
 * @param minCred The minimum acceptable credibility
 * @return A SetResponse object
 * @see SetResponse
 * @see Credibility
 */
public SetResponse
lookupRecords(Name name, int type, Credibility minCred) {
	return lookup(name, type, minCred);
}

private RRset []
findRecords(Name name, int type, Credibility minCred) {
	final SetResponse cr = lookupRecords(name, type, minCred);
	final RRset[] r;
	if (cr.isSuccessful())
		r = cr.answers();
	else
		r = null;
	return r;
}

/**
 * Looks up credible Records in the Cache (a wrapper around lookupRecords).
 * Unlike lookupRecords, this given no indication of why failure occurred.
 * @param name The name to look up
 * @param type The type to look up
 * @return An array of RRsets, or null
 * @see Credibility
 */
public RRset []
findRecords(Name name, int type) {
	return findRecords(name, type, Credibility.NORMAL);
}

/**
 * Looks up Records in the Cache (a wrapper around lookupRecords).  Unlike
 * lookupRecords, this given no indication of why failure occurred.
 * @param name The name to look up
 * @param type The type to look up
 * @return An array of RRsets, or null
 * @see Credibility
 */
public RRset []
findAnyRecords(Name name, int type) {
	return findRecords(name, type, Credibility.GLUE);
}

private final static Credibility
getCred(Section section, boolean isAuth) {
	final Credibility r;
	if (section == Section.ANSWER) {
		if (isAuth)
			r = Credibility.AUTH_ANSWER;
		else
			r = Credibility.NONAUTH_ANSWER;
	} else if (section == Section.AUTHORITY) {
		if (isAuth)
			r = Credibility.AUTH_AUTHORITY;
		else
			r = Credibility.NONAUTH_AUTHORITY;
	} else if (section == Section.ADDITIONAL) {
		r = Credibility.ADDITIONAL;
	} else
		throw new IllegalArgumentException("getCred: invalid section");
	return r;
}

private static void
markAdditional(RRset rrset, Set<Name> names) {
	final Record first = rrset.first();
	if (first.getAdditionalName() != null) {
		final Iterator<Record> it = rrset.rrs();
		while (it.hasNext()) {
			Record r = it.next();
			Name name = r.getAdditionalName();
			if (name != null)
				names.add(name);
		}
	}
}

/**
 * Adds all data from a Message into the Cache.  Each record is added with
 * the appropriate credibility, and negative answers are cached as such.
 * @param in The Message to be added
 * @return A SetResponse that reflects what would be returned from a cache
 * lookup, or null if nothing useful could be cached from the message.
 * @see Message
 */
@SuppressWarnings("deprecation")	// Type.A6
public SetResponse
addMessage(Message in) {
	final boolean isAuth = in.getHeader().getFlag(Flags.AA);
	final Record question = in.getQuestion();
	final Name qname;
	Name curname;
	final int qtype;
	final int qclass;
	Credibility cred;
	final int rcode = in.getHeader().getRcode();
	boolean completed = false;
	final RRset [] answers, auth, addl;
	SetResponse response = null;
	final boolean verbose = Options.check(Options.Standard.verbosecache);
	final HashSet<Name> additionalNames;

	if ((rcode != Rcode.NOERROR && rcode != Rcode.NXDOMAIN) ||
	    question == null)
		return null;

	qname = question.getName();
	qtype = question.getType();
	qclass = question.getDClass();

	curname = qname;

	additionalNames = new HashSet<Name>();

	answers = in.getSectionRRsets(Section.ANSWER);
	for (RRset answer : answers) {
		if (answer.getDClass() != qclass)
			continue;
		int type = answer.getType();
		Name name = answer.getName();
		cred = getCred(Section.ANSWER, isAuth);
		if ((type == qtype || qtype == Type.ANY) &&
		    name.equals(curname))
		{
			addRRset(answer, cred);
			completed = true;
			if (curname == qname) {
				if (response == null)
					response = SetResponse.success(answer);
			}
			markAdditional(answer, additionalNames);
		} else if (type == Type.CNAME && name.equals(curname)) {
			CNAMERecord cname;
			addRRset(answer, cred);
			if (curname == qname)
				response = SetResponse.cname(answer);
			cname = (CNAMERecord) answer.first();
			curname = cname.getTarget();
		} else if (type == Type.DNAME && curname.subdomain(name)) {
			DNAMERecord dname;
			addRRset(answer, cred);
			if (curname == qname)
				response = SetResponse.dname(answer);
			dname = (DNAMERecord) answer.first();
			try {
				curname = curname.fromDNAME(dname);
			}
			catch (NameTooLongException e) {
				break;
			}
		}
	}

	auth = in.getSectionRRsets(Section.AUTHORITY);
	RRset soa = null, ns = null;
	for (RRset rrs : auth) {
		int rrsetType = rrs.getType();
		if (rrsetType == Type.SOA &&
		    curname.subdomain(rrs.getName())) {
			soa = rrs;
		} else if (rrsetType == Type.NS &&
			 curname.subdomain(rrs.getName())) {
			ns = rrs;
		}
	}
	if (!completed) {
		/* This is a negative response or a referral. */
		final int cachetype = (rcode == Rcode.NXDOMAIN) ? Type_NXDOMAIN : qtype;
		if (rcode == Rcode.NXDOMAIN || soa != null || ns == null) {
			/* Negative response */
			cred = getCred(Section.AUTHORITY, isAuth);
			SOARecord soarec = null;
			if (soa != null)
				soarec = (SOARecord) soa.first();
			addNegative(curname, cachetype, soarec, cred);
			if (response == null) {
				if (rcode == Rcode.NXDOMAIN)
					response = SetResponse.nxdomain;
				else
					response = SetResponse.nxrrset;
			}
			/* DNSSEC records are not cached. */
		} else {
			/* Referral response */
			cred = getCred(Section.AUTHORITY, isAuth);
			addRRset(ns, cred);
			markAdditional(ns, additionalNames);
			if (response == null)
				response = SetResponse.delegation(ns);
		}
	} else if (rcode == Rcode.NOERROR && ns != null) {
		/* Cache the NS set from a positive response. */
		cred = getCred(Section.AUTHORITY, isAuth);
		addRRset(ns, cred);
		markAdditional(ns, additionalNames);
	}

	addl = in.getSectionRRsets(Section.ADDITIONAL);
	for (RRset rrs : addl) {
		int type = rrs.getType();
		if (type == Type.A || type == Type.AAAA || type == Type.A6) {
			Name name = rrs.getName();
			if (additionalNames.contains(name)) {
				cred = getCred(Section.ADDITIONAL, isAuth);
				addRRset(rrs, cred);
			}
		}
	}
	if (verbose)
		System.out.println("addMessage: " + response);
	return (response);
}

/**
 * Flushes an RRset from the cache
 * @param name The name of the records to be flushed
 * @param type The type of the records to be flushed
 * @see RRset
 */
public void
flushSet(Name name, int type) {
	removeElement(name, type);
}

/**
 * Flushes all RRsets with a given name from the cache
 * @param name The name of the records to be flushed
 * @see RRset
 */
public void
flushName(Name name) {
	removeName(name);
}

/**
 * Sets the maximum length of time that a negative response will be stored
 * in this Cache.  A negative value disables this feature (that is, sets
 * no limit).
 */
public void
setMaxNCache(int seconds) {
	maxncache = seconds;
}

/**
 * Gets the maximum length of time that a negative response will be stored
 * in this Cache.  A negative value indicates no limit.
 */
public int
getMaxNCache() {
	return maxncache;
}

/**
 * Sets the maximum length of time that records will be stored in this
 * Cache.  A negative value disables this feature (that is, sets no limit).
 */
public void
setMaxCache(int seconds) {
	maxcache = seconds;
}

/**
 * Gets the maximum length of time that records will be stored
 * in this Cache.  A negative value indicates no limit.
 */
public int
getMaxCache() {
	return maxcache;
}

/**
 * Gets the current number of entries in the Cache, where an entry consists
 * of all records with a specific Name.
 */
public int
getSize() {
	return data.size();
}

/**
 * Gets the maximum number of entries in the Cache, where an entry consists
 * of all records with a specific Name.  A negative value is treated as an
 * infinite limit.
 */
public int
getMaxEntries() {
	return data.getMaxSize();
}

/**
 * Sets the maximum number of entries in the Cache, where an entry consists
 * of all records with a specific Name.  A negative value is treated as an
 * infinite limit.
 *
 * Note that setting this to a value lower than the current number
 * of entries will not cause the Cache to shrink immediately.
 *
 * The default maximum number of entries is 50000.
 *
 * @param entries The maximum number of entries in the Cache.
 */
public void
setMaxEntries(int entries) {
	data.setMaxSize(entries);
}

/**
 * Returns the DNS class of this cache.
 */
public int
getDClass() {
	return dclass;
}

/**
 * Returns the contents of the Cache as a string.
 */
@Override
public String
toString() {
	final StringBuilder sb = new StringBuilder();
	synchronized (this) {
		final Iterator<Object> it = data.values().iterator();
		while (it.hasNext()) {
			Element [] elements = allElements(it.next());
			for (Element element : elements) {
				sb.append(element);
				sb.append('\n');
			}
		}
	}
	return sb.toString();
}

}
