// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

import java.io.*;
import java.net.*;
import java.util.*;
import org.xbill.DNS.*;

/** @author Brian Wellington &lt;bwelling@xbill.org&gt; */

public class jnamed {

static final int FLAG_DNSSECOK = 1;
static final int FLAG_SIGONLY = 2;

final Map<Integer, Cache> caches;
final Map<Name, Zone> znames;
final Map<Name, TSIG> TSIGs;

private static String
addrport(InetAddress addr, int port) {
	return addr.getHostAddress() + "#" + port;
}

public
jnamed(String conffile) throws IOException, ZoneTransferException {
	final FileInputStream fs;
	final InputStreamReader isr;
	final BufferedReader br;
	final List<Integer> ports = new ArrayList<Integer>();
	final List<InetAddress> addresses = new ArrayList<InetAddress>();
	try {
		fs = new FileInputStream(conffile);
		isr = new InputStreamReader(fs);
		br = new BufferedReader(isr);
	}
	catch (IOException e) {
		System.out.println("Cannot open " + conffile);
		throw e;
	}

	try {
		caches = new HashMap<Integer, Cache>();
		znames = new HashMap<Name, Zone>();
		TSIGs = new HashMap<Name, TSIG>();

		String line = null;
		while ((line = br.readLine()) != null) {
			StringTokenizer st = new StringTokenizer(line);
			if (!st.hasMoreTokens())
				continue;
			String keyword = st.nextToken();
			if (!st.hasMoreTokens()) {
				System.out.println("Invalid line: " + line);
				continue;
			}
			if (keyword.charAt(0) == '#')
				continue;
			if (keyword.equals("primary"))
				addPrimaryZone(st.nextToken(), st.nextToken());
			else if (keyword.equals("secondary"))
				addSecondaryZone(st.nextToken(),
						 st.nextToken());
			else if (keyword.equals("cache")) {
				Cache cache = new Cache(st.nextToken());
				caches.put(Integer.valueOf(DClass.IN), cache);
			} else if (keyword.equals("key")) {
				String s1 = st.nextToken();
				String s2 = st.nextToken();
				if (st.hasMoreTokens())
					addTSIG(s1, s2, st.nextToken());
				else
					addTSIG("hmac-md5", s1, s2);
			} else if (keyword.equals("port")) {
				ports.add(Integer.valueOf(st.nextToken()));
			} else if (keyword.equals("address")) {
				String addr = st.nextToken();
				addresses.add(Address.getByAddress(addr));
			} else {
				System.out.println("unknown keyword: " +
						   keyword);
			}

		}

		if (ports.size() == 0)
			ports.add(Integer.valueOf(53));

		if (addresses.size() == 0)
			addresses.add(Address.getByAddress("0.0.0.0"));

		final Iterator<InetAddress> iaddr = addresses.iterator();
		while (iaddr.hasNext()) {
			InetAddress addr = iaddr.next();
			Iterator<Integer> iport = ports.iterator();
			while (iport.hasNext()) {
				int port = iport.next().intValue();
				addUDP(addr, port);
				addTCP(addr, port);
				System.out.println("jnamed: listening on " +
						   addrport(addr, port));
			}
		}
		System.out.println("jnamed: running");
	}
	finally {
		fs.close();
	}
}

public void
addPrimaryZone(String zname, String zonefile) throws IOException {
	Name origin = null;
	if (zname != null)
		origin = Name.fromString(zname, Name.root);
	final Zone newzone = new Zone(origin, zonefile);
	znames.put(newzone.getOrigin(), newzone);
}

public void
addSecondaryZone(String zone, String remote)
throws IOException, ZoneTransferException
{
	final Name zname = Name.fromString(zone, Name.root);
	final Zone newzone = new Zone(zname, DClass.IN, remote);
	znames.put(zname, newzone);
}

public void
addTSIG(String algstr, String namestr, String key) throws IOException {
	final Name name = Name.fromString(namestr, Name.root);
	TSIGs.put(name, new TSIG(algstr, namestr, key));
}

public Cache
getCache(int dclass) {
	Cache c = caches.get(Integer.valueOf(dclass));
	if (c == null) {
		c = new Cache(dclass);
		caches.put(Integer.valueOf(dclass), c);
	}
	return c;
}

public Zone
findBestZone(Name name) {
	Zone foundzone = null;
	foundzone = znames.get(name);
	if (foundzone != null)
		return foundzone;
	final int labels = name.labels();
	for (int i = 1; i < labels; i++) {
		Name tname = new Name(name, i);
		foundzone = znames.get(tname);
		if (foundzone != null)
			return foundzone;
	}
	return null;
}

public RRset
findExactMatch(Name name, int type, int dclass, boolean glue) {
	final RRset r;
	Zone zone = findBestZone(name);
	if (zone != null)
		r = zone.findExactMatch(name, type);
	else {
		RRset [] rrsets;
		Cache cache = getCache(dclass);
		if (glue)
			rrsets = cache.findAnyRecords(name, type);
		else
			rrsets = cache.findRecords(name, type);
		if (rrsets == null)
			r = null;
		else
			r = rrsets[0]; /* not quite right */
	}
	return r;
}

void
addRRset(Name name, Message response, RRset rrset, int section, int flags) {
	for (int s = 1; s <= section; s++)
		if (response.findRRset(name, rrset.getType(), s))
			return;
	if ((flags & FLAG_SIGONLY) == 0) {
		final Iterator<Record> it = rrset.rrs();
		while (it.hasNext()) {
			Record r = it.next();
			if (r.getName().isWild() && !name.isWild())
				r = r.withName(name);
			response.addRecord(r, section);
		}
	}
	if ((flags & (FLAG_SIGONLY | FLAG_DNSSECOK)) != 0) {
		final Iterator<Record> it = rrset.sigs();
		while (it.hasNext()) {
			Record r = it.next();
			if (r.getName().isWild() && !name.isWild())
				r = r.withName(name);
			response.addRecord(r, section);
		}
	}
}

private final static void
addSOA(Message response, Zone zone) {
	response.addRecord(zone.getSOA(), Section.AUTHORITY);
}

private final void
addNS(Message response, Zone zone, int flags) {
	final RRset nsRecords = zone.getNS();
	addRRset(nsRecords.getName(), response, nsRecords,
		 Section.AUTHORITY, flags);
}

private final static void
addCacheNS(Message response, Cache cache, Name name) {
	final SetResponse sr = cache.lookupRecords(name, Type.NS, Credibility.HINT);
	if (!sr.isDelegation())
		return;
	final RRset nsRecords = sr.getNS();
	final Iterator<Record> it = nsRecords.rrs();
	while (it.hasNext()) {
		Record r = it.next();
		response.addRecord(r, Section.AUTHORITY);
	}
}

private void
addGlue(Message response, Name name, int flags) {
	final RRset a = findExactMatch(name, Type.A, DClass.IN, true);
	if (a == null)
		return;
	addRRset(name, response, a, Section.ADDITIONAL, flags);
}

private void
addAdditional2(Message response, int section, int flags) {
	final Record [] records = response.getSectionArray(section);
	for (int i = 0; i < records.length; i++) {
		Record r = records[i];
		Name glueName = r.getAdditionalName();
		if (glueName != null)
			addGlue(response, glueName, flags);
	}
}

private final void
addAdditional(Message response, int flags) {
	addAdditional2(response, Section.ANSWER, flags);
	addAdditional2(response, Section.AUTHORITY, flags);
}

@SuppressWarnings("deprecation")	// Type.SIG
int
addAnswer(Message response, Name name, int type, int dclass,
	  int iterations, int flags)
{
	final SetResponse sr;
	int rcode = Rcode.NOERROR;

	if (iterations > 6)
		return Rcode.NOERROR;

	if (type == Type.RRSIG || type == Type.SIG) {
		type = Type.ANY;
		flags |= FLAG_SIGONLY;
	}

	final Zone zone = findBestZone(name);
	if (zone != null)
		sr = zone.findRecords(name, type);
	else {
		Cache cache = getCache(dclass);
		sr = cache.lookupRecords(name, type, Credibility.NORMAL);
	}

	if (sr.isUnknown()) {
		addCacheNS(response, getCache(dclass), name);
	}
	if (sr.isNXDOMAIN()) {
		response.getHeader().setRcode(Rcode.NXDOMAIN);
		if (zone != null) {
			addSOA(response, zone);
			if (iterations == 0)
				response.getHeader().setFlag(Flags.AA);
		}
		rcode = Rcode.NXDOMAIN;
	}
	else if (sr.isNXRRSET()) {
		if (zone != null) {
			addSOA(response, zone);
			if (iterations == 0)
				response.getHeader().setFlag(Flags.AA);
		}
	}
	else if (sr.isDelegation()) {
		final RRset nsRecords = sr.getNS();
		addRRset(nsRecords.getName(), response, nsRecords,
			 Section.AUTHORITY, flags);
	}
	else if (sr.isCNAME()) {
		final CNAMERecord cname = sr.getCNAME();
		final RRset rrset = new RRset(cname);
		addRRset(name, response, rrset, Section.ANSWER, flags);
		if (zone != null && iterations == 0)
			response.getHeader().setFlag(Flags.AA);
		rcode = addAnswer(response, cname.getTarget(),
				  type, dclass, iterations + 1, flags);
	}
	else if (sr.isDNAME()) {
		final DNAMERecord dname = sr.getDNAME();
		RRset rrset = new RRset(dname);
		addRRset(name, response, rrset, Section.ANSWER, flags);
		final Name newname;
		try {
			newname = name.fromDNAME(dname);
		}
		catch (NameTooLongException e) {
			return Rcode.YXDOMAIN;
		}
		rrset = new RRset(new CNAMERecord(name, dclass, 0, newname));
		addRRset(name, response, rrset, Section.ANSWER, flags);
		if (zone != null && iterations == 0)
			response.getHeader().setFlag(Flags.AA);
		rcode = addAnswer(response, newname, type, dclass,
				  iterations + 1, flags);
	}
	else if (sr.isSuccessful()) {
		final RRset [] rrsets = sr.answers();
		for (int i = 0; i < rrsets.length; i++)
			addRRset(name, response, rrsets[i],
				 Section.ANSWER, flags);
		if (zone != null) {
			addNS(response, zone, flags);
			if (iterations == 0)
				response.getHeader().setFlag(Flags.AA);
		}
		else
			addCacheNS(response, getCache(dclass), name);
	}
	return rcode;
}

byte []
doAXFR(Name name, Message query, TSIG tsig, TSIGRecord qtsig, Socket s) {
	final Zone zone = znames.get(name);
	boolean first = true;
	if (zone == null)
		return errorMessage(query, Rcode.REFUSED);
	final Iterator<RRset> it = zone.AXFR();
	try {
		final DataOutputStream dataOut;
		dataOut = new DataOutputStream(s.getOutputStream());
		final int id = query.getHeader().getID();
		while (it.hasNext()) {
			RRset rrset = it.next();
			Message response = new Message(id);
			Header header = response.getHeader();
			header.setFlag(Flags.QR);
			header.setFlag(Flags.AA);
			addRRset(rrset.getName(), response, rrset,
				 Section.ANSWER, FLAG_DNSSECOK);
			if (tsig != null) {
				tsig.applyStream(response, qtsig, first);
				qtsig = response.getTSIG();
			}
			first = false;
			byte [] out = response.toWire();
			dataOut.writeShort(out.length);
			dataOut.write(out);
		}
	}
	catch (IOException ex) {
		System.out.println("AXFR failed");
	}
	try {
		s.close();
	}
	catch (IOException ex) {
	}
	return null;
}

/*
 * Note: a null return value means that the caller doesn't need to do
 * anything.  Currently this only happens if this is an AXFR request over
 * TCP.
 */
byte []
generateReply(Message query, byte [] in, int length, Socket s)
{
	final Header header;
	final int maxLength;
	int flags = 0;

	header = query.getHeader();
	if (header.getFlag(Flags.QR))
		return null;
	if (header.getRcode() != Rcode.NOERROR)
		return errorMessage(query, Rcode.FORMERR);
	if (header.getOpcode() != Opcode.QUERY)
		return errorMessage(query, Rcode.NOTIMP);

	final Record queryRecord = query.getQuestion();

	final TSIGRecord queryTSIG = query.getTSIG();
	TSIG tsig = null;
	if (queryTSIG != null) {
		tsig = TSIGs.get(queryTSIG.getName());
		if (tsig == null ||
		    tsig.verify(query, in, length, null) != Rcode.NOERROR)
			return formerrMessage(in);
	}

	final OPTRecord queryOPT = query.getOPT();
	if (s != null)
		maxLength = 65535;
	else if (queryOPT != null)
		maxLength = Math.max(queryOPT.getPayloadSize(), 512);
	else
		maxLength = 512;

	if (queryOPT != null && (queryOPT.getFlags() & ExtendedFlags.DO) != 0)
		flags = FLAG_DNSSECOK;

	final Message response = new Message(query.getHeader().getID());
	response.getHeader().setFlag(Flags.QR);
	if (query.getHeader().getFlag(Flags.RD))
		response.getHeader().setFlag(Flags.RD);
	response.addRecord(queryRecord, Section.QUESTION);

	final Name name = queryRecord.getName();
	final int type = queryRecord.getType();
	final int dclass = queryRecord.getDClass();
	if (type == Type.AXFR && s != null)
		return doAXFR(name, query, tsig, queryTSIG, s);
	if (!Type.isRR(type) && type != Type.ANY)
		return errorMessage(query, Rcode.NOTIMP);

	final int rcode = addAnswer(response, name, type, dclass, 0, flags);
	if (rcode != Rcode.NOERROR && rcode != Rcode.NXDOMAIN)
		return errorMessage(query, rcode);

	addAdditional(response, flags);

	if (queryOPT != null) {
		final int optflags = (flags == FLAG_DNSSECOK) ? ExtendedFlags.DO : 0;
		final OPTRecord opt = new OPTRecord(4096, rcode, 0, optflags);
		response.addRecord(opt, Section.ADDITIONAL);
	}

	response.setTSIG(tsig, Rcode.NOERROR, queryTSIG);
	return response.toWire(maxLength);
}

byte []
buildErrorMessage(Header header, int rcode, Record question) {
	final Message response = new Message();
	response.setHeader(header);
	for (int i = 0; i < 4; i++)
		response.removeAllRecords(i);
	if (rcode == Rcode.SERVFAIL)
		response.addRecord(question, Section.QUESTION);
	header.setRcode(rcode);
	return response.toWire();
}

public byte []
formerrMessage(byte [] in) {
	final Header header;
	try {
		header = new Header(in);
	}
	catch (IOException e) {
		return null;
	}
	return buildErrorMessage(header, Rcode.FORMERR, null);
}

public byte []
errorMessage(Message query, int rcode) {
	return buildErrorMessage(query.getHeader(), rcode,
				 query.getQuestion());
}

public void
TCPclient(Socket s) {
	try {
		final int inLength;
		final DataInputStream dataIn;
		final DataOutputStream dataOut;
		final byte [] in;

		final InputStream is = s.getInputStream();
		dataIn = new DataInputStream(is);
		inLength = dataIn.readUnsignedShort();
		in = new byte[inLength];
		dataIn.readFully(in);
		dataIn.close();

		final Message query;
		byte [] response = null;
		try {
			query = new Message(in);
			response = generateReply(query, in, in.length, s);
		}
		catch (IOException e) {
			response = formerrMessage(in);
		}
		if (response != null) {
			dataOut = new DataOutputStream(s.getOutputStream());
			dataOut.writeShort(response.length);
			dataOut.write(response);
		}
	}
	catch (IOException e) {
		System.out.println("TCPclient(" +
				   addrport(s.getLocalAddress(),
					    s.getLocalPort()) +
				   "): " + e);
	}
	finally {
		try {
			s.close();
		}
		catch (IOException e) {}
	}
}

public void
serveTCP(InetAddress addr, int port) {
	ServerSocket sock = null;
	try {
		sock = new ServerSocket(port, 128, addr);
		while (true) {
			@SuppressWarnings("resource")	// closed in TCPclient()
			final Socket s = sock.accept();
			Thread t;
			t = new Thread(new Runnable() {
					public void run() {
						TCPclient(s);
					}
			});
			t.start();
		}
	}
	catch (IOException e) {
		System.out.println("serveTCP(" + addrport(addr, port) + "): " +
				   e);
	} finally {
		if (sock != null)
			try {
				sock.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	}
}

public void
serveUDP(InetAddress addr, int port) {
	DatagramSocket sock = null;
	try {
		sock = new DatagramSocket(port, addr);
		final int udpLength = 512;
		final byte [] in = new byte[udpLength];
		final DatagramPacket indp = new DatagramPacket(in, in.length);
		DatagramPacket outdp = null;
		while (true) {
			indp.setLength(in.length);
			try {
				sock.receive(indp);
			}
			catch (InterruptedIOException e) {
				continue;
			}
			Message query;
			byte [] response = null;
			try {
				query = new Message(in);
				response = generateReply(query, in,
							 indp.getLength(),
							 null);
				if (response == null)
					continue;
			}
			catch (IOException e) {
				response = formerrMessage(in);
			}
			if (outdp == null)
				outdp = new DatagramPacket(response,
							   response.length,
							   indp.getAddress(),
							   indp.getPort());
			else {
				outdp.setData(response);
				outdp.setLength(response.length);
				outdp.setAddress(indp.getAddress());
				outdp.setPort(indp.getPort());
			}
			sock.send(outdp);
		}
	}
	catch (IOException e) {
		System.out.println("serveUDP(" + addrport(addr, port) + "): " +
				   e);
	} finally {
		if (sock != null)
			sock.close();
	}
}

public void
addTCP(final InetAddress addr, final int port) {
	final Thread t;
	t = new Thread(new Runnable() {
			public void run() {serveTCP(addr, port);}});
	t.start();
}

public void
addUDP(final InetAddress addr, final int port) {
	final Thread t;
	t = new Thread(new Runnable() {
			public void run() {serveUDP(addr, port);}});
	t.start();
}

public static void main(String [] args) {
	if (args.length > 1) {
		System.out.println("usage: jnamed [conf]");
		System.exit(0);
	}
	try {
		String conf;
		if (args.length == 1)
			conf = args[0];
		else
			conf = "jnamed.conf";
		new jnamed(conf);
	}
	catch (IOException e) {
		System.out.println(e);
	}
	catch (ZoneTransferException e) {
		System.out.println(e);
	}
}

}
