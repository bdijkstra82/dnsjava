// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.util.HashMap;

/**
 * Constants and functions relating to DNS Types
 *
 * @author Brian Wellington
 */

public final class Type {

/** Address */
public static final int A		= 1;

/** Name server */
public static final int NS		= 2;

/** Mail destination
 * @deprecated replaced by MX in RFC 973 */
@Deprecated
public static final int MD		= 3;

/** Mail forwarder
 * @deprecated replaced by MX in RFC 973 */
@Deprecated
public static final int MF		= 4;

/** Canonical name (alias) */
public static final int CNAME		= 5;

/** Start of authority */
public static final int SOA		= 6;

/** Mailbox domain name
 * @deprecated classified as experimental by RFC 1035 */
@Deprecated
public static final int MB		= 7;

/** Mail group member
 * @deprecated classified as experimental by RFC 1035 */
@Deprecated
public static final int MG		= 8;

/** Mail rename name
 * @deprecated classified as experimental by RFC 1035 */
@Deprecated
public static final int MR		= 9;

/** Null record
 * @deprecated Obsoleted by RFC 1035 */
@Deprecated
public static final int NULL		= 10;

/** Well known services
 * @deprecated not to be relied upon (RFC 1123, 1127) */
@Deprecated
public static final int WKS		= 11;

/** Domain name pointer */
public static final int PTR		= 12;

/** Host information
 * @deprecated Not in current use by any notable application. */
@Deprecated
public static final int HINFO		= 13;

/** Mailbox information
 * @deprecated classified as experimental by RFC 1035 */
@Deprecated
public static final int MINFO		= 14;

/** Mail routing information */
public static final int MX		= 15;

/** Text strings */
public static final int TXT		= 16;

/** Responsible person */
@Deprecated
public static final int RP		= 17;

/** AFS cell database */
public static final int AFSDB		= 18;

/** X.25 calling address
 * @deprecated Not in current use by any notable application. */
@Deprecated
public static final int X25		= 19;

/** ISDN calling address
 * @deprecated Not in current use by any notable application. */
@Deprecated
public static final int ISDN		= 20;

/** Router
 * @deprecated Not in current use by any notable application. */
@Deprecated
public static final int RT		= 21;

/** NSAP address
 * @deprecated Not in current use by any notable application. */
@Deprecated
public static final int NSAP		= 22;

/** Reverse NSAP address
 * @deprecated Not in current use by any notable application. */
@Deprecated
public static final int NSAP_PTR	= 23;

/** Signature
 * @deprecated Obsoleted by DNSSEC updates (RFC 3755) */
@Deprecated
public static final int SIG		= 24;

/** Key
 * @deprecated Obsoleted by DNSSEC updates (RFC 3755) */
@Deprecated
public static final int KEY		= 25;

/** X.400 mail mapping
 * @deprecated Not in current use by any notable application. */
@Deprecated
public static final int PX		= 26;

/** Geographical position
 * @deprecated withdrawn, use LOC (29) */
@Deprecated
public static final int GPOS		= 27;

/** IPv6 address */
public static final int AAAA		= 28;

/** Location */
public static final int LOC		= 29;

/** Next valid name in zone
 * @deprecated Obsoleted by DNSSEC updates (RFC 3755) */
@Deprecated
public static final int NXT		= 30;

/** Endpoint identifier
 * @deprecated Not in current use by any notable application. */
@Deprecated
public static final int EID		= 31;

/** Nimrod locator
 * @deprecated Not in current use by any notable application. */
@Deprecated
public static final int NIMLOC		= 32;

/** Server selection */
public static final int SRV		= 33;

/** ATM address
 * @deprecated Not in current use by any notable application. */
@Deprecated
public static final int ATMA		= 34;

/** Naming authority pointer */
public static final int NAPTR		= 35;

/** Key exchange */
public static final int KX		= 36;

/** Certificate */
public static final int CERT		= 37;

/** IPv6 address
 * @deprecated historic (RFC 6563) */
@Deprecated
public static final int A6		= 38;

/** Non-terminal name redirection */
public static final int DNAME		= 39;

/** Options - contains EDNS metadata */
public static final int OPT		= 41;

/** Address Prefix List
 * @deprecated Not in current use by any notable application. */
@Deprecated
public static final int APL		= 42;

/** Delegation Signer */
public static final int DS		= 43;

/** SSH Key Fingerprint */
public static final int SSHFP		= 44;

/** IPSEC key */
public static final int IPSECKEY	= 45;

/** Resource Record Signature */
public static final int RRSIG		= 46;

/** Next Secure Name */
public static final int NSEC		= 47;

/** DNSSEC Key */
public static final int DNSKEY		= 48;

/** Dynamic Host Configuration Protocol (DHCP) ID */
public static final int DHCID		= 49;

/** Next SECure, 3rd edition, RFC 5155 */
public static final int NSEC3		= 50;

/** Next SECure PARAMeter, RFC 5155 */
public static final int NSEC3PARAM	= 51;

/** Transport Layer Security Authentication, draft-ietf-dane-protocol-23 */
public static final int TLSA		= 52;

/** S/MIME cert association, draft-ietf-dane-smime */
public static final int SMIMEA		= 53;

/** OpenPGP Key, RFC 7929 */
public static final int OPENPGPKEY	= 61;

/** Sender Policy Framework
 * @Deprecated discontinued in RFC 7208 */
@Deprecated
public static final int SPF		= 99;

/** Transaction key - used to compute a shared secret or exchange a key */
public static final int TKEY		= 249;

/** Transaction signature */
public static final int TSIG		= 250;

/** Incremental zone transfer */
public static final int IXFR		= 251;

/** Zone transfer */
public static final int AXFR		= 252;

/** Transfer mailbox records
 * @deprecated classified as experimental by RFC 1035 */
@Deprecated
public static final int MAILB		= 253;

/** Transfer mail agent records
 * @Deprecated replaced by MX in RFC 973 */
@Deprecated
public static final int MAILA		= 254;

/** Matches any type */
public static final int ANY		= 255;

/** URI
 * @see <a href="http://tools.ietf.org/html/draft-faltstrom-uri-14">draft-faltstrom-uri-14</a>
 */
public static final int URI		= 256;

/** Certification Authority Authorization, RFC 6844 */
public static final int CAA		= 257;

/** DNSSEC Lookaside Validation, RFC 4431 . */
public static final int DLV		= 32769;


private static class TypeMnemonic extends Mnemonic {
	private final HashMap<Integer, Class<? extends Record>> classes;

	public
	TypeMnemonic() {
		super("Type", CASE_UPPER);
		setPrefix("TYPE");
		classes = new HashMap<Integer, Class<? extends Record>>();
	}

	public void
	add(int val, String str, Class<? extends Record> cls) {
		super.add(val, str);
		classes.put(Integer.valueOf(val), cls);
	}

	@Override
	public void
	check(int val) {
		Type.check(val);
	}

	public Record
	getProto(int val) {
		check(val);
		final Class<? extends Record> cls = classes.get(Integer.valueOf(val));
		Record r = null;
		if (cls != null) {
			try {
				r = cls.newInstance();
			} catch (InstantiationException e) {
				throw new AssertionError(e);
			} catch (IllegalAccessException e) {
				throw new AssertionError(e);
			}
		}
		return r;
	}
}

private static final TypeMnemonic types = new TypeMnemonic();

static {
	types.add(A, "A", ARecord.class);
	types.add(NS, "NS", NSRecord.class);
	types.add(MD, "MD", MDRecord.class);
	types.add(MF, "MF", MFRecord.class);
	types.add(CNAME, "CNAME", CNAMERecord.class);
	types.add(SOA, "SOA", SOARecord.class);
	types.add(MB, "MB", MBRecord.class);
	types.add(MG, "MG", MGRecord.class);
	types.add(MR, "MR", MRRecord.class);
	types.add(NULL, "NULL", NULLRecord.class);
	types.add(WKS, "WKS", WKSRecord.class);
	types.add(PTR, "PTR", PTRRecord.class);
	types.add(HINFO, "HINFO", HINFORecord.class);
	types.add(MINFO, "MINFO", MINFORecord.class);
	types.add(MX, "MX", MXRecord.class);
	types.add(TXT, "TXT", TXTRecord.class);
	types.add(RP, "RP", RPRecord.class);
	types.add(AFSDB, "AFSDB", AFSDBRecord.class);
	types.add(X25, "X25", X25Record.class);
	types.add(ISDN, "ISDN", ISDNRecord.class);
	types.add(RT, "RT", RTRecord.class);
	types.add(NSAP, "NSAP", NSAPRecord.class);
	types.add(NSAP_PTR, "NSAP-PTR", NSAP_PTRRecord.class);
	types.add(SIG, "SIG", SIGRecord.class);
	types.add(KEY, "KEY", KEYRecord.class);
	types.add(PX, "PX", PXRecord.class);
	types.add(GPOS, "GPOS", GPOSRecord.class);
	types.add(AAAA, "AAAA", AAAARecord.class);
	types.add(LOC, "LOC", LOCRecord.class);
	types.add(NXT, "NXT", NXTRecord.class);
	types.add(EID, "EID");
	types.add(NIMLOC, "NIMLOC");
	types.add(SRV, "SRV", SRVRecord.class);
	types.add(ATMA, "ATMA");
	types.add(NAPTR, "NAPTR", NAPTRRecord.class);
	types.add(KX, "KX", KXRecord.class);
	types.add(CERT, "CERT", CERTRecord.class);
	types.add(A6, "A6", A6Record.class);
	types.add(DNAME, "DNAME", DNAMERecord.class);
	types.add(OPT, "OPT", OPTRecord.class);
	types.add(APL, "APL", APLRecord.class);
	types.add(DS, "DS", DSRecord.class);
	types.add(SSHFP, "SSHFP", SSHFPRecord.class);
	types.add(IPSECKEY, "IPSECKEY", IPSECKEYRecord.class);
	types.add(RRSIG, "RRSIG", RRSIGRecord.class);
	types.add(NSEC, "NSEC", NSECRecord.class);
	types.add(DNSKEY, "DNSKEY", DNSKEYRecord.class);
	types.add(DHCID, "DHCID", DHCIDRecord.class);
	types.add(NSEC3, "NSEC3", NSEC3Record.class);
	types.add(NSEC3PARAM, "NSEC3PARAM", NSEC3PARAMRecord.class);
	types.add(TLSA, "TLSA", TLSARecord.class);
	types.add(SMIMEA, "SMIMEA", SMIMEARecord.class);
	types.add(OPENPGPKEY, "OPENPGPKEY", OPENPGPKEYRecord.class);
	types.add(SPF, "SPF", SPFRecord.class);
	types.add(TKEY, "TKEY", TKEYRecord.class);
	types.add(TSIG, "TSIG", TSIGRecord.class);
	types.add(IXFR, "IXFR");
	types.add(AXFR, "AXFR");
	types.add(MAILB, "MAILB");
	types.add(MAILA, "MAILA");
	types.add(ANY, "ANY");
	types.add(URI, "URI", URIRecord.class);
	types.add(CAA, "CAA", CAARecord.class);
	types.add(DLV, "DLV", DLVRecord.class);
}

private
Type() {
}

/**
 * Checks that a numeric Type is valid.
 * @throws InvalidTypeException The type is out of range.
 */
public static void
check(int val) {
	if (val < 0 || val > 0xFFFF)
		throw new InvalidTypeException(val);
}

/**
 * Converts a numeric Type into a String
 * @param val The type value.
 * @return The canonical string representation of the type
 * @throws InvalidTypeException The type is out of range.
 */
public static String
string(int val) {
	return types.getText(val);
}

/**
 * Converts a String representation of an Type into its numeric value.
 * @param s The string representation of the type
 * @param numberok Whether a number will be accepted or not.
 * @return The type code, or -1 on error.
 */
public static int
value(String s, boolean numberok) {
	int val = types.getValue(s);
	if (val == -1 && numberok) {
		val = types.getValue("TYPE" + s);
	}
	return val;
}

/**
 * Converts a String representation of an Type into its numeric value
 * @return The type code, or -1 on error.
 */
public static int
value(String s) {
	return value(s, false);
}

static Record
getProto(int val) {
	return types.getProto(val);
}

/** Is this type valid for a record (a non-meta type)? */
public static boolean
isRR(int type) {
	switch (type) {
		case OPT:
		case TKEY:
		case TSIG:
		case IXFR:
		case AXFR:
		case MAILB:
		case MAILA:
		case ANY:
			return false;
		default:
			return true;
	}
}

}
