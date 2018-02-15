// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)
package org.xbill.DNS;

import java.io.*;
import java.util.Arrays;

/**
 * DNS extension options, as described in RFC 2671.  The rdata of an OPT record
 * is defined as a list of options; this represents a single option.
 *
 * @author Brian Wellington
 * @author Ming Zhou &lt;mizhou@bnivideo.com&gt;, Beaumaris Networks
 */
public abstract class EDNSOption implements Serializable {

public static class Code {
	private Code() {}

	/** Name Server Identifier, RFC 5001 */
	public final static int NSID = 3;

	/** Client Subnet, defined in draft-vandergaast-edns-client-subnet-02 */
	public final static int CLIENT_SUBNET = 8;

	private static final Mnemonic codes = new Mnemonic("EDNS Option Codes",
						     Mnemonic.CASE_UPPER, "CODE", 0xFFFF, true);

	static {
		codes.add(NSID, "NSID");
		codes.add(CLIENT_SUBNET, "CLIENT_SUBNET");
	}

	/**
	 * Converts an EDNS Option Code into its textual representation
	 */
	public static String
	string(int code) {
		return codes.getText(code);
	}

	/**
	 * Converts a textual representation of an EDNS Option Code into its
	 * numeric value.
	 * @param s The textual representation of the option code
	 * @return The option code, or -1 on error.
	 */
	public static int
	value(String s) {
		return codes.getValue(s);
	}
}

private final int code;

/**
 *
 * Creates an option with the given option code and data.
 */
public
EDNSOption(int code) {
	this.code = Record.checkU16("code", code);
}

@Override
public String
toString() {
	final StringBuilder sb = new StringBuilder();

	sb.append('{');
	sb.append(EDNSOption.Code.string(code));
	sb.append(": ");
	sb.append(optionToString());
	sb.append('}');

	return sb.toString();
}

/**
 * Returns the EDNS Option's code.
 *
 * @return the option code
 */
public int
getCode() {
	return code;
}

/**
 * Returns the EDNS Option's data, as a byte array.
 *
 * @return the option data
 */
byte []
getData() {
	final DNSOutput out = new DNSOutput();
	optionToWire(out);
	return out.toByteArray();
}

/**
 * Converts the wire format of an EDNS Option (the option data only) into the
 * type-specific format.
 * @param in The input Stream.
 */
abstract void
optionFromWire(DNSInput in) throws IOException;

/**
 * Converts the wire format of an EDNS Option (including code and length) into
 * the type-specific format.
 * @param out The input stream.
 */
static EDNSOption
fromWire(DNSInput in) throws IOException {
	final int code, length;

	code = in.readU16();
	length = in.readU16();
	if (in.remaining() < length)
		throw new WireParseException("truncated option");
	final int save = in.saveActive();
	in.setActive(length);
	final EDNSOption option;
	switch (code) {
	case Code.NSID:
		option = new NSIDOption();
		break;
	case Code.CLIENT_SUBNET:
		option = new ClientSubnetOption();
		break;
	default:
		option = new GenericEDNSOption(code);
		break;
	}
	option.optionFromWire(in);
	in.restoreActive(save);

	return option;
}

/**
 * Converts the wire format of an EDNS Option (including code and length) into
 * the type-specific format.
 * @return The option, in wire format.
 */
public static EDNSOption
fromWire(byte [] b) throws IOException {
	return fromWire(new DNSInput(b));
}

/**
 * Converts an EDNS Option (the type-specific option data only) into wire format.
 * @param out The output stream.
 */
abstract void
optionToWire(DNSOutput out);

/**
 * Converts an EDNS Option (including code and length) into wire format.
 * @param out The output stream.
 */
void
toWire(DNSOutput out) {
	out.writeU16(code);
	final int lengthPosition = out.current();
	out.writeU16(0); /* until we know better */
	optionToWire(out);
	final int length = out.current() - lengthPosition - 2;
	out.writeU16At(length, lengthPosition);
}

/**
 * Converts an EDNS Option (including code and length) into wire format.
 * @return The option, in wire format.
 */
public byte []
toWire() {
	final DNSOutput out = new DNSOutput();
	toWire(out);
	return out.toByteArray();
}

/**
 * Determines if two EDNS Options are identical.
 * @param arg The option to compare to
 * @return true if the options are equal, false otherwise.
 */
@Override
public boolean
equals(Object arg) {
	if (arg == null || !(arg instanceof EDNSOption))
		return false;
	final EDNSOption opt = (EDNSOption) arg;
	if (code != opt.code)
		return false;
	return Arrays.equals(getData(), opt.getData());
}

/**
 * Generates a hash code based on the EDNS Option's data.
 */
@Override
public int
hashCode() {
	final byte [] array = getData();
	int hashval = 0;
	for (int i = 0; i < array.length; i++)
		hashval += ((hashval << 3) + (array[i] & 0xFF));
	return hashval;
}

abstract String optionToString();

}
