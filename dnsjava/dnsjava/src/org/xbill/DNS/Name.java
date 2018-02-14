// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import java.text.*;
import java.util.Arrays;

/**
 * A representation of a domain name.  It may either be absolute (fully
 * qualified) or relative.
 *
 * @author Brian Wellington
 */

public class Name implements Comparable<Name>, Serializable {

private static final long serialVersionUID = -7257019940971525644L;

private static final int LABEL_NORMAL = 0;
private static final int LABEL_COMPRESSION = 0xC0;
private static final int LABEL_MASK = 0xC0;

/* The name data */
private final byte[] name;

/*
 * Effectively an 8 byte array, where the low order byte stores the number
 * of labels and the 7 higher order bytes store per-label offsets.
 */
private final long offsets;

/* Lazily computed hashcode. */
private int hashcode;

private static final byte [] emptyLabel = new byte[] {0};
private static final byte [] wildLabel = new byte[] {1, '*'};

/** The root name */
public static final Name root;

/** The root name */
public static final Name empty;

/** The maximum length of a Name */
private static final int MAXNAME = 255;

/** The maximum length of a label in a Name */
private static final int MAXLABEL = 63;

/** The maximum number of labels in a Name */
private static final int MAXLABELS = 128;

/** The maximum number of cached offsets */
private static final int MAXOFFSETS = 7;

/* Used for printing non-printable characters */
private static final DecimalFormat byteFormat = new DecimalFormat();

/* Used to efficiently convert bytes to lowercase */
private static final byte lowercase[] = new byte[256];

/* Used in wildcard names. */
private static final Name wild;

static {
	byteFormat.setMinimumIntegerDigits(3);

	for (int i = 0; i < 'A'; i++) {
		lowercase[i] = (byte)i;
	}
	for (int i = 'A'; i <= 'Z'; i++) {
		lowercase[i] = (byte)(i - 'A' + 'a');
	}
	for (int i = 'Z' + 1; i < lowercase.length; i++) {
		lowercase[i] = (byte)i;
	}

	NameBuilder nb;
	nb = new NameBuilder();
	nb.appendSafe(emptyLabel, 0, 1);
	root = nb.toName();

	empty = new Name(new byte[0], 0L);

	nb = new NameBuilder();
	nb.appendSafe(wildLabel, 0, 1);
	wild = nb.toName();
}

private static int lowercase(int b) {
	return lowercase[b & 0xff] & 0xff;
}

private Name(byte[] name, long offsets) {
	this.name = name;
	this.offsets = offsets;
}

private static final long
setoffset(long offsets, int n, int offset) {
	if (n < MAXOFFSETS) {
		final int shift = 8 * (7 - n);
		offsets &= (~(0xFFL << shift));
		offsets |= ((long)offset << shift);
	}
	return offsets;
}

private final int
offset(int n) {
	final int r;
	if (n == 0 && getlabels() == 0)
		r = 0;
	else {
		if (n < 0 || n >= getlabels())
			throw new IllegalArgumentException("label out of range");
		if (n < MAXOFFSETS) {
			final int shift = 8 * (7 - n);
			r = ((int)(offsets >>> shift) & 0xFF);
		} else {
			int pos = offset(MAXOFFSETS - 1);
			for (int i = MAXOFFSETS - 1; i < n; i++)
				pos += (name[pos] + 1);
			r = pos;
		}
	}
	return r;
}

private static final long
setlabels(long offsets, int labels) {
	offsets &= ~(0xFFL);
	offsets |= labels;
	return offsets;
}

private final int
getlabels() {
	return (int)offsets & 0xFF;
}

private static void
parseException(String str, String message) throws TextParseException {
	throw new TextParseException('\'' + str + "': " + message);
}

/**
 * Create a new name from a string and an origin.  This does not automatically
 * make the name absolute; it will be absolute if it has a trailing dot or an
 * absolute origin is appended.  This is identical to the constructor, except
 * that it will avoid creating new objects in some cases.
 * @param s The string to be converted
 * @param origin If the name is not absolute, the origin to be appended.
 * @throws TextParseException The name is invalid.
 */
public static Name
fromString(String s, Name origin) throws TextParseException {
	if (s.length() == 0)
		parseException(s, "empty name");
	else if (s.equals("@")) {
		if (origin == null)
			return empty;
		return origin;
	} else if (s.equals(".")) {
		return root;
	}
	final NameBuilder nb = new NameBuilder();
	int labelstart = -1;
	int pos = 1;
	final byte [] label = new byte[MAXLABEL + 1];
	boolean escaped = false;
	int digits = 0;
	int intval = 0;
	boolean absolute = false;
	for (int i = 0; i < s.length(); i++) {
		byte b = (byte) s.charAt(i);
		if (escaped) {
			if (b >= '0' && b <= '9' && digits < 3) {
				digits++;
				intval = intval * 10 + (b - '0');
				if (intval > 255)
					parseException(s, "bad escape");
				if (digits < 3)
					continue;
				b = (byte) intval;
			}
			else if (digits > 0 && digits < 3)
				parseException(s, "bad escape");
			if (pos > MAXLABEL)
				parseException(s, "label too long");
			labelstart = pos;
			label[pos++] = b;
			escaped = false;
		} else if (b == '\\') {
			escaped = true;
			digits = 0;
			intval = 0;
		} else if (b == '.') {
			if (labelstart == -1)
				parseException(s, "invalid empty label");
			label[0] = (byte)(pos - 1);
			nb.appendFromString(s, label, 0, 1);
			labelstart = -1;
			pos = 1;
		} else {
			if (labelstart == -1)
				labelstart = i;
			if (pos > MAXLABEL)
				parseException(s, "label too long");
			label[pos++] = b;
		}
	}
	if (digits > 0 && digits < 3)
		parseException(s, "bad escape");
	if (escaped)
		parseException(s, "bad escape");
	if (labelstart == -1) {
		nb.appendFromString(s, emptyLabel, 0, 1);
		absolute = true;
	} else {
		label[0] = (byte)(pos - 1);
		nb.appendFromString(s, label, 0, 1);
	}
	if (origin != null && !absolute)
		nb.appendFromString(s, origin.name, origin.offset(0),
				 origin.getlabels());
	return nb.toName();
}

/**
 * Create a new name from a string.  This does not automatically make the name
 * absolute; it will be absolute if it has a trailing dot.  This is identical
 * to the constructor, except that it will avoid creating new objects in some
 * cases.
 * @param s The string to be converted
 * @throws TextParseException The name is invalid.
 */
public static Name
fromString(String s) throws TextParseException {
	return fromString(s, null);
}

/**
 * Create a new name from a constant string.  This should only be used when
 the name is known to be good - that is, when it is constant.
 * @param s The string to be converted
 * @throws IllegalArgumentException The name is invalid.
 */
public static Name
fromConstantString(String s) {
	try {
		return fromString(s, null);
	}
	catch (TextParseException e) {
		throw new IllegalArgumentException("Invalid name '" + s + '\'');
	}
}

/**
 * Create a new name from DNS a wire format message
 * @param in A stream containing the DNS message which is currently
 * positioned at the start of the name to be read.
 */
public
Name(DNSInput in) throws WireParseException {
	int len, pos;
	boolean done = false;
	final byte[] label = new byte[MAXLABEL + 1];
	boolean savedState = false;
	final NameBuilder nb = new NameBuilder();

	while (!done) {
		len = in.readU8();
		switch (len & LABEL_MASK) {
		case LABEL_NORMAL:
			if (getlabels() >= MAXLABELS)
				throw new WireParseException("too many labels");
			if (len == 0) {
				nb.append(emptyLabel, 0, 1);
				done = true;
			} else {
				label[0] = (byte)len;
				in.readByteArray(label, 1, len);
				nb.append(label, 0, 1);
			}
			break;
		case LABEL_COMPRESSION:
			pos = in.readU8();
			pos += ((len & ~LABEL_MASK) << 8);
			if (Options.check(Options.Standard.verbosecompression))
				System.err.println("currently " + in.current() +
						   ", pointer to " + pos);

			if (pos >= in.current() - 2)
				throw new WireParseException("bad compression");
			if (!savedState) {
				in.save();
				savedState = true;
			}
			in.jump(pos);
			if (Options.check(Options.Standard.verbosecompression))
				System.err.println("current name '" + this +
						   "', seeking to " + pos);
			break;
		default:
			throw new WireParseException("bad label type");
		}
	}
	if (savedState) {
		in.restore();
	}
	name = nb.makeName();
	offsets = nb.makeOffsets();
}

/**
 * Create a new name from DNS wire format
 * @param b A byte array containing the wire format of the name.
 */
public
Name(byte [] b) throws IOException {
	this(new DNSInput(b));
}

/**
 * Create a new name by removing labels from the beginning of an existing Name
 * @param src An existing Name
 * @param n The number of labels to remove from the beginning in the copy
 */
public
Name(Name src, int n) {
	final int slabels = src.labels();
	if (n > slabels)
		throw new IllegalArgumentException("attempted to remove too " +
						   "many labels");
	name = src.name;
	long offsets;
	offsets = setlabels(0L, slabels - n);
	for (int i = 0; i < MAXOFFSETS && i < slabels - n; i++)
		offsets = setoffset(offsets, i, src.offset(i + n));
	this.offsets = offsets;
}

/**
 * Creates a new name by concatenating two existing names.
 * @param prefix The prefix name.
 * @param suffix The suffix name.
 * @return The concatenated name.
 * @throws NameTooLongException The name is too long.
 */
public static Name
concatenate(Name prefix, Name suffix) throws NameTooLongException {
	if (prefix.isAbsolute())
		return (prefix);
	final NameBuilder nb = new NameBuilder(prefix);
	nb.append(suffix.name, suffix.offset(0), suffix.getlabels());
	return nb.toName();
}

/**
 * If this name is a subdomain of origin, return a new name relative to
 * origin with the same value. Otherwise, return the existing name.
 * @param origin The origin to remove.
 * @return The possibly relativized name.
 */
public Name
relativize(Name origin) {
	if (origin == null || !subdomain(origin))
		return this;
	final int length = length() - origin.length();
	final int labels = labels() - origin.labels();
	final long offsets = setlabels(this.offsets, labels);
	final byte[] name = new byte[length];
	System.arraycopy(this.name, offset(0), name, 0, length);
	return new Name(name, offsets);
}

/**
 * Generates a new Name with the first n labels replaced by a wildcard
 * @return The wildcard name
 */
public Name
wild(int n) {
	if (n < 1)
		throw new IllegalArgumentException("must replace 1 or more " +
						   "labels");
	try {
		final NameBuilder nb = new NameBuilder(wild);
		nb.append(name, offset(n), getlabels() - n);
		return nb.toName();
	}
	catch (NameTooLongException e) {
		throw new IllegalStateException
					("Name.wild: concatenate failed");
	}
}

/**
 * Returns a canonicalized version of the Name (all lowercase).  This may be
 * the same name, if the input Name is already canonical.
 */
public Name
canonicalize() {
	boolean canonical = true;
	for (int i = 0; i < name.length; i++) {
		int b = name[i] & 0xff;
		if (lowercase(b) != b) {
			canonical = false;
			break;
		}
	}
	if (canonical)
		return this;

	final NameBuilder nb = new NameBuilder();
	nb.appendSafe(name, offset(0), getlabels());
	final byte[] arr = nb.name;
	for (int i = 0; i < nb.length; i++)
		arr[i] = (byte) lowercase(arr[i]);

	return nb.toName();
}

/**
 * Generates a new Name to be used when following a DNAME.
 * @param dname The DNAME record to follow.
 * @return The constructed name.
 * @throws NameTooLongException The resulting name is too long.
 */
public Name
fromDNAME(DNAMERecord dname) throws NameTooLongException {
	final Name dnameowner = dname.getName();
	final Name dnametarget = dname.getTarget();
	if (!subdomain(dnameowner))
		return null;

	final int plabels = labels() - dnameowner.labels();
	final int plength = length() - dnameowner.length();
	final int pstart = offset(0);

	final int dlabels = dnametarget.labels();
	final int dlength = dnametarget.length();

	if (plength + dlength > MAXNAME)
		throw new NameTooLongException();

	final NameBuilder nb = new NameBuilder();
	nb.labels = plabels + dlabels;
	nb.length = plength + dlength;
	System.arraycopy(name, pstart, nb.name, 0, plength);
	System.arraycopy(dnametarget.name, 0, nb.name, plength, dlength);

	for (int i = 0, pos = 0; i < MAXOFFSETS && i < plabels + dlabels; i++) {
		nb.setOffset(i, pos);
		pos += (nb.name[pos] + 1);
	}
	return nb.toName();
}

/**
 * Is this name a wildcard?
 */
public boolean
isWild() {
	if (labels() == 0)
		return false;
	return (name[0] == 1 && name[1] == '*');
}

/**
 * Is this name absolute?
 */
public boolean
isAbsolute() {
	final int nlabels = labels();
	if (nlabels == 0)
		return false;
    return name[offset(nlabels - 1)] == 0;
}

/**
 * The length of the name.
 */
public int
length() {
	if (getlabels() == 0)
		return 0;
	return name.length - offset(0);
}

/**
 * The number of labels in the name.
 */
public int
labels() {
	return getlabels();
}

/**
 * Is the current Name a subdomain of the specified name?
 */
public boolean
subdomain(Name domain) {
	final int labels = labels();
	final int dlabels = domain.labels();
	if (dlabels > labels)
		return false;
	if (dlabels == labels)
		return equals(domain);
	return domain.equals(name, offset(labels - dlabels));
}

private static String
byteString(byte [] array, int pos) {
	final StringBuilder sb = new StringBuilder();
	final int len = array[pos++];
	for (int i = pos; i < pos + len; i++) {
		int b = array[i] & 0xFF;
		if (b <= 0x20 || b >= 0x7f) {
			sb.append('\\');
			sb.append(byteFormat.format(b));
		}
		else if ("\"().;\\@$".indexOf(b) != -1)
		{
			sb.append('\\');
			sb.append((char)b);
		}
		else
			sb.append((char)b);
	}
	return sb.toString();
}

/**
 * Convert a Name to a String
 * @param omitFinalDot If true, and the name is absolute, omit the final dot.
 * @return The representation of this name as a (printable) String.
 */
public String
toString(boolean omitFinalDot) {
	final int labels = labels();
	if (labels == 0)
		return "@";
	else if (labels == 1 && name[offset(0)] == 0)
		return ".";
	final StringBuilder sb = new StringBuilder();
	for (int i = 0, pos = offset(0); i < labels; i++) {
		int len = name[pos];
		if (len > MAXLABEL)
			throw new IllegalStateException("invalid label");
		if (len == 0) {
			if (!omitFinalDot)
				sb.append('.');
			break;
		}
		if (i > 0)
			sb.append('.');
		sb.append(byteString(name, pos));
		pos += (1 + len);
	}
	return sb.toString();
}

/**
 * Convert a Name to a String
 * @return The representation of this name as a (printable) String.
 */
@Override
public String
toString() {
	return toString(false);
}

/**
 * Retrieve the nth label of a Name.  This makes a copy of the label; changing
 * this does not change the Name.
 * @param n The label to be retrieved.  The first label is 0.
 */
public byte []
getLabel(int n) {
	final int pos = offset(n);
	final int len = name[pos] + 1;
	final byte[] label = new byte[len];
	System.arraycopy(name, pos, label, 0, len);
	return label;
}

/**
 * Convert the nth label in a Name to a String
 * @param n The label to be converted to a (printable) String.  The first
 * label is 0.
 */
public String
getLabelString(int n) {
	final int pos = offset(n);
	return byteString(name, pos);
}

/**
 * Emit a Name in DNS wire format
 * @param out The output stream containing the DNS message.
 * @param c The compression context, or null of no compression is desired.
 * @throws IllegalArgumentException The name is not absolute.
 */
public void
toWire(DNSOutput out, Compression c) {
	if (!isAbsolute())
		throw new IllegalArgumentException("toWire() called on " +
						   "non-absolute name");

	final int labels = labels();
	boolean z = true;
	for (int i = 0; i < labels - 1 && z; i++) {
		Name tname;
		if (i == 0)
			tname = this;
		else
			tname = new Name(this, i);
		int pos = -1;
		if (c != null)
			pos = c.get(tname);
		if (pos >= 0) {
			pos |= (LABEL_MASK << 8);
			out.writeU16(pos);
			z = false;
		} else {
			if (c != null)
				c.add(out.current(), tname);
			int off = offset(i);
			out.writeByteArray(name, off, name[off] + 1);
		}
	}
	if (z)
		out.writeU8(0);
}

/**
 * Emit a Name in DNS wire format
 * @throws IllegalArgumentException The name is not absolute.
 */
public byte []
toWire() {
	final DNSOutput out = new DNSOutput();
	toWire(out, null);
	return out.toByteArray();
}

/**
 * Emit a Name in canonical DNS wire format (all lowercase)
 * @param out The output stream to which the message is written.
 */
public void
toWireCanonical(DNSOutput out) {
	final byte [] b = toWireCanonical();
	out.writeByteArray(b);
}

/**
 * Emit a Name in canonical DNS wire format (all lowercase)
 * @return The canonical form of the name.
 */
public byte []
toWireCanonical() {
	final int labels = labels();
	if (labels == 0)
		return (new byte[0]);
	final byte [] b = new byte[name.length - offset(0)];
	for (int i = 0, spos = offset(0), dpos = 0; i < labels; i++) {
		int len = name[spos];
		if (len > MAXLABEL)
			throw new IllegalStateException("invalid label");
		b[dpos++] = name[spos++];
		for (int j = 0; j < len; j++)
			b[dpos++] = (byte) lowercase(name[spos++]);
	}
	return b;
}

/**
 * Emit a Name in DNS wire format
 * @param out The output stream containing the DNS message.
 * @param c The compression context, or null of no compression is desired.
 * @param canonical If true, emit the name in canonicalized form
 * (all lowercase).
 * @throws IllegalArgumentException The name is not absolute.
 */
public void
toWire(DNSOutput out, Compression c, boolean canonical) {
	if (canonical)
		toWireCanonical(out);
	else
		toWire(out, c);
}

private final boolean
equals(byte [] b, int bpos) {
	final int labels = labels();
	for (int i = 0, pos = offset(0); i < labels; i++) {
		if (name[pos] != b[bpos])
			return false;
		int len = name[pos++];
		bpos++;
		if (len > MAXLABEL)
			throw new IllegalStateException("invalid label");
		for (int j = 0; j < len; j++)
			if (lowercase(name[pos++]) != lowercase(b[bpos++]))
				return false;
	}
	return true;
}

/**
 * Are these two Names equivalent?
 */
@Override
public boolean
equals(Object arg) {
	if (arg == this)
		return true;
	if (arg == null || !(arg instanceof Name))
		return false;
	final Name d = (Name) arg;
	if (d.hashCode() != hashCode())
		return false;
	if (d.labels() != labels())
		return false;
	return equals(d.name, d.offset(0));
}

/**
 * Computes a hashcode based on the value
 */
@Override
public int
hashCode() {
	int h = hashcode;
	if (h == 0) {
		for (int i = offset(0); i < name.length; i++)
			h += ((h << 3) + lowercase(name[i]));
		hashcode = h;
	}
	return h;
}

/**
 * Compares this Name to another Object.
 * @param o The Object to be compared.
 * @return The value 0 if the argument is a name equivalent to this name;
 * a value less than 0 if the argument is less than this name in the canonical
 * ordering, and a value greater than 0 if the argument is greater than this
 * name in the canonical ordering.
 * @throws ClassCastException if the argument is not a Name.
 */
public int
compareTo(Name arg) {
	if (this == arg)
		return (0);

	final int labels = labels();
	final int alabels = arg.labels();
	final int compares = labels > alabels ? alabels : labels;

	for (int i = 1; i <= compares; i++) {
		int start = offset(labels - i);
		int astart = arg.offset(alabels - i);
		int length = name[start];
		int alength = arg.name[astart];
		for (int j = 0; j < length && j < alength; j++) {
			int n = lowercase(name[j + start + 1]) -
				lowercase(arg.name[j + astart + 1]);
			if (n != 0)
				return (n);
		}
		if (length != alength)
			return (length - alength);
	}
	return (labels - alabels);
}

private static class NameBuilder {
	private final byte[] name;
	private int labels;
	private final byte[] offset;
	private int length;

	private NameBuilder() {
		name = new byte[MAXNAME];
		offset = new byte[MAXOFFSETS];
	}

	private NameBuilder(Name src) {
		this();
		if (src.name != null && src.name.length > 0 && src.length() > 0) {
			try {
				append(src.name, 0, src.getlabels());
			} catch (NameTooLongException e) {
				throw new AssertionError(e);
			}
		}
	}

	private int getOffset(int i) {
		return offset[i] & 0xff;
	}

	private void setOffset(int i, int pos) {
		offset[i] = (byte) pos;
	}

	private long makeOffsets() {
		long offsets = Name.setlabels(0L, labels);
		for (int i = 0; i < Name.MAXOFFSETS; i++) {
			offsets = Name.setoffset(offsets, i, getOffset(i));
		}
		return offsets;
	}

	private byte[] makeName() {
		return Arrays.copyOf(name, length);
	}

	private Name toName() {
		return new Name(makeName(), makeOffsets());
	}

	private void
	append(byte [] array, int start, int n) throws NameTooLongException {
		final int length = this.length;
		int alength = 0;
		for (int i = 0, pos = start; i < n; i++) {
			int len = array[pos];
			if (len > MAXLABEL)
				throw new IllegalStateException("invalid label");
			len++;
			pos += len;
			alength += len;
		}
		final int newlength = length + alength;
		if (newlength > MAXNAME)
			throw new NameTooLongException();
		final int labels = this.labels;
		final int newlabels = labels + n;
		if (newlabels > MAXLABELS)
			throw new IllegalStateException("too many labels");
		final byte[] name = this.name;
		System.arraycopy(array, start, name, length, alength);
		for (int i = 0, pos = length, j = labels; i < n && j < MAXOFFSETS; i++, j++) {
			setOffset(j, pos);
			pos += (name[pos] + 1);
		}
		this.labels = newlabels;
		this.length = newlength;
	}

	private void
	appendFromString(String fullName, byte[] array, int start, int n)
	throws TextParseException
	{
		try {
			append(array, start, n);
		}
		catch (NameTooLongException e) {
			parseException(fullName, "Name too long");
		}
	}

	private void
	appendSafe(byte[] array, int start, int n) {
		try {
			append(array, start, n);
		}
		catch (NameTooLongException e) {
			throw new AssertionError(e);
		}
	}
}
}

