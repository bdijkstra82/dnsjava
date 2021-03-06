// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * DNS Name Compression object.
 * @see Message
 * @see Name
 *
 * @author Brian Wellington
 */

public class Compression {

private static class Entry {
	final Name name;
	final int pos;
	final Entry next;
	public Entry(Name name, int pos, Entry next) {
		this.name = name;
		this.pos = pos;
		this.next = next;
	}
}

private static final int TABLE_SIZE = 17;
private static final int MAX_POINTER = 0x3FFF;
private final Entry [] table;
private final boolean verbose = Options.check(Options.Standard.verbosecompression);

/**
 * Creates a new Compression object.
 */
public
Compression() {
	table = new Entry[TABLE_SIZE];
}

private static int getRow(Name name) {
	final int row = (name.hashCode() & 0x7FFFFFFF) % TABLE_SIZE;
	return row;
}

/**
 * Adds a compression entry mapping a name to a position in a message.
 * @param pos The position at which the name is added.
 * @param name The name being added to the message.
 */
public void
add(int pos, Name name) {
	if (pos > MAX_POINTER)
		return;
	final int row = getRow(name);
	final Entry entry = new Entry(name, pos, table[row]);
	table[row] = entry;
	if (verbose)
		System.err.println("Adding " + name + " at " + pos);
}

/**
 * Retrieves the position of the given name, if it has been previously
 * included in the message.
 * @param name The name to find in the compression table.
 * @return The position of the name, or -1 if not found.
 */
public int
get(Name name) {
	final int row = getRow(name);
	int pos = -1;
	for (Entry entry = table[row]; pos == -1 && entry != null; entry = entry.next) {
		if (entry.name.equals(name))
			pos = entry.pos;
	}
	if (verbose)
		System.err.println("Looking for " + name + ", found " + pos);
	return pos;
}

}
