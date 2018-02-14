// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS.utils;

import java.io.*;

/**
 * Routines for converting between Strings of hex-encoded data and arrays of
 * binary data.  This is not actually used by DNS.
 *
 * @author Brian Wellington
 */

public class base16 {

private static final String Base16 = "0123456789ABCDEF";

private
base16() {}

/**
 * Convert binary data to a hex-encoded String
 * @param b An array containing binary data
 * @return A String containing the encoded data
 */
public static String
toString(byte [] b) {
	final char[] ca = new char[b.length * 2];

	for (int i = 0, j = 0; i < b.length; i++) {
		int value = b[i] & 0xFF;
		int high = value >> 4;
		int low = value & 0xF;
		ca[j++] = Base16.charAt(high);
		ca[j++] = Base16.charAt(low);
	}
	return new String(ca);
}

private static int decode(char c) {
	int v;
	if (c >= '0' && c <= '9')
		v = c - '0';
	else if (c >= 'A' && c <= 'F')
		v = c - 'A' + 10;
	else if (c >= 'a' && c <= 'f')
		v = c - 'a' + 10;
	else
		v = -1;
	return v;
}

/**
 * Convert a hex-encoded String to binary data
 * @param str A String containing the encoded data
 * @return An array containing the binary data, or null if the string is invalid
 */
public static byte []
fromString(String str) {
	final ByteArrayOutputStream bs = new ByteArrayOutputStream(str.length() / 2);

	int n = 0, high = -1, low;
	for (int i = 0; i < str.length() && n >= 0; i++) {
		char ch = str.charAt(i);
		if (!Character.isWhitespace(ch)) {
			int b = decode(ch);
			if (b < 0)
				n = -1;
			else {
				if (n == 0)
					high = b;
				else {
					low = b;
					bs.write((high << 4) | low);
				}
				n = 1 - n;
			}
		}
	}
	return (n == 0) ? bs.toByteArray() : null;
}

}
