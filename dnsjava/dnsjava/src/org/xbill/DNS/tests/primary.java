// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS.tests;

import java.util.*;
import org.xbill.DNS.*;

public class primary {

private static void
usage() {
	System.out.println("usage: primary [-t] [-a | -i] origin file");
	System.exit(1);
}

public static void
main(String [] args) throws Exception {
	boolean time = false;
	boolean axfr = false;
	boolean iterator = false;
	int arg = 0;

	if (args.length < 2)
		usage();

	while (args.length - arg > 2) {
		if (args[0].equals("-t"))
			time = true;
		else if (args[0].equals("-a"))
			axfr = true;
		else if (args[0].equals("-i"))
			iterator = true;
		arg++;
	}

	final Name origin = Name.fromString(args[arg++], Name.root);
	final String file = args[arg++];

	final long start = System.currentTimeMillis();
	final Zone zone = new Zone(origin, file);
	final long end = System.currentTimeMillis();
	if (axfr) {
		final Iterator<RRset> it = zone.AXFR();
		while (it.hasNext()) {
			System.out.println(it.next());
		}
	} else if (iterator) {
		final Iterator<RRset> it = zone.iterator();
		while (it.hasNext()) {
			System.out.println(it.next());
		}
	} else {
		System.out.println(zone);
	}
	if (time)
		System.out.println("; Load time: " + (end - start) + " ms");
}

}
