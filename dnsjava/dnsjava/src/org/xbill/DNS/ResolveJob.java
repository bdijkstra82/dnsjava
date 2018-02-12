// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * A special-purpose thread used by Resolvers (both SimpleResolver and
 * ExtendedResolver) to perform asynchronous queries.
 *
 * @author Brian Wellington
 */

class ResolveJob implements Runnable {

private final Message query;
private final Object id;
private final ResolverListener listener;
private final Resolver res;

/** Creates a new ResolveThread */
public
ResolveJob(Resolver res, Message query, Object id,
	      ResolverListener listener)
{
	this.res = res;
	this.query = query;
	this.id = id;
	this.listener = listener;
}


/**
 * Performs the query, and executes the callback.
 */
public void
run() {
	try {
		final Message response = res.send(query);
		listener.receiveMessage(id, response);
	}
	catch (Exception e) {
		listener.handleException(id, e);
	}
}

}
