package org.xbill.DNS;

import java.net.InetAddress;

public abstract class AddressRecordBase extends Record {

	AddressRecordBase() {}

	public AddressRecordBase(Name name, int type, int dclass, long ttl) {
		super(name, type, dclass, ttl);
	}

	public abstract InetAddress getAddress();

}
