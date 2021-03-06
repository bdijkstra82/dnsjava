// Copyright (c) 2005 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;

final class TCPClient extends Client {

public
TCPClient(long endTime) throws IOException {
	super(SocketChannel.open(), endTime);
}

@SuppressWarnings("resource")
void
bind(SocketAddress addr) throws IOException {
	final SocketChannel channel = (SocketChannel) key.channel();
	channel.socket().bind(addr);
}

@SuppressWarnings("resource")
void
connect(SocketAddress addr) throws IOException {
	final SocketChannel channel = (SocketChannel) key.channel();
	if (channel.connect(addr))
		return;
	key.interestOps(SelectionKey.OP_CONNECT);
	try {
		while (!channel.finishConnect()) {
			if (!key.isConnectable())
				blockUntil(key, endTime);
		}
	}
	finally {
		if (key.isValid())
			key.interestOps(0);
	}
}

@SuppressWarnings("resource")
void
send(byte [] data) throws IOException {
	final SocketChannel channel = (SocketChannel) key.channel();
	verboseLog("TCP write", channel.socket().getLocalSocketAddress(),
		   channel.socket().getRemoteSocketAddress(), data);
	final byte [] lengthArray = new byte[2];
	lengthArray[0] = (byte)(data.length >>> 8);
	lengthArray[1] = (byte)(data.length & 0xFF);
	final ByteBuffer [] buffers = new ByteBuffer[2];
	buffers[0] = ByteBuffer.wrap(lengthArray);
	buffers[1] = ByteBuffer.wrap(data);
	int nsent = 0;
	key.interestOps(SelectionKey.OP_WRITE);
	try {
		while (nsent < data.length + 2) {
			if (key.isWritable()) {
				long n = channel.write(buffers);
				if (n < 0)
					throw new EOFException();
				nsent += (int) n;
				if (nsent < data.length + 2 &&
				    System.currentTimeMillis() > endTime)
					throw new SocketTimeoutException();
			} else
				blockUntil(key, endTime);
		}
	}
	finally {
		if (key.isValid())
			key.interestOps(0);
	}
}

@SuppressWarnings("resource")
private byte []
_recv(int length) throws IOException {
	final SocketChannel channel = (SocketChannel) key.channel();
	int nrecvd = 0;
	final byte [] data = new byte[length];
	final ByteBuffer buffer = ByteBuffer.wrap(data);
	key.interestOps(SelectionKey.OP_READ);
	try {
		while (nrecvd < length) {
			if (key.isReadable()) {
				long n = channel.read(buffer);
				if (n < 0)
					throw new EOFException();
				nrecvd += (int) n;
				if (nrecvd < length &&
				    System.currentTimeMillis() > endTime)
					throw new SocketTimeoutException();
			} else
				blockUntil(key, endTime);
		}
	}
	finally {
		if (key.isValid())
			key.interestOps(0);
	}
	return data;
}

@SuppressWarnings("resource")
byte []
recv() throws IOException {
	final byte [] buf = _recv(2);
	final int length = ((buf[0] & 0xFF) << 8) + (buf[1] & 0xFF);
	final byte [] data = _recv(length);
	final SocketChannel channel = (SocketChannel) key.channel();
	verboseLog("TCP read", channel.socket().getLocalSocketAddress(),
		   channel.socket().getRemoteSocketAddress(), data);
	return data;
}

static byte []
sendrecv(SocketAddress local, SocketAddress remote, byte [] data, long endTime)
throws IOException
{
	final TCPClient client = new TCPClient(endTime);
	try {
		if (local != null)
			client.bind(local);
		client.connect(remote);
		client.send(data);
		return client.recv();
	}
	finally {
		client.cleanup();
	}
}

static byte []
sendrecv(SocketAddress addr, byte [] data, long endTime) throws IOException {
	return sendrecv(null, addr, data, endTime);
}

}
