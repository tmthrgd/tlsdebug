// Copyright 2017 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License that can be found in
// the LICENSE file.

package tlsdebug

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

var bufferPool = &sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// ClientHelloFunc represents a function to call after
// extracting the ClientHello message.
//
// conn is the underlying net.Conn that the ClientHello was
// extracted from. ch is the ClientHello message. err is
// any error that occurred while extracting the ClientHello.
//
// conn MUST NOT be written to or read from, doing so will
// cause the connection to fail. ch MUST NOT be modified,
// doing so MAY cause the connection to fail. ch MUST NOT be
// retained after the function returns as it will be reused.
type ClientHelloFunc func(conn net.Conn, ch []byte, err error)

// ClientHelloListener wraps a net.Listener and wraps each
// accepted net.Conn with ClientHelloConn.
func ClientHelloListener(ln net.Listener, fn ClientHelloFunc) net.Listener {
	return &clientHelloListener{ln, fn}
}

type clientHelloListener struct {
	net.Listener
	fn ClientHelloFunc
}

func (ln *clientHelloListener) Accept() (net.Conn, error) {
	c, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return ClientHelloConn(c, ln.fn), nil
}

// ClientHelloConn wraps a net.Conn, extracts the ClientHello
// and calls fn. It is transparent to the user of the
// net.Conn and is a does nothing after the ClientHello has
// been extracted.
func ClientHelloConn(c net.Conn, fn ClientHelloFunc) net.Conn {
	return &clientHelloConn{
		Conn: c,
		fn:   fn,
	}
}

type clientHelloConn struct {
	net.Conn
	fn ClientHelloFunc

	buf *bytes.Buffer

	doneCH bool
}

func (ch *clientHelloConn) Close() error {
	if ch.buf != nil {
		ch.buf.Reset()
		bufferPool.Put(ch.buf)
		ch.buf = nil
	}

	return ch.Conn.Close()
}

func (ch *clientHelloConn) Read(b []byte) (n int, err error) {
	n, err = ch.Conn.Read(b)
	if ch.doneCH || (err != nil && err != io.EOF) {
		return n, err
	}

	hb := b[:n]
	if ch.buf != nil {
		ch.buf.Write(b[:n])
		hb = ch.buf.Bytes()
	}

	hb, herr := handshakeRecord(hb)
	if herr == io.ErrUnexpectedEOF {
		if ch.buf != nil {
			// Continue buffering the
			// handshake and wait.
			return n, err
		}

		// The handshake record was not read in
		// a single call to Read. We buffer what
		// we have and wait.
		ch.buf = bufferPool.Get().(*bytes.Buffer)
		ch.buf.Grow(512 + 32)
		ch.buf.Write(b[:n])
		return n, err
	}

	ch.doneCH = true

	if herr == nil {
		hb, herr = parseHello(hb)
	}

	ch.fn(ch.Conn, hb, herr)

	if ch.buf != nil {
		ch.buf.Reset()
		bufferPool.Put(ch.buf)
		ch.buf = nil
	}

	return n, err
}

// Read one TLS record, which must be for the handshake
// protocol, from b.
func handshakeRecord(b []byte) ([]byte, error) {
	const headerSize = 1 + 2 + 2
	if len(b) < headerSize {
		return nil, io.ErrUnexpectedEOF
	}

	typ := b[0]
	vers := binary.BigEndian.Uint16(b[1:])
	length := binary.BigEndian.Uint16(b[3:])
	b = b[headerSize:]

	const typeHandshake = 22
	if typ != typeHandshake {
		// Taken from crypto/tls:
		//   No valid TLS record has a type of 0x80, however
		//   SSLv2 handshakes start with a uint16 length
		//   where the MSB is set and the first record is
		//   always < 256 bytes long. Therefore typ == 0x80
		//   strongly suggests an SSLv2 client.
		if typ == 0x80 {
			return nil, errors.New("unsupported SSLv2 handshake received")
		}

		return nil, errors.New("record type is not handshake")
	}

	const majorVersion = 3
	if vers>>8 != majorVersion {
		return nil, fmt.Errorf("record has unsupported version %04x", vers)
	}

	const maxRecordLength = 16384
	if length > maxRecordLength {
		return nil, errors.New("record length is greater than maximum allowed")
	}

	if int(length) > len(b) {
		return nil, io.ErrUnexpectedEOF
	}

	return b[:length], nil
}

// Parse a TLS handshake record as a ClientHello message.
func parseHello(b []byte) ([]byte, error) {
	const headerSize = 1 + 3
	if len(b) < headerSize {
		return nil, errors.New("handshake record is too short")
	}

	typ := b[0]

	var length uint32
	for _, v := range b[1:4] {
		length = (length << 8) | uint32(v)
	}

	b = b[headerSize:]

	const typeClientHello = 1
	if typ != typeClientHello {
		return nil, fmt.Errorf("handshake record (%d) is not ClientHello", typ)
	}

	if int(length) > len(b) {
		return nil, errors.New("handshake record has invalid length")
	}

	return b[:length], nil
}
