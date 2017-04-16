// Copyright 2017 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

package tlsdebug

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// TLSHandshakeFunc is a function to be called after a TLS handshake
// has been performed. It takes the underlying net.Conn, a
// *tls.ConnectionState and any error returned from
// (*tls.Conn).Handshake.
//
// conn MUST NOT be written to or read from, doing so will
// cause the connection to fail. cs will never be nil.
type TLSHandshakeFunc func(conn net.Conn, cs *tls.ConnectionState, err error)

// HTTPHandshakeListener wraps a given net.Listener. On calls to Accept
// it performs the TLS handshake and subsequently invokes fn.
//
// The *http.Server's ReadTimeout and WriteTimeout are used to cover
// the TLS handshake. This mirrors the standard timeout behaviour of
// (*http.Server).Serve.
//
// The returned net.Listener's Accept will panic if the net.Conn is not
// a *tls.Conn. ln should be a the return value of tls.NewListener.
func HTTPHandshakeListener(ln net.Listener, srv *http.Server, fn TLSHandshakeFunc) net.Listener {
	return &httpHandshakeListener{
		ln, fn,
		srv.ReadTimeout,
		srv.WriteTimeout,
	}
}

type httpHandshakeListener struct {
	net.Listener
	fn           TLSHandshakeFunc
	readTimeout  time.Duration
	writeTimeout time.Duration
}

func (ln *httpHandshakeListener) Accept() (net.Conn, error) {
	c, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}

	tc, ok := c.(*tls.Conn)
	if !ok {
		panic("tlsdebug.httpHandshakeListener: Accept did not return *tls.Conn")
	}

	if ln.readTimeout != 0 || ln.writeTimeout != 0 {
		now := time.Now()

		if ln.readTimeout != 0 {
			tc.SetReadDeadline(now.Add(ln.readTimeout))
		}

		if ln.writeTimeout != 0 {
			tc.SetWriteDeadline(now.Add(ln.writeTimeout))
		}
	}

	err = tc.Handshake()
	cs := tc.ConnectionState()
	ln.fn(c, &cs, err)
	return c, nil
}
