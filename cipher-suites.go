// Copyright 2017 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License that can be found in
// the LICENSE file.

package tlsdebug

import "crypto/tls"

const (
	// TLS 1.3+ cipher suites.
	tls13_TLS_AES_128_GCM_SHA256       uint16 = 0x1301
	tls13_TLS_AES_256_GCM_SHA384       uint16 = 0x1302
	tls13_TLS_CHACHA20_POLY1305_SHA256 uint16 = 0x1303
)

const (
	// suiteECDH indicates that the cipher suite involves elliptic curve
	// Diffie-Hellman.
	suiteECDHE = 1 << iota
	// suiteECDSA indicates that the cipher suite involves an ECDSA
	// signature. If this is not set then the cipher suite is RSA based.
	suiteECDSA
	// suiteTLS12 indicates that the cipher suite should only be advertised
	// and accepted when using TLS 1.2.
	suiteTLS12
	// suiteTLS13 indicates that the ones and only cipher suites to be
	// advertised and accepted when using TLS 1.3.
	suiteTLS13
)

// CipherSuite represents a TLS cipher suite.
type CipherSuite struct {
	// flags is a bitmask of the suite* values, above.
	flags int
	name  string
}

var cipherSuites = map[uint16]*CipherSuite{
	// XXX: keep in sync with crypto/tls and cloudflare/tls-tris.
	tls13_TLS_CHACHA20_POLY1305_SHA256:          {suiteTLS13, "TLS_CHACHA20_POLY1305_SHA256"},
	tls13_TLS_AES_128_GCM_SHA256:                {suiteTLS13, "TLS_AES_128_GCM_SHA256"},
	tls13_TLS_AES_256_GCM_SHA384:                {suiteTLS13, "TLS_AES_256_GCM_SHA384"},
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:    {suiteECDHE | suiteTLS12, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"},
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:  {suiteECDHE | suiteECDSA | suiteTLS12, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"},
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   {suiteECDHE | suiteTLS12, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: {suiteECDHE | suiteECDSA | suiteTLS12, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   {suiteECDHE | suiteTLS12, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: {suiteECDHE | suiteECDSA | suiteTLS12, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:   {suiteECDHE | suiteTLS12, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"},
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:      {suiteECDHE, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"},
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: {suiteECDHE | suiteECDSA | suiteTLS12, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"},
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:    {suiteECDHE | suiteECDSA, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"},
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:      {suiteECDHE, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"},
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:    {suiteECDHE | suiteECDSA, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"},
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256:         {suiteTLS12, "TLS_RSA_WITH_AES_128_GCM_SHA256"},
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384:         {suiteTLS12, "TLS_RSA_WITH_AES_256_GCM_SHA384"},
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256:         {suiteTLS12, "TLS_RSA_WITH_AES_128_CBC_SHA256"},
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:            {0, "TLS_RSA_WITH_AES_128_CBC_SHA"},
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:            {0, "TLS_RSA_WITH_AES_256_CBC_SHA"},
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:     {suiteECDHE, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"},
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           {0, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
	tls.TLS_RSA_WITH_RC4_128_SHA:                {0, "TLS_RSA_WITH_RC4_128_SHA"},
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          {suiteECDHE, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"},
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:        {suiteECDHE | suiteECDSA, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"},
}

// CipherSuiteByID returns a CipherSuite that corresponds
// to a given id or nil if the cipher suite is unknown.
func CipherSuiteByID(id uint16) *CipherSuite {
	return cipherSuites[id]
}

// Name returns the name of the cipher suite.
//
// It returns an empty string if cs is nil.
func (cs *CipherSuite) Name() string {
	if cs == nil {
		return ""
	}

	return cs.name
}

// ECDHE returns true if the cipher suite uses an ECDHE key agreement.
//
// It returns false if cs is nil.
func (cs *CipherSuite) ECDHE() bool {
	return cs != nil && cs.flags&(suiteECDHE|suiteTLS13) == suiteECDHE
}

// RSA returns true if the cipher suite is RSA based.
//
// It returns false if cs is nil.
func (cs *CipherSuite) RSA() bool {
	return cs != nil && cs.flags&(suiteECDSA|suiteTLS13) == 0
}

// ECDSA returns true if the cipher suite is ECDSA based.
//
// It returns false if cs is nil.
func (cs *CipherSuite) ECDSA() bool {
	return cs != nil && cs.flags&(suiteECDSA|suiteTLS13) == suiteECDSA
}

// TLS12 returns true if the cipher suite is TLS 1.2 only.
//
// It returns false if cs is nil.
func (cs *CipherSuite) TLS12() bool {
	return cs != nil && cs.flags&suiteTLS12 != 0
}

// TLS13 returns true if the cipher suite is TLS 1.3 only.
//
// It returns false if cs is nil.
func (cs *CipherSuite) TLS13() bool {
	return cs != nil && cs.flags&suiteTLS13 != 0
}
