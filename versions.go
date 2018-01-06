// Copyright 2017 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License that can be found in
// the LICENSE file.

package tlsdebug

import "crypto/tls"

const (
	tls13_VersionTLS13        = 0x0304
	tls13_VersionTLS13Draft18 = 0x7f00 | 18
	tls13_VersionTLS13Draft22 = 0x7f00 | 22
)

// VersionName returns a human readable name associated
// with a given TLS version code.
//
// It returns an empty string if the version is unknown.
func VersionName(vers uint16) string {
	return versionToName[vers]
}

var versionToName = map[uint16]string{
	// XXX: keep in sync with crypto/tls and cloudflare/tls-tris.
	tls.VersionSSL30:          "SSL 3.0",
	tls.VersionTLS10:          "TLS 1.0",
	tls.VersionTLS11:          "TLS 1.1",
	tls.VersionTLS12:          "TLS 1.2",
	tls13_VersionTLS13:        "TLS 1.3",
	tls13_VersionTLS13Draft18: "TLS 1.3 (draft 18)",
	tls13_VersionTLS13Draft22: "TLS 1.3 (draft 22)",
}
