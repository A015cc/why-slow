package netsys

import (
	"net"
	"net/http"
	"time"
)

// DirectClient returns an HTTP client that ignores every proxy setting: the
// system proxy, HTTP_PROXY, HTTPS_PROXY and ALL_PROXY alike.
//
// This is not a nicety, it is the constraint the whole nat probe rests on.
// why-slow is routinely run on machines whose system proxy forwards to a remote
// VPS. If the public-IP lookup went through that proxy, the address reported
// would be the VPS's, and the diagnosis would not merely be wrong but backwards
// — it would report the datacenter as the user's ISP. Encoding the bypass here,
// once, is what keeps that mistake from being reintroduced per call site.
//
// Note the deliberate asymmetry: Probe and Proxy are both set explicitly to nil
// rather than left unset, because leaving Proxy unset yields http.ProxyFromEnvironment.
func DirectClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	tr := &http.Transport{
		Proxy: nil, // never consult the environment or the system configuration
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: time.Second,
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}
