// Command dns-oracle queries a DNS server using AdGuard's own dnsproxy client,
// so an adguardlite listener can be checked against the exact client the Go
// implementation uses rather than a hand-rolled one.
//
// The certificate is verified normally; --ca adds a root so a self-signed
// certificate can be trusted without touching the system trust store.
//
//	dns-oracle --upstream tls://127.0.0.1:853 --ca cert.pem --name example.com
package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
)

func main() {
	addr := flag.String("upstream", "", "the upstream to query, e.g. tls://127.0.0.1:853")
	ca := flag.String("ca", "", "a PEM file holding an additional trusted root")
	name := flag.String("name", "example.com", "the name to look up")
	qtype := flag.String("type", "A", "the query type")
	bootstrap := flag.String("bootstrap", "", "a plain resolver for the upstream's hostname")
	timeout := flag.Duration("timeout", 10*time.Second, "how long to wait")
	flag.Parse()

	if *addr == "" {
		fmt.Fprintln(os.Stderr, "usage: dns-oracle --upstream <addr> [--ca cert.pem] --name <name>")
		os.Exit(2)
	}

	opts := &upstream.Options{
		Logger:  slog.New(slog.DiscardHandler),
		Timeout: *timeout,
	}

	// Trust the given root in addition to the system ones, so a self-signed
	// certificate can be verified rather than skipped.
	if *ca != "" {
		pem, err := os.ReadFile(*ca)
		if err != nil {
			fail("reading the ca file: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			fail("the ca file holds no certificate")
		}
		opts.RootCAs = pool
	}

	if *bootstrap != "" {
		ap, err := netip.ParseAddrPort(*bootstrap)
		if err != nil {
			fail("parsing the bootstrap address: %v", err)
		}
		r, err := upstream.NewUpstreamResolver(ap.String(), opts)
		if err != nil {
			fail("building the bootstrap resolver: %v", err)
		}
		opts.Bootstrap = upstream.NewCachingResolver(r)
	}

	u, err := upstream.AddressToUpstream(*addr, opts)
	if err != nil {
		fail("parsing the upstream: %v", err)
	}
	defer func() { _ = u.Close() }()

	qt, ok := dns.StringToType[strings.ToUpper(*qtype)]
	if !ok {
		fail("unknown query type %q", *qtype)
	}

	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn(*name), qt)
	req.RecursionDesired = true

	resp, err := u.Exchange(req)
	if err != nil {
		fail("exchange failed: %v", err)
	}

	fmt.Printf("upstream=%s rcode=%s answers=%d\n",
		u.Address(), dns.RcodeToString[resp.Rcode], len(resp.Answer))
	for _, rr := range resp.Answer {
		fmt.Printf("  %s\n", rr.String())
	}
}

// fail reports a problem and exits non-zero.
func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
