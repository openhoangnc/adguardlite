# Encryption

**Settings → Encryption settings** turns on TLS. One certificate and one key
serve four listeners:

| Protocol | Port | Transport |
|---|---|---|
| Web interface over HTTPS | `tls.port_https` (443) | TCP |
| DNS-over-HTTPS | `tls.port_https` (443) | TCP, and UDP for HTTP/3 |
| DNS-over-TLS | `tls.port_dns_over_tls` (853) | TCP |
| DNS-over-QUIC | `tls.port_dns_over_quic` (853) | UDP |

DNSCrypt is not implemented and `tls.port_dnscrypt` is ignored.

## What you need

- **A certificate chain**, PEM, leaf first, then any intermediates. Pasted into
  the form or read from `tls.certificate_path`.
- **A private key**, PEM. RSA, ECDSA and Ed25519 are all accepted, in PKCS#1,
  SEC1 or PKCS#8 encoding. Pasted into the form or read from
  `tls.private_key_path`.
- **A server name** in `tls.server_name`, matching the certificate. Clients
  verify it, and it is also what makes [ClientIDs over DoT and
  DoQ](clients.md#clientid) work.

The form reports what it parsed — subject, validity window, whether the chain
and the key belong together — before you save, so a mismatch is caught without
restarting anything.

## Reloading

The listeners hold the certificate behind a shared slot, so replacing one takes
effect on the **next handshake**. No restart, and connections already open are
not disturbed.

Two things replace it:

- **Saving one** through Settings → Encryption settings, which installs it at
  once.
- **Rewriting the files.** When `tls.certificate_path` or
  `tls.private_key_path` is set, the files are compared with what is being
  served once a minute, and a changed pair is installed. This is what makes an
  ACME client's renewal reach the listeners: it rewrites the files on its own
  schedule and has no way to tell the server, and nothing in the configuration
  moves when it does.

A renewal that is caught halfway through — the new certificate beside the old
key — does not replace anything: the pair has to parse and belong together
first, and the check a minute later finds it whole. The same goes for a file
that is briefly missing. In both cases the certificate in use keeps being
served, and the log says what it saw.

A certificate with less than a week to run and nothing renewing it is reported
hourly, and an expired one as an error. Neither can be fixed from here — by
that point whatever was meant to renew it has stopped — but it is the last
chance to act before clients start refusing to connect.

Listener **ports** are read at startup. Changing one needs a restart.

## Getting a certificate

Any certificate works; nothing here talks to a CA. The two usual routes:

**Let's Encrypt, for a name that resolves publicly.** Use your preferred ACME
client and point `tls.certificate_path` and `tls.private_key_path` at what it
writes. A renewal is then picked up within a minute and served on the next
handshake, without touching the configuration and without a restart.

```yaml
tls:
  enabled: true
  server_name: dns.example.org
  certificate_path: /etc/letsencrypt/live/dns.example.org/fullchain.pem
  private_key_path: /etc/letsencrypt/live/dns.example.org/privkey.pem
```

For ClientIDs over DoT or DoQ the certificate also needs `*.dns.example.org`,
which means a DNS-01 challenge.

**Your own CA, for a name that does not.** Issue a certificate for the server
name, and install the CA certificate on every client that will use it.
Self-signed certificates that no client trusts will fail to connect rather than
warn, because DNS clients have nowhere to show a warning.

## Serving DoH without TLS

`http.doh.insecure_enabled` serves DNS-over-HTTPS over **plain HTTP**. It
exists for one case: a reverse proxy in front that terminates TLS itself. With
it off — the default — the DoH route answers only on the encrypted listener, so
an operator cannot expose queries in the clear by accident.

## Checking it works

```bash
# DNS-over-TLS
kdig -d @dns.example.org +tls-ca +tls-host=dns.example.org example.org

# DNS-over-HTTPS
curl -sS -H 'accept: application/dns-message' \
  'https://dns.example.org/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDb3JnAAABAAE'
```

A failure to verify is a certificate problem, not a DNS one: check that the
chain is complete and that the name you connected to is in it.
