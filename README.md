# kmip-ruby

[![CI](https://github.com/cyphera-labs/kmip-ruby/actions/workflows/ci.yml/badge.svg)](https://github.com/cyphera-labs/kmip-ruby/actions/workflows/ci.yml)
[![Security](https://github.com/cyphera-labs/kmip-ruby/actions/workflows/codeql.yml/badge.svg)](https://github.com/cyphera-labs/kmip-ruby/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

KMIP client for Ruby -- connect to any KMIP-compliant key management server.

Supports Thales CipherTrust, IBM SKLM, Entrust KeyControl, Fortanix, HashiCorp Vault Enterprise, and any KMIP 1.4 server.

```
gem install cyphera-kmip
```

## Quick Start

```ruby
require "cyphera_kmip"

client = CypheraKmip::Client.new(
  host: "kmip-server.corp.internal",
  client_cert: "/path/to/client.pem",
  client_key: "/path/to/client-key.pem",
  ca_cert: "/path/to/ca.pem",
)

# Fetch a key by name (locate + get in one call)
key = client.fetch_key("my-encryption-key")
# key is a binary string of raw key bytes (e.g., 32 bytes for AES-256)

# Or step by step:
ids = client.locate("my-key")
result = client.get(ids[0])
puts result[:key_material].unpack1("H*")

# Create a new AES-256 key on the server
created = client.create("new-key-name", "AES", 256)
puts created[:unique_identifier]

client.close
```

## Operations

| Operation | Method | Description |
|-----------|--------|-------------|
| Locate | `client.locate(name)` | Find keys by name, returns unique IDs |
| Get | `client.get(id)` | Fetch key material by unique ID |
| Create | `client.create(name, algo, length)` | Create a new symmetric key |
| Fetch | `client.fetch_key(name)` | Locate + Get in one call |

## Authentication

KMIP uses mutual TLS (mTLS). Provide:
- **Client certificate** -- identifies your application to the KMS
- **Client private key** -- proves ownership of the certificate
- **CA certificate** -- validates the KMS server's certificate

```ruby
client = CypheraKmip::Client.new(
  host: "kmip.corp.internal",
  port: 5696,                          # default KMIP port
  client_cert: "/etc/kmip/client.pem",
  client_key: "/etc/kmip/client-key.pem",
  ca_cert: "/etc/kmip/ca.pem",
  timeout: 10,                         # connection timeout (seconds)
)
```

## TTLV Codec

The low-level TTLV (Tag-Type-Length-Value) encoder/decoder is also available for advanced use:

```ruby
include CypheraKmip

# Build custom KMIP messages
msg = Ttlv.encode_structure(Tag::REQUEST_MESSAGE, [...])

# Parse raw KMIP responses
parsed = Ttlv.decode(response_bytes)
```

## Supported KMS Servers

| Server | KMIP Version | Tested |
|--------|-------------|--------|
| Thales CipherTrust Manager | 1.x, 2.0 | Planned |
| IBM SKLM | 1.x, 2.0 | Planned |
| Entrust KeyControl | 1.x, 2.0 | Planned |
| Fortanix DSM | 2.0 | Planned |
| HashiCorp Vault Enterprise | 1.4 | Planned |
| PyKMIP (test server) | 1.0-2.0 | CI |

## Zero Dependencies

This library uses only Ruby standard library (`socket`, `openssl`). No external dependencies.

## Status

Alpha. KMIP 1.4 operations: Locate, Get, Create.

## License

Apache 2.0 -- Copyright 2026 Horizon Digital Engineering LLC
