<!--
SPDX-FileCopyrightText: 2017-2019 Pleroma Authors <https://pleroma.social/>
SPDX-License-Identifier: LGPL-3.0-only
-->

# HttpSignatures

**Elixir library for manipulating and validating HTTP signatures, supporting both [draft-cavage](https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12) and [RFC 9421](https://datatracker.ietf.org/doc/html/rfc9421) formats.**

## Supported Formats

### Draft-Cavage (original)

The original HTTP Signatures draft used by most ActivityPub implementations. Uses a single `Signature` header with `keyId`, `algorithm`, `headers`, and `signature` fields.

### RFC 9421 (newer)

The standardized [HTTP Message Signatures](https://datatracker.ietf.org/doc/html/rfc9421) format, used by newer implementations such as Fedify and Mitra 4.4+. Uses two headers:

- `Signature-Input` — describes what was signed (covered components and parameters), encoded as [RFC 8941 Structured Fields](https://datatracker.ietf.org/doc/html/rfc8941)
- `Signature` — the actual signature bytes, also as an RFC 8941 Structured Field

Format detection is automatic: when both `Signature-Input` and `Signature` headers are present, the library uses RFC 9421 verification. When only `Signature` is present, it uses draft-cavage.

> **Note:** Currently only incoming signature **verification** is currently implemented for RFC 9421. Outgoing signing still uses draft-cavage. RFC 9421 signing support is planned for future work.

## Installation

The package can be installed by adding `http_signatures` to your list
of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:http_signatures, "~> 0.1.0"}
  ]
end
```

## Configuration

You will need to write an adapter module that implements the
`HTTPSignatures.Adapter` behaviour. This is used to fetch public
keys when verifying signatures. The adapter is configured like so:

```elixir
config :http_signatures, adapter: YourAdapter
```

## Usage

### Validating incoming requests

```elixir
# Automatic format detection and validation (draft-cavage or RFC 9421)
HTTPSignatures.validate(conn)

# Or with pre-extracted headers and key
HTTPSignatures.validate(headers, signature_map, public_key)
```

### Signing outgoing requests (draft-cavage)

```elixir
HTTPSignatures.sign(private_key, key_id, headers)
```

### RFC 9421 module

The `HTTPSignatures.RFC9421` module can also be used directly:

```elixir
# Parse RFC 9421 headers into a signature map
signature_map = HTTPSignatures.RFC9421.parse(signature_input_header, signature_header)

# Build the signature base string for verification
sigstring = HTTPSignatures.RFC9421.build_signature_base(headers, components, raw_params)

# Verify a parsed RFC 9421 signature
HTTPSignatures.RFC9421.verify(headers, signature_map, public_key)
```

### Supported algorithms

- `rsa-v1_5-sha256` — RSA PKCS#1 v1.5 with SHA-256 (default, most common in ActivityPub)
- `ed25519` — Ed25519 (EdDSA)

## Documentation

Published at [https://hexdocs.pm/http_signatures](https://hexdocs.pm/http_signatures).
