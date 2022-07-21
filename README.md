<!--
SPDX-FileCopyrightText: 2017-2019 Pleroma Authors <https://pleroma.social/>
SPDX-License-Identifier: LGPL-3.0-only
-->

# HttpSignatures

**Elixir library for manipulating and validating HTTP signatures.**

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

You will need to write an adapter module that compiles with the
`HTTPSignatures.Adapter` behaviour.  This is used to fetch the public
keys when verifying signatures.  The adapter is configured like so:

```
config :http_signatures, adapter: YourAdapter
```

## Documentation

Published at [https://hexdocs.pm/http_signatures](https://hexdocs.pm/http_signatures).
