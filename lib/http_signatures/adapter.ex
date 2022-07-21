# Pleroma: A lightweight social networking server
# SPDX-FileCopyrightText: 2017-2019 Pleroma Authors <https://pleroma.social/>
# SPDX-License-Identifier: LGPL-3.0-only

defmodule HTTPSignatures.Adapter do
  @moduledoc """
  Contract for HTTPSignatures adapters.

  Projects making use of the HTTPSignatures library use an adapter in order
  to provide and refresh the keys used to validate signatures.

  To set the adapter in your project, use the config system:

  ```elixir
  config :http_signatures, adapter: YourAdapter
  ```
  """

  @doc """
  Fetch a public key, given a `Plug.Conn` structure.
  """
  @callback fetch_public_key(Plug.Conn.t()) :: {:ok, any()} | {:error, any()}

  @doc """
  Refetch a public key, given a `Plug.Conn` structure.
  Called when the initial key supplied failed to validate the signature.
  """
  @callback refetch_public_key(Plug.Conn.t()) :: {:ok, any()} | {:error, any()}
end
