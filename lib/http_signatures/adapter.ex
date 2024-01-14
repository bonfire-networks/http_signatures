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
  Get public key from local cache/DB, given a `Plug.Conn` or a key_id.
  """
  @callback get_public_key(Plug.Conn.t() | any()) :: {:ok, any()} | {:error, any()}

  @doc """
  Get or fetch a public key from remote actor, given a `Plug.Conn` or a key_id.
  """
  @callback fetch_public_key(Plug.Conn.t() | any()) :: {:ok, any()} | {:error, any()}
  
  @doc """
  Refetch a public key from remote actor, given a `Plug.Conn` or a key_id.
  Called when the initial key supplied failed to validate the signature.
  """
  @callback fetch_fresh_public_key(Plug.Conn.t() | any()) :: {:ok, any()} | {:error, any()}
end
