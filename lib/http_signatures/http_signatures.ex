# Pleroma: A lightweight social networking server
# Copyright © 2017-2019 Pleroma Authors <https://pleroma.social/>
# SPDX-License-Identifier: LGPL-3.0-only

# https://tools.ietf.org/html/draft-cavage-http-signatures-08
defmodule HTTPSignatures do
  @moduledoc """
  HTTP Signatures library.
  """

  require Logger

  def split_signature(sig) do
    default = %{"headers" => "date"}

    sig =
      sig
      |> String.trim()
      |> String.split(",")
      |> Enum.reduce(default, fn part, acc ->
        [key | rest] = String.split(part, "=")
        value = Enum.join(rest, "=")
        Map.put(acc, key, String.trim(value, "\""))
      end)

    Map.put(sig, "headers", String.split(sig["headers"], ~r/\s/))
  end

  def validate(headers, signature, public_key) do
    sigstring = build_signing_string(headers, signature["headers"])
    Logger.debug("Signature: #{signature["signature"]}")
    Logger.debug("Sigstring: #{sigstring}")
    {:ok, sig} = Base.decode64(signature["signature"])
    :public_key.verify(sigstring, :sha256, sig, public_key)
  end

  def validate_conn(conn) do
    adapter = Application.get_env(:http_signatures, :adapter)

    with {:ok, public_key} <- adapter.fetch_public_key(conn) do
      if validate_conn(conn, public_key) do
        true
      else
        Logger.debug("Could not validate, trying to refetch any relevant keys")

        with {:ok, public_key} <- adapter.refetch_public_key(conn) do
          validate_conn(conn, public_key)
        end
      end
    else
      e ->
        Logger.debug("Could not validate against known public keys: #{inspect(e)}")
        false
    end
  end

  def validate_conn(conn, public_key) do
    headers = Enum.into(conn.req_headers, %{})
    signature = split_signature(headers["signature"])
    validate(headers, signature, public_key)
  end

  def build_signing_string(headers, used_headers) do
    used_headers
    |> Enum.map(fn header -> "#{header}: #{headers[header]}" end)
    |> Enum.join("\n")
  end

  def sign(private_key, key_id, headers) do
    sigstring = build_signing_string(headers, Map.keys(headers))

    signature =
      :public_key.sign(sigstring, :sha256, private_key)
      |> Base.encode64()

    [
      keyId: key_id,
      algorithm: "rsa-sha256",
      headers: Map.keys(headers) |> Enum.join(" "),
      signature: signature
    ]
    |> Enum.map(fn {k, v} -> "#{k}=\"#{v}\"" end)
    |> Enum.join(",")
  end
end
