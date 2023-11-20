# Pleroma: A lightweight social networking server
# SPDX-FileCopyrightText: 2017-2019 Pleroma Authors <https://pleroma.social/>
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
    |> IO.inspect(label: "Verify:")
  end

  def validate_conn(conn) do
    adapter = Application.get_env(:http_signatures, :adapter)

    with {:ok, public_key} <- adapter.fetch_public_key(conn) do
      if not is_nil(public_key) and validate_conn(conn, public_key) do
        true
      else
        Logger.info("Could not validate, trying to refetch any relevant keys")

        with {:ok, public_key} <- adapter.refetch_public_key(conn) do
          Logger.debug("refetched public key: #{inspect(public_key)}")
          validate_conn(conn, public_key)
        end
      end
    else
      e ->
        Logger.info("Could not find any public key to validate: #{inspect(e)}")
        false
    end
  end

  def validate_conn(conn, public_key) do
    headers = Enum.into(conn.req_headers, %{})

    signature =
      split_signature(headers["signature"])
      |> IO.inspect(label: "Signature from header:")

    validate(headers, signature, public_key)
  end

  @doc "Get signature for conn in split form."
  def signature_for_conn(conn) do
    with headers <- Enum.into(conn.req_headers, %{}),
         signature when is_binary(signature) <- headers["signature"] do
      split_signature(signature)
    else
      _ ->
        %{}
    end
  end

  def build_signing_string(headers, used_headers) do
    used_headers
    |> Enum.map_join("\n", fn header -> "#{header}: #{headers[header]}" end)
  end

  # Sort map alphabetically to ensure stability
  defp stable_sort_headers(headers) when is_map(headers) do
    headers
    |> Enum.into([])
    |> Enum.sort_by(fn {k, _v} -> k end)
  end

  def sign(private_key, key_id, headers) do
    headers = stable_sort_headers(headers)
    sigstring = build_signing_string(headers, Keyword.keys(headers))

    signature =
      :public_key.sign(sigstring, :sha256, private_key)
      |> Base.encode64()

    [
      keyId: key_id,
      algorithm: "rsa-sha256",
      headers: Keyword.keys(headers) |> Enum.join(" "),
      signature: signature
    ]
    |> Enum.map_join(",", fn {k, v} -> "#{k}=\"#{v}\"" end)
  end
end
