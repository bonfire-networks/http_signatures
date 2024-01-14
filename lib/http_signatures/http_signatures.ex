# Pleroma: A lightweight social networking server
# SPDX-FileCopyrightText: 2017-2019 Pleroma Authors <https://pleroma.social/>
# SPDX-License-Identifier: LGPL-3.0-only

# https://tools.ietf.org/html/draft-cavage-http-signatures-08
defmodule HTTPSignatures do
  @moduledoc """
  HTTP Signatures library.
  """

  import Untangle

  @doc "Validates signature in headers using a cached public_key, and tries to fetch a fresh public_key if not present or invalid"
  def validate(conn_or_headers) do
    headers = to_headers(conn_or_headers)
    adapter = Application.get_env(:http_signatures, :adapter)

    with %{"keyId" => key_id} = signature <- extract_signature(headers),
         {:ok, public_key} <- adapter.get_public_key(key_id) do

      if not is_nil(public_key) and validate(headers, signature, public_key) do
        true
      else
        warn("Could not validate, trying to refetch any relevant keys")

        with {:ok, fresh_public_key} <- adapter.fetch_fresh_public_key(key_id) do
          if not is_nil(fresh_public_key) and fresh_public_key !=public_key do
            debug(fresh_public_key, "refetched public key")
            validate(headers, signature, fresh_public_key)
          else
            debug("refetched public key was not found or identical")
            false
          end
        end
      end
    else
      e ->
        error(e, "Could not find any public key to validate")
        false
    end
  end

  @doc "Validates signature in headers using a cached public_key only"
  def validate_cached(conn_or_headers) do
    headers = to_headers(conn_or_headers)
    adapter = Application.get_env(:http_signatures, :adapter)

    with %{"keyId" => key_id} = signature <- extract_signature(headers),
         {:ok, public_key} <- adapter.get_public_key(key_id) do

      if not is_nil(public_key) and validate(headers, signature, public_key) do
        true
      else
        warn("Could not validate, you may want to refetch any relevant keys")
        false
      end
    else
      e ->
        error(e, "Could not find any public key to validate")
        false
    end
  end

  def validate(headers, signature, public_key) do
    sigstring = build_signing_string(headers, signature["headers"])
    
    if signed = signature["signature"] do
      debug(signed, "Signature")
      debug(sigstring, "Sigstring")

      {:ok, sig} = Base.decode64(signed)
      # |> debug("decoded signature")

      :public_key.verify(sigstring, :sha256, sig, public_key)
      |> debug("Verify:")
    else
      warn(signature, "no signature in headers")
      false
    end
  end


  def validate_headers(headers, public_key) do
    validate(headers, extract_signature(headers), public_key)
  end

  @doc "Get signature for conn or headers in split form."
  def extract_signature(%{"signature"=> signature}) do
    split_signature(signature)
    |> debug()
  end
  def extract_signature(other) do
    to_headers(other)
    |> extract_signature()
  end

  def to_headers(%{req_headers: headers}) do
    Enum.into(headers, %{})
  end
  def to_headers(headers) when is_map(headers) do
    headers
  end
  def to_headers(headers) do
    Enum.into(headers, %{})
  end

  def split_signature(sig) when is_binary(sig) do
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
  def split_signature(_), do: %{}

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
    |> debug("sign_headers")

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
