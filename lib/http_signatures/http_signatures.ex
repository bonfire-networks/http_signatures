# Pleroma: A lightweight social networking server
# SPDX-FileCopyrightText: 2017-2019 Pleroma Authors <https://pleroma.social/>
# SPDX-License-Identifier: LGPL-3.0-only

defmodule HTTPSignatures do
  @moduledoc """
  HTTP Signatures library supporting both draft-cavage-http-signatures-08 and RFC 9421 HTTP Message Signatures.
  """

  import Untangle

  alias HTTPSignatures.RFC9421

  @doc """
  Validates signature in headers using a cached public_key.

  Options:
  - `refetch_if_expired: true` — if cached key doesn't validate, tries to fetch a fresh key and re-validate
  - `return: :key_host` — returns the keyId's hostname on success instead of `true`
  - `return: :key` — returns the parsed keyId URI on success instead of `true`

  Format is auto-detected based on headers:
  - `Signature-Input` header present → RFC 9421
  - `Signature` header only → draft-cavage
  """
  def validate(conn_or_headers, opts \\ []) do
    headers = to_headers(conn_or_headers)
    adapter = Application.get_env(:http_signatures, :adapter)

    with %{"keyId" => key_id} = signature <- extract_signature(headers),
         {:ok, public_key} <- adapter.get_public_key(key_id) do

      valid? =
        if not is_nil(public_key) and validate(headers, signature, public_key) do
          true
        else
          if opts[:refetch_if_expired] do
            warn("Could not validate, trying to refetch any relevant keys")

            with {:ok, fresh_public_key} <- adapter.fetch_fresh_public_key(key_id) do
              if not is_nil(fresh_public_key) and fresh_public_key != public_key do
                debug(fresh_public_key, "refetched public key")
                validate(headers, signature, fresh_public_key)
              else
                debug("refetched public key was not found or identical")
                false
              end
            end
          else
            warn("Could not validate, you may want to refetch any relevant keys")
            false
          end
        end

      return_result(valid?, key_id, opts[:return])
    else
      e ->
        error(e, "Could not find any public key to validate")
        false
    end
  end

  def validate_cached(conn_or_headers, opts \\ []), do: validate(conn_or_headers, opts |> Keyword.put(:refetch_if_expired, false))

  # With `return: :key_host`, returns the keyId's hostname on success, false on failure.
  # Default behaviour returns boolean for backwards compatibility.
  defp return_result(true, key_id, :key_host) when is_binary(key_id) do
    URI.parse(key_id).host || true
  end
  defp return_result(true, key_id, :key) when is_binary(key_id) do
    URI.parse(key_id) || true
  end
  defp return_result(valid?, _key_id, _opts), do: valid?

  @doc "Validates a signature against headers and a public key. Dispatches to RFC 9421 or draft-cavage based on format."
  def validate(headers, %{"format" => :rfc9421} = signature, public_key) do
    RFC9421.verify(headers, signature, public_key)
  end

  def validate(headers, signature, public_key) do
    sigstring = build_signing_string(headers, signature["headers"])

    if signed = signature["signature"] do
      debug(signed, "Signature")
      debug(sigstring, "Sigstring")

      {:ok, sig} = Base.decode64(signed)

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

  @doc """
  Extracts and parses signature from headers. Auto-detects format:
  - RFC 9421: when `signature-input` header is present
  - Draft-cavage: when only `signature` header is present
  """
  def extract_signature(%{"signature-input" => sig_input, "signature" => sig}) do
    RFC9421.parse(sig_input, sig)
    |> Map.put("format", :rfc9421)
    |> debug("RFC 9421 signature extracted")
  end

  def extract_signature(%{"signature-input" => sig_input} = headers) do
    # RFC 9421 with structured Signature header (may have different casing)
    sig = headers["signature"] || ""
    RFC9421.parse(sig_input, sig)
    |> Map.put("format", :rfc9421)
    |> debug("RFC 9421 signature extracted")
  end

  def extract_signature(%{"signature" => signature}) do
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

  @doc "Parses a draft-cavage Signature header into a map."
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

  @doc "Builds the signing string for draft-cavage signatures."
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

  @doc """
  Signs headers. Supports two formats via the `:format` option:

  - `:cavage` (default) — draft-cavage format, returns a single `Signature` header string
  - `:rfc9421` — RFC 9421 format, returns `{signature_input, signature}` header pair

  For `:rfc9421`, `headers` should be a map of component names to values (e.g., `%{"@method" => "POST"}`).
  Additional options for RFC 9421: `:components`, `:label`, `:created` (see `HTTPSignatures.RFC9421.sign/4`).
  """
  def sign(private_key, key_id, headers, opts \\ [])

  def sign(private_key, key_id, headers, opts) when is_map(headers) do
    case Keyword.get(opts, :format, :cavage) do
      :rfc9421 ->
        RFC9421.sign(private_key, key_id, headers, opts)

      _cavage ->
        sign_cavage(private_key, key_id, headers)
    end
  end

  def sign(private_key, key_id, headers, opts) when is_list(headers) do
    case Keyword.get(opts, :format, :cavage) do
      :rfc9421 ->
        RFC9421.sign(private_key, key_id, Map.new(headers), opts)

      _cavage ->
        sign_cavage(private_key, key_id, headers)
    end
  end

  defp sign_cavage(private_key, key_id, headers) when is_map(headers) do
    sign_cavage(private_key, key_id, stable_sort_headers(headers))
  end

  defp sign_cavage(private_key, key_id, headers) when is_list(headers) do
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
