# SPDX-License-Identifier: LGPL-3.0-only

defmodule HTTPSignatures.RFC9421 do
  @moduledoc """
  RFC 9421 HTTP Message Signatures verification.

  Parses `Signature-Input` and `Signature` headers (RFC 8941 Structured Fields), builds the signature base per RFC 9421 Section 2.5, and verifies against a public key.

  Currently implements verification only. Signing support is planned for future work.
  """

  import Untangle

  @doc """
  Parses RFC 9421 signature headers and returns a normalized signature map compatible with the `HTTPSignatures` adapter interface.

  Returns a map with:
  - `"keyId"` — the key identifier from signature parameters
  - `"algorithm"` — the algorithm identifier (or nil)
  - `"headers"` — the list of covered component identifiers
  - `"signature"` — the raw signature bytes (binary, not base64)
  - `"format"` — `:rfc9421`
  - `"created"` — creation timestamp (integer, or nil)
  - `"label"` — the signature label (e.g., "sig1")
  - `"raw_params"` — the raw signature-input member value for `@signature-params`
  """
  def parse(signature_input_header, signature_header) do
    with {:ok, sig_input_dict} <-
           HttpStructuredField.parse(signature_input_header, type: :dict),
         {label, components, params} <- extract_first_signature(sig_input_dict),
         {:ok, sig_dict} <- HttpStructuredField.parse(signature_header, type: :dict),
         {:ok, sig_bytes} <- extract_signature_bytes(sig_dict, label) do
      raw_params = extract_raw_params(signature_input_header, label)

      %{
        "keyId" => param_value(params, "keyid"),
        "algorithm" => param_value(params, "alg"),
        "headers" => components,
        "signature" => sig_bytes,
        "format" => :rfc9421,
        "created" => param_value(params, "created"),
        "label" => label,
        "raw_params" => raw_params,
        "params" => params
      }
    else
      error ->
        warn(error, "Failed to parse RFC 9421 signature headers")
        %{}
    end
  end

  @doc """
  Builds the signature base string per RFC 9421 Section 2.5.

  The signature base is the canonical string that was signed by the sender.
  Each covered component appears on its own line as `"component": value`, followed by a final `"@signature-params"` line.
  """
  def build_signature_base(headers, components, raw_params) do
    component_lines =
      Enum.map(components, fn component ->
        value = resolve_component(headers, component)
        ~s("#{component}": #{value})
      end)

    params_line = ~s("@signature-params": #{raw_params})

    Enum.join(component_lines ++ [params_line], "\n")
  end

  @doc """
  Verifies an RFC 9421 signature against a public key.
  """
  def verify(headers, signature_map, public_key) do
    components = signature_map["headers"]
    raw_params = signature_map["raw_params"]
    sig_bytes = signature_map["signature"]
    algorithm = signature_map["algorithm"]

    sigstring =
      build_signature_base(headers, components, raw_params)
      |> debug("RFC 9421 signature base")

    verify_with_algorithm(sigstring, sig_bytes, public_key, algorithm)
  end

  @doc """
  Signs a request using RFC 9421 HTTP Message Signatures.

  Returns `{signature_input_header, signature_header}` — the values for the
  `Signature-Input` and `Signature` HTTP headers.

  ## Parameters

  - `private_key` — decoded RSA private key
  - `key_id` — key identifier URI (e.g., `"https://example.com/actor#main-key"`)
  - `headers` — map of component name → value (e.g., `%{"@method" => "POST", ...}`)
  - `opts` — keyword list:
    - `:components` — ordered list of component identifiers to sign (default: sorted keys from headers)
    - `:label` — signature label (default: `"sig1"`)
    - `:created` — Unix timestamp (default: current time)

  ## Examples

      {sig_input, sig} = RFC9421.sign(private_key, "https://example.com/actor#main-key", %{
        "@method" => "POST",
        "@authority" => "recipient.example.com",
        "content-digest" => "sha-256=:abc123=:"
      })
      # sig_input => ~s[sig1=("@method" "@authority" "content-digest");created=...;keyid="..."]
      # sig => "sig1=:BASE64_SIGNATURE:"
  """
  def sign(private_key, key_id, headers, opts \\ []) do
    label = Keyword.get(opts, :label, "sig1")
    created = Keyword.get(opts, :created, System.os_time(:second))

    components =
      Keyword.get_lazy(opts, :components, fn ->
        headers |> Map.keys() |> Enum.sort()
      end)

    raw_params = serialize_signature_params(components, created, key_id)

    sigstring =
      build_signature_base(headers, components, raw_params)
      |> debug("RFC 9421 signing base")

    sig_bytes = :public_key.sign(sigstring, :sha256, private_key)
    sig_b64 = Base.encode64(sig_bytes)

    sig_input_header = "#{label}=#{raw_params}"
    sig_header = "#{label}=:#{sig_b64}:"

    {sig_input_header, sig_header}
  end

  @doc false
  def serialize_signature_params(components, created, key_id) do
    inner_list =
      components
      |> Enum.map_join(" ", &~s["#{&1}"])
      |> then(&"(#{&1})")

    ~s[#{inner_list};created=#{created};keyid="#{key_id}"]
  end

  # --- Private helpers ---

  # HttpStructuredField.parse(type: :dict) returns a single {label, value} tuple
  defp extract_first_signature({label, {:inner_list, items, params}}) do
    components = extract_component_names(items)
    {label, components, params}
  end

  defp extract_first_signature({label, {:inner_list, items}}) do
    components = extract_component_names(items)
    {label, components, []}
  end

  defp extract_first_signature(_), do: {:error, :no_signature_in_input}

  defp extract_component_names(items) do
    Enum.map(items, fn
      {:string, value} -> value
      {:string, value, _params} -> value
      {:token, value} -> value
      {:token, value, _params} -> value
    end)
  end

  defp extract_signature_bytes({label, {:binary, bytes}}, label), do: {:ok, bytes}
  defp extract_signature_bytes({label, {:binary, bytes, _params}}, label), do: {:ok, bytes}
  defp extract_signature_bytes(_, _label), do: {:error, :signature_label_not_found}

  defp extract_raw_params(raw_header, label) do
    # Extract the member value for the given label from the raw Signature-Input header.
    # For "sig1=(...);created=123", we extract "(...);created=123".
    prefix = label <> "="

    case String.split(raw_header, ", ") do
      members ->
        Enum.find_value(members, raw_header, fn member ->
          member = String.trim(member)

          if String.starts_with?(member, prefix) do
            String.slice(member, String.length(prefix)..-1//1)
          end
        end)
    end
  end

  defp param_value(params, key) do
    case List.keyfind(params, key, 0) do
      {^key, {:string, value}} -> value
      {^key, {:string, value, _}} -> value
      {^key, {:integer, value}} -> value
      {^key, {:integer, value, _}} -> value
      {^key, {:token, value}} -> value
      {^key, {:token, value, _}} -> value
      {^key, {:boolean, value}} -> value
      _ -> nil
    end
  end

  defp resolve_component(headers, "@method") do
    method = headers["@method"] || headers["(request-target-method)"] || "POST"
    String.upcase(method)
  end

  defp resolve_component(headers, "@authority") do
    headers["@authority"] || headers["host"] || ""
  end

  defp resolve_component(headers, "@path") do
    case headers["@path"] || headers["(request-target)"] do
      nil -> "/"
      target -> target |> String.split(" ") |> List.last() |> URI.parse() |> Map.get(:path, "/")
    end
  end

  defp resolve_component(headers, "@target-uri") do
    scheme = headers["@scheme"] || "https"
    authority = resolve_component(headers, "@authority")
    path = resolve_component(headers, "@path")
    query = resolve_component(headers, "@query")

    case query do
      nil -> "#{scheme}://#{authority}#{path}"
      "" -> "#{scheme}://#{authority}#{path}"
      q -> "#{scheme}://#{authority}#{path}?#{q}"
    end
  end

  defp resolve_component(headers, "@query") do
    case headers["@query"] do
      nil ->
        case headers["(request-target)"] do
          nil -> nil
          target -> target |> String.split(" ") |> List.last() |> URI.parse() |> Map.get(:query)
        end

      query ->
        query
    end
  end

  defp resolve_component(headers, "@scheme") do
    headers["@scheme"] || "https"
  end

  defp resolve_component(headers, "@status") do
    headers["@status"] || ""
  end

  # Regular HTTP header field
  defp resolve_component(headers, header_name) do
    headers[header_name] || ""
  end

  defp verify_with_algorithm(sigstring, sig_bytes, public_key, "ed25519") do
    try do
      :public_key.verify(sigstring, :none, sig_bytes, {:ed_pub, :ed25519, public_key})
    rescue
      _ -> false
    end
    |> debug("RFC 9421 ed25519 verify:")
  end

  defp verify_with_algorithm(sigstring, sig_bytes, public_key, _algorithm) do
    # Default to rsa-v1_5-sha256 (most common in ActivityPub federation)
    :public_key.verify(sigstring, :sha256, sig_bytes, public_key)
    |> debug("RFC 9421 rsa-v1_5-sha256 verify:")
  end
end
