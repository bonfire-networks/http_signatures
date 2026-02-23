# SPDX-License-Identifier: LGPL-3.0-only

defmodule HTTPSignatures.RFC9421Test do
  use ExUnit.Case

  @private_key hd(:public_key.pem_decode(File.read!(Path.join(__DIR__, "private.key"))))
               |> :public_key.pem_entry_decode()

  @public_key hd(:public_key.pem_decode(File.read!(Path.join(__DIR__, "public.key"))))
              |> :public_key.pem_entry_decode()

  describe "parse/2" do
    test "parses a Signature-Input with covered components and parameters" do
      sig_input =
        ~s[sig1=("@method" "@authority" "content-digest");created=1618884475;keyid="https://example.com/actor#main-key";alg="rsa-v1_5-sha256"]

      # Create a dummy signature for parsing (real verification tested separately)
      dummy_sig_bytes = :crypto.strong_rand_bytes(32) |> Base.encode64()
      sig_header = "sig1=:#{dummy_sig_bytes}:"

      result = HTTPSignatures.RFC9421.parse(sig_input, sig_header)

      assert result["format"] == :rfc9421
      assert result["keyId"] == "https://example.com/actor#main-key"
      assert result["algorithm"] == "rsa-v1_5-sha256"
      assert result["headers"] == ["@method", "@authority", "content-digest"]
      assert result["label"] == "sig1"
      assert result["created"] == 1_618_884_475
      assert is_binary(result["signature"])
    end

    test "parses Signature-Input without algorithm parameter" do
      sig_input =
        ~s[sig1=("@method" "@authority");created=1618884475;keyid="https://example.com/actor#main-key"]

      dummy_sig_bytes = :crypto.strong_rand_bytes(32) |> Base.encode64()
      sig_header = "sig1=:#{dummy_sig_bytes}:"

      result = HTTPSignatures.RFC9421.parse(sig_input, sig_header)

      assert result["keyId"] == "https://example.com/actor#main-key"
      assert result["algorithm"] == nil
      assert result["headers"] == ["@method", "@authority"]
    end
  end

  describe "build_signature_base/3" do
    test "builds correct signature base for derived and regular components" do
      headers = %{
        "@method" => "POST",
        "@authority" => "example.com",
        "content-digest" => "sha-256=:abc123=:",
        "content-type" => "application/activity+json"
      }

      components = ["@method", "@authority", "content-digest", "content-type"]

      raw_params =
        ~s[("@method" "@authority" "content-digest" "content-type");created=1618884475;keyid="https://example.com/actor#main-key"]

      result = HTTPSignatures.RFC9421.build_signature_base(headers, components, raw_params)

      expected = Enum.join([
        ~s["@method": POST],
        ~s["@authority": example.com],
        ~s["content-digest": sha-256=:abc123=:],
        ~s["content-type": application/activity+json],
        ~s["@signature-params": ] <> raw_params
      ], "\n")

      assert result == expected
    end

    test "builds correct signature base with @path component" do
      headers = %{
        "@method" => "POST",
        "@path" => "/inbox"
      }

      raw_params = ~s[("@method" "@path");created=123;keyid="test"]

      result = HTTPSignatures.RFC9421.build_signature_base(headers, ["@method", "@path"], raw_params)

      expected = Enum.join([
        ~s["@method": POST],
        ~s["@path": /inbox],
        ~s["@signature-params": ] <> raw_params
      ], "\n")

      assert result == expected
    end
  end

  describe "verify/3" do
    test "verifies a valid RFC 9421 RSA signature" do
      headers = %{
        "@method" => "POST",
        "@authority" => "example.com",
        "content-type" => "application/activity+json"
      }

      components = ["@method", "@authority", "content-type"]

      raw_params =
        ~s[("@method" "@authority" "content-type");created=1618884475;keyid="Test"]

      # Build the signature base and sign it with our test key
      sigstring =
        HTTPSignatures.RFC9421.build_signature_base(headers, components, raw_params)

      sig_bytes = :public_key.sign(sigstring, :sha256, @private_key)
      sig_b64 = Base.encode64(sig_bytes)

      # Build Signature-Input and Signature headers
      sig_input_header = "sig1=" <> raw_params
      sig_header = "sig1=:#{sig_b64}:"

      # Parse and verify
      signature_map = HTTPSignatures.RFC9421.parse(sig_input_header, sig_header)
      assert signature_map["format"] == :rfc9421

      assert HTTPSignatures.RFC9421.verify(headers, signature_map, @public_key)
    end

    test "rejects an invalid RFC 9421 RSA signature" do
      headers = %{
        "@method" => "POST",
        "@authority" => "example.com"
      }

      raw_params = ~s[("@method" "@authority");created=1618884475;keyid="Test"]

      # Sign with correct key but tamper with headers
      sigstring =
        HTTPSignatures.RFC9421.build_signature_base(headers, ["@method", "@authority"], raw_params)

      sig_bytes = :public_key.sign(sigstring, :sha256, @private_key)
      sig_b64 = Base.encode64(sig_bytes)

      sig_input_header = "sig1=" <> raw_params
      sig_header = "sig1=:#{sig_b64}:"

      # Tamper: change @authority
      tampered_headers = Map.put(headers, "@authority", "evil.com")

      signature_map = HTTPSignatures.RFC9421.parse(sig_input_header, sig_header)
      refute HTTPSignatures.RFC9421.verify(tampered_headers, signature_map, @public_key)
    end
  end

  describe "format detection in HTTPSignatures.extract_signature/1" do
    test "detects RFC 9421 when signature-input header is present" do
      raw_params = ~s[("@method" "@authority");created=123;keyid="test-key"]
      dummy_sig = :crypto.strong_rand_bytes(32) |> Base.encode64()

      headers = %{
        "signature-input" => "sig1=" <> raw_params,
        "signature" => "sig1=:#{dummy_sig}:"
      }

      result = HTTPSignatures.extract_signature(headers)
      assert result["format"] == :rfc9421
      assert result["keyId"] == "test-key"
    end

    test "detects draft-cavage when only signature header is present" do
      headers = %{
        "signature" =>
          ~s[keyId="https://example.com/actor#main-key",algorithm="rsa-sha256",headers="(request-target) host date",signature="abc123=="]
      }

      result = HTTPSignatures.extract_signature(headers)
      assert result["keyId"] == "https://example.com/actor#main-key"
      refute Map.has_key?(result, "format")
    end
  end

  describe "end-to-end validate/3 dispatch" do
    test "validates RFC 9421 signature through main validate/3" do
      headers = %{
        "@method" => "POST",
        "@authority" => "example.com",
        "content-type" => "application/activity+json"
      }

      components = ["@method", "@authority", "content-type"]

      raw_params =
        ~s[("@method" "@authority" "content-type");created=1618884475;keyid="Test"]

      sigstring =
        HTTPSignatures.RFC9421.build_signature_base(headers, components, raw_params)

      sig_bytes = :public_key.sign(sigstring, :sha256, @private_key)
      sig_b64 = Base.encode64(sig_bytes)

      sig_input_header = "sig1=" <> raw_params
      sig_header = "sig1=:#{sig_b64}:"

      signature_map =
        HTTPSignatures.RFC9421.parse(sig_input_header, sig_header)
        |> Map.put("format", :rfc9421)

      # Dispatch through main module
      assert HTTPSignatures.validate(headers, signature_map, @public_key)
    end
  end

  describe "RFC9421.sign/4" do
    test "returns a {signature_input, signature} tuple with correct format" do
      headers = %{
        "@method" => "POST",
        "@authority" => "example.com",
        "content-digest" => "sha-256=:abc123=:"
      }

      key_id = "https://example.com/actor#main-key"

      {sig_input, sig} =
        HTTPSignatures.RFC9421.sign(@private_key, key_id, headers,
          components: ["@method", "@authority", "content-digest"],
          created: 1_618_884_475
        )

      # Signature-Input format: sig1=("comp1" "comp2");created=...;keyid="..."
      assert String.starts_with?(sig_input, "sig1=(")
      assert sig_input =~ ~s[;keyid="#{key_id}"]
      assert sig_input =~ ";created=1618884475"
      assert sig_input =~ ~s["@method"]
      assert sig_input =~ ~s["@authority"]
      assert sig_input =~ ~s["content-digest"]

      # Signature format: sig1=:base64:
      assert String.starts_with?(sig, "sig1=:")
      assert String.ends_with?(sig, ":")
    end

    test "round-trip: sign then parse then verify" do
      headers = %{
        "@method" => "POST",
        "@authority" => "recipient.example.com",
        "content-digest" => "sha-256=:dGVzdA==:",
        "content-type" => "application/activity+json"
      }

      key_id = "https://example.com/actor#main-key"
      components = ["@method", "@authority", "content-digest", "content-type"]

      {sig_input, sig} =
        HTTPSignatures.RFC9421.sign(@private_key, key_id, headers,
          components: components,
          created: 1_700_000_000
        )

      # Parse the produced headers back
      signature_map = HTTPSignatures.RFC9421.parse(sig_input, sig)

      assert signature_map["format"] == :rfc9421
      assert signature_map["keyId"] == key_id
      assert signature_map["headers"] == components
      assert signature_map["created"] == 1_700_000_000
      assert is_binary(signature_map["signature"])

      # Verify with the matching public key
      assert HTTPSignatures.RFC9421.verify(headers, signature_map, @public_key)

      # Verify fails with tampered headers
      tampered = Map.put(headers, "@authority", "evil.com")
      refute HTTPSignatures.RFC9421.verify(tampered, signature_map, @public_key)
    end

    test "defaults components to sorted header keys when not specified" do
      headers = %{
        "@method" => "GET",
        "@authority" => "example.com",
        "@path" => "/users/alice"
      }

      key_id = "https://example.com/actor#main-key"

      {sig_input, _sig} =
        HTTPSignatures.RFC9421.sign(@private_key, key_id, headers, created: 123)

      # Components should be alphabetically sorted: @authority, @method, @path
      assert sig_input =~ ~s[("@authority" "@method" "@path")]
    end

    test "custom label" do
      headers = %{"@method" => "POST"}
      key_id = "test-key"

      {sig_input, sig} =
        HTTPSignatures.RFC9421.sign(@private_key, key_id, headers,
          label: "mysig",
          created: 123
        )

      assert String.starts_with?(sig_input, "mysig=")
      assert String.starts_with?(sig, "mysig=:")
    end
  end

  describe "HTTPSignatures.sign/4 with format opt" do
    test "format: :rfc9421 delegates to RFC9421.sign" do
      headers = %{
        "@method" => "POST",
        "@authority" => "example.com"
      }

      key_id = "https://example.com/actor#main-key"

      {sig_input, sig} =
        HTTPSignatures.sign(@private_key, key_id, headers,
          format: :rfc9421,
          components: ["@method", "@authority"],
          created: 1_618_884_475
        )

      assert is_binary(sig_input)
      assert is_binary(sig)
      assert String.starts_with?(sig_input, "sig1=")
      assert String.starts_with?(sig, "sig1=:")
    end

    test "default format returns draft-cavage string" do
      headers = %{
        "(request-target)": "post /inbox",
        host: "example.com",
        date: "Thu, 05 Jan 2014 21:31:40 GMT"
      }

      key_id = "https://example.com/actor#main-key"

      result = HTTPSignatures.sign(@private_key, key_id, headers)

      assert is_binary(result)
      assert result =~ "keyId="
      assert result =~ "signature="
    end

    test "round-trip through sign (rfc9421) and validate dispatch" do
      headers = %{
        "@method" => "POST",
        "@authority" => "example.com",
        "content-type" => "application/activity+json"
      }

      key_id = "https://example.com/actor#main-key"
      components = ["@method", "@authority", "content-type"]

      {sig_input, sig} =
        HTTPSignatures.sign(@private_key, key_id, headers,
          format: :rfc9421,
          components: components,
          created: 1_618_884_475
        )

      # Parse and validate through the main module
      signature_map = HTTPSignatures.RFC9421.parse(sig_input, sig)
      assert HTTPSignatures.validate(headers, signature_map, @public_key)
    end
  end
end
