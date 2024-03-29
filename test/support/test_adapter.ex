# Pleroma: A lightweight social networking server
# SPDX-FileCopyrightText: 2017-2019 Pleroma Authors <https://pleroma.social/>
# SPDX-License-Identifier: LGPL-3.0-only

defmodule HTTPSignatures.TestAdapter do
  @behaviour HTTPSignatures.Adapter

  @moduledoc "Test adapter for HTTPSignatures library."

  @mastodon_admin_pubkey hd(
                           :public_key.pem_decode(
                             File.read!("test/admin@mastodon.example.org.key")
                           )
                         )
                         |> :public_key.pem_entry_decode()

  @rye_pubkey hd(:public_key.pem_decode(File.read!("test/rye@niu.moe.key")))
              |> :public_key.pem_entry_decode()

  @lm_pubkey hd(
               :public_key.pem_decode(File.read!("test/lucifermysticus@mst3k.interlinked.me.key"))
             )
             |> :public_key.pem_entry_decode()

  def get_public_key(_), do: {:ok, @mastodon_admin_pubkey}

  def fetch_fresh_public_key(%{params: params}),
    do: fetch_fresh_public_key(params)

  def fetch_fresh_public_key(%{"actor" => actor}
      ),
      do: fetch_fresh_public_key(actor)

  def fetch_fresh_public_key("https://niu.moe/users/rye"),
    do: {:ok, @rye_pubkey}

  def fetch_fresh_public_key("https://mst3k.interlinked.me/users/luciferMysticus"
      ),
      do: {:ok, @lm_pubkey}

  def fetch_fresh_public_key(_), do: {:error, "no public key found"}
end
