# SPDX-FileCopyrightText: 2017-2019 Pleroma Authors <https://pleroma.social/>
# SPDX-License-Identifier: LGPL-3.0-only

import Config

config :http_signatures, adapter: HTTPSignatures.NullAdapter

if Mix.env() == :test do
  config :http_signatures, adapter: HTTPSignatures.TestAdapter
end
