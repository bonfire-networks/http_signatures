use Mix.Config

config :http_signatures, adapter: HTTPSignatures.NullAdapter

if Mix.env() == :test do
  config :http_signatures, adapter: HTTPSignatures.TestAdapter
end
