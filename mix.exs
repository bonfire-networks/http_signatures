defmodule HttpSignatures.MixProject do
  use Mix.Project

  def project do
    [
      app: :http_signatures,
      description: "Library for manipulating and validating HTTP signatures",
      version: "0.1.0",
      elixir: "~> 1.7",
      elixirc_options: [warnings_as_errors: true],
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :public_key]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:credo, "~> 1.0.0", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false},
      {:dialyxir, "~> 1.0.0-rc.5", only: [:dev], runtime: false}
    ]
  end

  defp package do
    [
      licenses: ["LGPL-3.0-only"],
      links: %{"GitLab" => "https://git.pleroma.social/pleroma/elixir-libraries/http_signatures"}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]
end
