defmodule ExICE.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/elixir-webrtc/ex_ice"

  def project do
    [
      app: :ex_ice,
      version: "0.1.0",
      elixir: "~> 1.13",
      start_permanent: Mix.env() == :prod,
      description: "Implementation of trickle ICE protocol",
      package: package(),
      deps: deps(),

      # docs
      docs: docs(),
      source_url: @source_url,

      # code coverage
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test,
        "coveralls.json": :test
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  def package do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/elixir-webrtc/ex_ice"}
    ]
  end

  defp deps do
    [
      {:ex_stun, "~> 0.1.0"},
      {:excoveralls, "~> 0.15", only: :test, runtime: false},
      {:ex_doc, "~> 0.27", only: :dev, runtime: false},
      {:credo, "~> 1.6", only: [:dev, :test], runtime: false}
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md"],
      source_ref: "v#{@version}",
      formatters: ["html"],
      nest_modules_by_prefix: [ExICE]
    ]
  end
end
