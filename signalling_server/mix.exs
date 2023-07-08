defmodule SignallingServer.MixProject do
  use Mix.Project

  def project do
    [
      app: :signalling_server,
      version: "0.1.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      mod: {SignallingServer.App, []},
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:plug, "~> 1.14.0"},
      {:bandit, "~> 1.0.0-pre.10"},
      {:websock_adapter, "~> 0.5.0"}
    ]
  end
end
