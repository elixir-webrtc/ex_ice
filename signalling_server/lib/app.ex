defmodule SignallingServer.App do
  use Application

  @impl true
  def start(_type, _args) do
    webserver = {Bandit, plug: SignallingServer.Router, scheme: :http, port: 4000}

    children = [
      webserver,
      {SignallingServer.Room, []}
    ]

    {:ok, _} = Supervisor.start_link(children, strategy: :one_for_one)
  end
end
