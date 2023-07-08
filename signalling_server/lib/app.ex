defmodule SignallingServer.App do
  use Application

  @impl true
  def start(_type, _args) do
    webserver = {Bandit, plug: SignallingServer.Router, scheme: :http, port: 4000}
    {:ok, _} = Supervisor.start_link([webserver], strategy: :one_for_one)
  end
end
