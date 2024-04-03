defmodule ExICE.Priv.App do
  @moduledoc false
  use Application

  @impl true
  def start(_type, _args) do
    children = [{ExICE.Priv.MDNS.Resolver, :gen_udp}]
    Supervisor.start_link(children, strategy: :one_for_one)
  end
end
