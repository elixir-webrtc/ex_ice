defmodule ExICE.App do
  @moduledoc false
  use Application

  @impl true
  def start(_type, _args) do
    children = [{ExICE.MDNS.Resolver, :gen_udp}]
    Supervisor.start_link(children, strategy: :one_for_one)
  end
end
