defmodule ExICE.Priv.IfDiscovery.Inet do
  @moduledoc false

  @behaviour ExICE.Priv.IfDiscovery

  @impl true
  defdelegate getifaddrs(), to: :inet
end
