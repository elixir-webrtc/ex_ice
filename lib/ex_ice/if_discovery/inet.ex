defmodule ExICE.IfDiscovery.Inet do
  @moduledoc false

  @behaviour ExICE.IfDiscovery

  @impl true
  defdelegate getifaddrs(), to: :inet
end
