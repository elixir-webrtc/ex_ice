defmodule ExICE.IfDiscovery do
  @moduledoc false

  # ifopts should be of type :inet.getifaddrs_ifopts() but this is an internal :inet type
  @callback getifaddrs() :: {:ok, [{ifname :: charlist(), ifopts :: list()}]} | {:error, term()}
end
