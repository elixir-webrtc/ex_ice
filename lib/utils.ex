defmodule ExICE.Utils do
  @spec family(:inet.ip_address()) :: :ipv4 | :ipv6
  def family(ip) do
    case ip do
      {_, _, _, _} -> :ipv4
      {_, _, _, _, _, _, _, _} -> :ipv6
    end
  end
end
