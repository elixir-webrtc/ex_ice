defmodule ExICE.Utils do
  @moduledoc false

  @spec family(:inet.ip_address()) :: :ipv4 | :ipv6
  def family(ip) do
    case ip do
      {_, _, _, _} -> :ipv4
      {_, _, _, _, _, _, _, _} -> :ipv6
    end
  end

  @spec id() :: non_neg_integer()
  def id() do
    <<id::12*8>> = :crypto.strong_rand_bytes(12)
    id
  end
end
