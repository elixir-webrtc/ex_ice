defmodule ExICE.Priv.Transport.UDP do
  @moduledoc false
  @behaviour ExICE.Priv.Transport

  @impl true
  defdelegate open(port, opts), to: :gen_udp

  @impl true
  defdelegate sockname(socket), to: :inet

  @impl true
  defdelegate send(socket, dest, packet), to: :gen_udp

  @impl true
  defdelegate close(socket), to: :gen_udp
end
