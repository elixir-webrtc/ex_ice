defmodule ExICE.Priv.Transport.UDP do
  @moduledoc false
  @behaviour ExICE.Priv.Transport

  @impl true
  def transport, do: :udp

  # Obtaining one candidate for each IP address
  @impl true
  def socket_configs, do: [[]]

  @impl true
  def setup_socket(ip, port, socket_opts, _tp_opts \\ []) do
    ip_opt = if ip, do: [ip: ip], else: []
    :gen_udp.open(port, socket_opts ++ ip_opt)
  end

  @impl true
  defdelegate sockname(socket), to: :inet

  @impl true
  def send(socket, dest, packet, _tp_opts \\ []), do: :gen_udp.send(socket, dest, packet)

  @impl true
  defdelegate close(socket), to: :gen_udp
end
