defmodule ExICE.Priv.Transport.TCP do
  @moduledoc false
  @behaviour ExICE.Priv.Transport

  require Logger

  alias ExICE.Priv.Transport.TCP.Client

  @impl true
  def transport, do: :tcp

  # Obtaining three candidates for each IP address, per RFC 6544, sec. 5.1.
  @impl true
  def socket_configs,
    do: [
      [tcp_type: :passive],
      [tcp_type: :so],
      [tcp_type: :active]
    ]

  @impl true
  def setup_socket(ip, port, socket_opts, tp_opts) do
    case Registry.lookup(ExICE.Priv.Registry, {ip, port}) do
      # This protects us from reusing ports ONLY within the same VM instance
      # See `ExICE.Priv.Transport.TCP.Client.setup_socket/5` for more info
      [{_pid, _}] ->
        # TODO: Consider using another (custom) reason to distinguish from POSIX EADDRINUSE
        {:error, :eaddrinuse}

      [] ->
        {:ok, pid} = Client.start_link()
        Client.setup_socket(pid, ip, port, socket_opts, tp_opts)
    end
  end

  @impl true
  defdelegate sockname(socket), to: :inet

  # HACK: using listen sockets here is ugly, but was easier to fit into the existing ICE Agent implementation.
  #       This should be changed, especially because we're going to want to close the listen sockets
  #       after the connection is successfully established.
  @impl true
  def send(listen_socket, dest, packet, tp_opts \\ []) do
    with {:ok, local} <- sockname(listen_socket),
         [{pid, _}] <- Registry.lookup(ExICE.Priv.Registry, local) do
      GenServer.call(pid, {:send, listen_socket, dest, packet, tp_opts})
    else
      _ -> {:error, :no_client_process}
    end
  end

  @impl true
  def close(listen_socket) do
    with {:ok, local} <- sockname(listen_socket),
         [{pid, _}] <- Registry.lookup(ExICE.Priv.Registry, local) do
      GenServer.call(pid, {:close, listen_socket})
    else
      _ -> {:error, :no_client_process}
    end
  end
end
