defmodule ExICE.Priv.Transport.TCP.Client do
  @moduledoc false

  use GenServer

  require Logger

  alias ExICE.Priv.Transport

  @connect_timeout_ms 500

  @spec start_link(Keyword.t()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts ++ [ice_agent: self()])
  end

  @spec setup_socket(
          GenServer.server(),
          :inet.ip_address(),
          :inet.port_number(),
          [Transport.open_option()],
          Transport.transport_options()
        ) :: {:ok, Transport.socket()} | {:error, term()}
  def setup_socket(pid, ip, port, socket_opts, tp_opts) do
    GenServer.call(pid, {:setup_socket, ip, port, socket_opts, tp_opts})
  end

  # HACK: using listen sockets here is ugly, but was easier to fit into the existing ICE Agent implementation.
  #       This should be changed, especially because we're going to want to close the listen sockets
  #       after the connection is successfully established.
  @spec send(
          GenServer.server(),
          Transport.socket(),
          {:inet.ip_address(), :inet.port_number()},
          binary(),
          Transport.transport_options()
        ) :: :ok | {:error, term()}
  def send(pid, listen_socket, dest, packet, tp_opts \\ []) do
    GenServer.call(pid, {:send, listen_socket, dest, packet, tp_opts})
  end

  @spec close(GenServer.server(), Transport.socket()) :: :ok
  def close(pid, listen_socket) do
    GenServer.call(pid, {:close, listen_socket})
  end

  @impl true
  def init(opts) do
    state = %{
      ice_agent: Keyword.fetch!(opts, :ice_agent),
      listen_socket: nil,
      socket_opts: nil,
      tcp_type: nil,
      connections: %{}
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:setup_socket, ip, port, socket_opts, tp_opts}, _from, state) do
    # * For TCP ICE to work, in certain cases we need to be able to both listen
    #   and make connection attempts from the same socket.
    # * The OS will not allow that unless we set SO_REUSEADDR/SO_REUSEPORT, which we do here.
    # * However, this means the OS will no longer protect us from binding to the same address+port
    #   when we DON'T want that to happen.
    # * If `ice_agent.ports == [0]`, this has no impact: the OS will use a different ephemeral port every time.
    # * Otherwise, we run into a problem: the user has specified a port range (i.e. `50000..50500`),
    #   and we'd need to explicitly ask the OS to list currently bound sockets to determine
    #   whether we can use a certain port number from that range.
    # * We try to alleviate this issue to an extent by checking against the sockets which we know of,
    #   those present in `ExICE.Priv.Registry`.
    # * This, however, does not protect us from binding to sockets opened with SO_REUSEPORT,
    #   that are in use by another OS process with the same effective UID as this one,
    #   which can happen i.e. when we run ICE Agents in two separate VM instances.
    socket_opts = socket_opts ++ [ip: ip, reuseport: true]
    tcp_type = Keyword.fetch!(tp_opts, :tcp_type)

    case :gen_tcp.listen(port, socket_opts) do
      {:ok, listen_socket} ->
        {:ok, {^ip, _sock_port} = local} = :inet.sockname(listen_socket)

        # Always claim the port, but don't accept incoming connections in :active mode
        if tcp_type in [:passive, :so] do
          pid = self()
          spawn_link(fn -> acceptor_loop(listen_socket, pid) end)
        end

        state =
          %{
            state
            | listen_socket: listen_socket,
              socket_opts: socket_opts,
              tcp_type: tcp_type,
              connections: %{}
          }

        {:ok, _} = Registry.register(ExICE.Priv.Registry, local, self())

        {:reply, {:ok, listen_socket}, state}

      {:error, _reason} = err ->
        {:reply, err, state}
    end
  end

  @impl true
  def handle_call({:send, listen_socket, dest, packet, tp_opts}, _from, state) do
    {:ok, src} = :inet.sockname(listen_socket)

    state =
      if state.connections[dest] == nil and
           Keyword.get(tp_opts, :connect?, state.tcp_type in [:active, :so]) do
        try_connect(state, src, dest, tp_opts)
      else
        state
      end

    case state.connections[dest] do
      %{socket: socket, frame?: frame?} ->
        {:reply, do_send(socket, packet, frame?), state}

      nil ->
        if state.tcp_type == :passive do
          Logger.debug("Not sending data from a passive candidate that isn't connected")
          # We're lying here to make the rest of the logic (kinda) work
          {:reply, :ok, state}
        else
          {:reply, {:error, :enotconn}, state}
        end
    end
  end

  @impl true
  def handle_call({:close, listen_socket}, _from, state) do
    # TODO: revisit the closing logic
    :gen_tcp.close(listen_socket)
    Enum.each(state.connections, fn {_, %{socket: socket}} -> :gen_tcp.close(socket) end)

    {:stop, :normal, :ok, state}
  end

  @impl true
  def handle_info({:connected, socket}, state) do
    {:ok, remote} = :inet.peername(socket)

    conn_state = %{
      socket: socket,
      recv_buffer: <<>>,
      frame?: true
    }

    state = put_in(state, [:connections, remote], conn_state)

    {:noreply, state}
  end

  # TODO: consider receiving TCP data in the ICEAgent process
  @impl true
  def handle_info({:tcp, socket, packet}, state) do
    {:ok, {src_ip, src_port} = remote} = :inet.peername(socket)

    conn_state = state.connections[remote]

    cond do
      is_nil(conn_state) ->
        Logger.warning("Received TCP data on unknown connection, dropping")
        {:noreply, state}

      conn_state.frame? ->
        # Framing according to RFC 4571
        previous =
          case conn_state.recv_buffer do
            nil -> <<>>
            data -> data
          end

        case previous <> packet do
          <<length::unsigned-big-16, data::binary-size(length), rest::binary>> ->
            # HACK: this is dirty and means that, with framing, we're miscalculating
            #       the bytes_sent and bytes_received counters
            send(state.ice_agent, {:udp, state.listen_socket, src_ip, src_port, data})
            state = put_in(state, [:connections, remote, :recv_buffer], <<>>)

            if rest != <<>> do
              handle_info({:tcp, socket, rest}, state)
            else
              {:noreply, state}
            end

          data ->
            state = put_in(state, [:connections, remote, :recv_buffer], data)
            {:noreply, state}
        end

      true ->
        send(state.ice_agent, {:udp, state.listen_socket, src_ip, src_port, packet})
        {:noreply, state}
    end
  end

  @impl true
  def handle_info({:tcp_closed, socket}, state) do
    connections = Map.reject(state.connections, fn {_, %{socket: s}} -> s == socket end)

    {:noreply, %{state | connections: connections}}
  end

  defp try_connect(state, local, remote, tp_opts) do
    {local_ip, local_port} = local
    {remote_ip, remote_port} = remote

    # TODO: determine how big of a timeout we should use here
    case :gen_tcp.connect(
           remote_ip,
           remote_port,
           state.socket_opts ++ [port: local_port],
           @connect_timeout_ms
         ) do
      {:ok, socket} ->
        Logger.debug("""
        Successfully initiated new connection.
        Local: #{inspect(local_ip)}:#{inspect(local_port)}
        Remote: #{inspect(remote_ip)}:#{inspect(remote_port)}
        Socket: #{inspect(socket)}
        """)

        conn_state = %{
          socket: socket,
          recv_buffer: <<>>,
          frame?: Keyword.get(tp_opts, :frame?, true)
        }

        put_in(state, [:connections, remote], conn_state)

      {:error, :eaddrinuse} ->
        # This happens with SO candidates, when the acceptor loop accepted the incoming connection already,
        # but we have yet to process the relevant message
        Logger.debug("Unable to initiate connection, we're already connected")

        receive do
          {:connected, _} = msg ->
            {:noreply, state} = handle_info(msg, state)
            state
        after
          50 -> state
        end

      other ->
        Logger.debug("Unable to initiate connection, reason: #{inspect(other)}")
        state
    end
  end

  defp acceptor_loop(listen_socket, pid) do
    {:ok, {sock_ip, sock_port}} = :inet.sockname(listen_socket)

    case :gen_tcp.accept(listen_socket) do
      {:ok, socket} ->
        :ok = :gen_tcp.controlling_process(socket, pid)
        send(pid, {:connected, socket})

        {:ok, {peer_ip, peer_port}} = :inet.peername(socket)

        Logger.debug("""
        Accepted new incoming connection.
        Local: #{inspect(sock_ip)}:#{inspect(sock_port)}
        Remote: #{inspect(peer_ip)}:#{inspect(peer_port)}
        Listen socket: #{inspect(listen_socket)}
        Socket: #{inspect(socket)}
        """)

        acceptor_loop(listen_socket, pid)

      {:error, :closed} ->
        Logger.debug("""
        TCP listen socket closed.
        Local: #{inspect(sock_ip)}:#{inspect(sock_port)}
        Listen socket: #{inspect(listen_socket)}
        """)

        :ok

      # TODO: should we keep accepting in this case?
      {:error, reason} ->
        Logger.debug("""
        TCP listen socket accept failed with reason: #{inspect(reason)}.
        Local: #{inspect(sock_ip)}:#{inspect(sock_port)}
        Listen socket: #{inspect(listen_socket)}
        """)

        acceptor_loop(listen_socket, pid)
    end
  end

  defp do_send(socket, packet, frame?) do
    data =
      if frame? do
        # RFC 4571
        <<byte_size(packet)::unsigned-big-16, packet::binary>>
      else
        packet
      end

    :gen_tcp.send(socket, data)
  end
end
