defmodule ExICE.Priv.Transport.TCP.Client do
  @moduledoc false
  @behaviour ExICE.Priv.Transport

  use GenServer
  require Logger

  @spec start_link(Keyword.t()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts ++ [ice_agent: self()], name: __MODULE__)
  end

  @impl ExICE.Priv.Transport
  def transport, do: :tcp

  # Obtaining three candidates, as per RFC 6544, sec. 5.1.
  @impl ExICE.Priv.Transport
  def socket_configs,
    do: [
      %{tcp_type: :passive},
      %{tcp_type: :so},
      %{tcp_type: :active}
    ]

  @impl ExICE.Priv.Transport
  def setup_socket(ip, port, socket_opts, tp_config) do
    GenServer.call(__MODULE__, {:setup_socket, ip, port, socket_opts, tp_config})
  end

  @impl ExICE.Priv.Transport
  defdelegate sockname(socket), to: :inet

  # HACK: using listen sockets here is ugly, but was easier to fit into the existing ICE Agent implementation.
  #       This should be changed, especially because we're going to want to close the listen sockets
  #       after the connection is successfully established.
  @impl ExICE.Priv.Transport
  def send(listen_socket, dest, packet, tp_opts \\ []) do
    GenServer.call(__MODULE__, {:send, listen_socket, dest, packet, tp_opts})
  end

  @impl ExICE.Priv.Transport
  def close(listen_socket) do
    GenServer.call(__MODULE__, {:close, listen_socket})
  end

  @impl GenServer
  def init(opts) do
    {:ok, %{ref: make_ref(), ice_agent: Keyword.fetch!(opts, :ice_agent), sockets: %{}}}
  end

  # This protects us from reusing ports ONLY within the same TCP client
  # See below for more details
  @impl GenServer
  def handle_call({:setup_socket, ip, port, _, _}, _from, %{sockets: sockets} = state)
      when is_map_key(sockets, {ip, port}) do
    # TODO: Consider using another (custom) reason to distinguish from POSIX EADDRINUSE
    {:reply, {:error, :eaddrinuse}, state}
  end

  @impl GenServer
  def handle_call({:setup_socket, ip, port, socket_opts, %{tcp_type: tcp_type}}, _from, state) do
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
    #   those created in the past by this GenServer.
    # * This, however, does not protect us from binding to sockets opened with SO_REUSEPORT,
    #   that are in use by another OS process with the same effective UID as this one,
    #   which can happen i.e. when we run ICE Agents in two separate VM instances.
    #
    # TODO: warn about this in the documentation of ICE Agent's `:ports` option
    socket_opts = socket_opts ++ [ip: ip, reuseport: true]

    case :gen_tcp.listen(port, socket_opts) do
      {:ok, listen_socket} ->
        {:ok, {^ip, _sock_port} = local} = :inet.sockname(listen_socket)

        # Always claim the port, but don't accept incoming connections in :active mode
        if tcp_type in [:passive, :so] do
          pid = self()
          spawn_link(fn -> acceptor_loop(listen_socket, pid) end)
        end

        state =
          put_in(state, [:sockets, local], %{
            listen_socket: listen_socket,
            socket_opts: socket_opts,
            tcp_type: tcp_type,
            connections: %{}
          })

        {:reply, {:ok, listen_socket}, state}

      {:error, _reason} = err ->
        {:reply, err, state}
    end
  end

  @impl GenServer
  def handle_call({:send, listen_socket, dest, packet, tp_opts}, _from, state) do
    {:ok, src} = :inet.sockname(listen_socket)
    sock_state = state.sockets[src]

    state =
      if sock_state.connections[dest] == nil and
           Keyword.get(tp_opts, :connect?, sock_state.tcp_type in [:active, :so]) do
        try_connect(state, src, dest, tp_opts)
      else
        state
      end

    case state.sockets[src][:connections][dest] do
      %{socket: socket, frame?: frame?} ->
        {:reply, do_send(socket, packet, frame?), state}

      nil ->
        if sock_state.tcp_type == :passive do
          Logger.debug("Not sending data from a passive candidate that isn't connected")
          # We're lying here to make the rest of the logic (kinda) work
          {:reply, :ok, state}
        else
          {:reply, {:error, :enotconn}, state}
        end
    end
  end

  @impl GenServer
  def handle_call({:close, listen_socket}, _from, state) do
    {:ok, local} = :inet.sockname(listen_socket)

    {sock_state, state} = pop_in(state, [:sockets, local])

    case sock_state do
      nil ->
        Logger.debug("Socket already closed")

      %{listen_socket: listen_socket, connections: conn_states} ->
        # TODO: revisit the closing logic
        :gen_tcp.close(listen_socket)
        Enum.each(conn_states, fn {_, %{socket: socket}} -> :gen_tcp.close(socket) end)
    end

    {:reply, :ok, state}
  end

  @impl GenServer
  def handle_info({:connected, _listen_socket, socket}, state) do
    {:ok, local} = :inet.sockname(socket)
    {:ok, remote} = :inet.peername(socket)

    conn_state = %{
      socket: socket,
      recv_buffer: <<>>,
      frame?: true
    }

    # TODO: we should probably ensure `local` is key in `state.sockets`
    state = put_in(state, [:sockets, local, :connections, remote], conn_state)

    {:noreply, state}
  end

  @impl GenServer
  def handle_info({:tcp, socket, packet}, state) do
    {:ok, local} = :inet.sockname(socket)
    {:ok, {src_ip, src_port} = remote} = :inet.peername(socket)

    sock_state = state.sockets[local]
    conn_state = sock_state.connections[remote]

    cond do
      is_nil(conn_state) ->
        # FIXME: this occasionally happens, and it shouldn't
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
            send(state.ice_agent, {:udp, sock_state.listen_socket, src_ip, src_port, data})
            state = put_in(state, [:sockets, local, :connections, remote, :recv_buffer], <<>>)

            if rest != <<>> do
              handle_info({:tcp, socket, rest}, state)
            else
              {:noreply, state}
            end

          data ->
            state = put_in(state, [:sockets, local, :connections, remote, :recv_buffer], data)
            {:noreply, state}
        end

      true ->
        send(state.ice_agent, {:udp, sock_state.listen_socket, src_ip, src_port, packet})
        {:noreply, state}
    end
  end

  @impl GenServer
  def handle_info({:tcp_closed, socket}, state) do
    {src, dst} = find_by_socket(socket, state)

    {_, state} = pop_in(state, [:sockets, src, :connections, dst])

    {:noreply, state}
  end

  defp find_by_socket(socket, state) do
    for {src, sock_state} <- state.sockets,
        {dst, %{socket: connected_socket}} <- sock_state.connections do
      {src, dst, connected_socket}
    end
    |> Enum.find_value(fn
      {src, dst, ^socket} -> {src, dst}
      _other -> nil
    end)
  end

  defp try_connect(state, local, remote, tp_opts) do
    %{socket_opts: socket_opts, listen_socket: listen_socket} = state.sockets[local]

    {local_ip, local_port} = local
    {remote_ip, remote_port} = remote

    # TODO: determine how big of a timeout we should use here
    case :gen_tcp.connect(remote_ip, remote_port, socket_opts ++ [port: local_port], 500) do
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

        put_in(state, [:sockets, local, :connections, remote], conn_state)

      {:error, :eaddrinuse} ->
        # This happens with SO candidates, when the acceptor loop accepted the incoming connection already,
        # but we have yet to process the relevant message
        Logger.debug("Unable to initiate connection, we're already connected")

        receive do
          {:connected, ^listen_socket, _} = msg ->
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
        send(pid, {:connected, listen_socket, socket})

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
